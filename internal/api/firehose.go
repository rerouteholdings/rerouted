package api

// The public firehose: a live, unauthenticated Server-Sent Events feed of every delivery
// stored into a local user's inbox. Off by default (REROUTED_PUBLIC_FIREHOSE). It's a
// deployment feature for a public development server, not part of the protocol. Each
// delivery is shown censored (censorDelivery): no ciphertext, no group ID, no commit
// receipt, and the delivery ID only as a hash. Who sent it to whom, its kind, its epoch, and
// its timing are shown to anyone.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

const (
	firehoseReplay     = 50   // events replayed to a new connection
	firehoseMaxClients = 200  // concurrent connections
	firehoseClientBuf  = 64   // events buffered per connection before it's dropped
	firehoseQueue      = 1024 // deliveries waiting to be formatted before new ones are dropped
)

type firehoseItem struct {
	to string
	it store.Item
}

type firehoseClient struct {
	ch chan []byte // formatted events; closed when the client is dropped
}

type firehose struct {
	s     *Server
	in    chan firehoseItem
	ping  time.Duration
	mu    sync.Mutex
	n     uint64
	ring  [][]byte
	conns map[*firehoseClient]bool

	namesMu sync.Mutex
	names   map[string]cachedName // handles checked through their handle documents

	salt []byte // keys the delivery-ID hashes; new on every start, so they can't be matched later
}

func newFirehose(s *Server) *firehose {
	f := &firehose{s: s, in: make(chan firehoseItem, firehoseQueue), ping: 25 * time.Second, conns: map[*firehoseClient]bool{}, names: map[string]cachedName{}, salt: make([]byte, 32)}
	if _, err := rand.Read(f.salt); err != nil {
		panic(err) // crypto/rand doesn't fail on supported systems
	}
	go f.run()
	return f
}

// publish hands a stored inbox item to the firehose without ever waiting: if the
// firehose is behind, the item is skipped. Safe to call on a nil firehose (off).
func (f *firehose) publish(to string, it store.Item) {
	if f == nil || it.Delivery == nil {
		return
	}
	select {
	case f.in <- firehoseItem{to, it}:
	default:
	}
}

// run formats queued items and fans them out, off the inbox write path.
func (f *firehose) run() {
	for fi := range f.in {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		who := f.publicName(ctx, fi.to)
		// The sender gets the same treatment: a local sender is named by handle, the way
		// recipients are. A remote sender stays an ID: this server has no verified handle for them.
		var env struct {
			From string `json:"from"`
		}
		from := ""
		if json.Unmarshal(fi.it.Delivery, &env) == nil && env.From != "" {
			from = f.publicName(ctx, env.From)
		}
		cancel()
		f.emit(who, from, fi.it)
	}
}

func (f *firehose) emit(who, from string, it store.Item) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	ev, err := firehoseEvent(f.n, who, from, it, f.salt)
	if err != nil {
		f.n--
		f.s.log.Error("firehose: encode event", "err", err)
		return
	}
	if len(f.ring) == firehoseReplay {
		copy(f.ring, f.ring[1:])
		f.ring = f.ring[:firehoseReplay-1]
	}
	f.ring = append(f.ring, ev)
	for c := range f.conns {
		select {
		case c.ch <- ev:
		default: // too slow: drop it rather than wait
			f.dropLocked(c)
		}
	}
}

func (f *firehose) dropLocked(c *firehoseClient) {
	if f.conns[c] {
		delete(f.conns, c)
		close(c.ch)
	}
}

// closeAll ends every connection, for server shutdown.
func (f *firehose) closeAll() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for c := range f.conns {
		f.dropLocked(c)
	}
}

// firehoseEvent formats one SSE event, with the delivery censored (censorDelivery). `from`
// names its sender (a handle, if the sender is local), and is left out when it's unknown.
func firehoseEvent(n uint64, who, from string, it store.Item, salt []byte) ([]byte, error) {
	d, err := censorDelivery(it.Delivery, salt)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("event: delivery\ndata: ")
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err = enc.Encode(struct {
		N        uint64          `json:"n"`
		TS       string          `json:"ts"`
		For      string          `json:"for"`
		From     string          `json:"from,omitempty"`
		Delivery json.RawMessage `json:"delivery"`
	}{n, time.Unix(it.TS, 0).UTC().Format(time.RFC3339), who, from, d})
	if err != nil {
		return nil, err
	}
	buf.WriteString("\n") // Encode ended the data line; this blank line ends the event
	return buf.Bytes(), nil
}

// censorDelivery is a stored delivery as the public feed shows it. Gone: `data` (the MLS
// ciphertext, link bundle, or chain entries; only its size is kept, as `data_bytes`),
// `receipt` (the hub's signed commit receipt), and `group` (which would link a group's
// messages together). `id` becomes a short hash under `salt`, enough to tell one delivery's
// copies apart from another's without revealing the ID itself. Everything else stays.
func censorDelivery(raw []byte, salt []byte) (json.RawMessage, error) {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if data, ok := d["data"]; ok {
		var b64 string
		n := 0
		if json.Unmarshal(data, &b64) == nil {
			n = base64.RawURLEncoding.DecodedLen(len(strings.TrimRight(b64, "=")))
		}
		d["data_bytes"], _ = json.Marshal(n)
		delete(d, "data")
	}
	delete(d, "receipt")
	delete(d, "group")
	if id, ok := d["id"]; ok {
		m := hmac.New(sha256.New, salt)
		m.Write(id)
		d["id"], _ = json.Marshal(hex.EncodeToString(m.Sum(nil)[:8]))
	}
	return json.Marshal(d)
}

// publicName is an identity's handle, if it resolves to them both ways (SPEC §5.3), or else
// their ID. A handle registered here is checked against this server's own index. Any other
// handle, such as a user's own domain, is checked by fetching its handle document, as for a
// signed-in user's lookup. Those answers, failures included, are kept for nameTTL so the
// feed doesn't fetch for every delivery.
func (f *firehose) publicName(ctx context.Context, id string) string {
	st, _, err := f.s.identity(ctx, id)
	if err != nil || st.Handle == "" {
		return id
	}
	if owner, err := f.s.st.Chains().ByHandle(ctx, st.Handle); err == nil {
		if owner == id {
			return st.Handle
		}
		return id // registered here to someone else
	}
	if f.s.fed == nil {
		return id
	}
	key := id + " " + st.Handle // a new handle on the chain gets a fresh check
	f.namesMu.Lock()
	n, ok := f.names[key]
	f.namesMu.Unlock()
	if ok && time.Now().Before(n.until) {
		return n.name
	}
	name := id
	if d, err := f.s.fed.ResolveHandle(ctx, st.Handle); err == nil && d.ID == id {
		name = st.Handle
	}
	f.namesMu.Lock()
	if len(f.names) > 10000 {
		f.names = map[string]cachedName{} // bounded: start over rather than grow without limit
	}
	f.names[key] = cachedName{name, time.Now().Add(nameTTL)}
	f.namesMu.Unlock()
	return name
}

// How long a handle checked through its handle document is trusted by the feed.
const nameTTL = 10 * time.Minute

type cachedName struct {
	name  string
	until time.Time
}

// GET /v0/dev/firehose (routed only when the firehose is on).
func (s *Server) firehoseStream(w http.ResponseWriter, r *http.Request) {
	f := s.fire
	c := &firehoseClient{ch: make(chan []byte, firehoseClientBuf)}
	f.mu.Lock()
	if len(f.conns) >= firehoseMaxClients {
		f.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "too many firehose connections")
		return
	}
	replay := append([][]byte(nil), f.ring...)
	f.conns[c] = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.dropLocked(c)
		f.mu.Unlock()
	}()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	send := func(b []byte) bool {
		if _, err := w.Write(b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	for _, ev := range replay {
		if !send(ev) {
			return
		}
	}
	if len(replay) == 0 && rc.Flush() != nil {
		return
	}
	tick := time.NewTicker(f.ping)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-c.ch:
			if !ok || !send(ev) {
				return
			}
		case <-tick.C:
			if !send([]byte(": ping\n\n")) {
				return
			}
		}
	}
}
