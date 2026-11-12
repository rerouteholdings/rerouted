package api

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// sendLink stores a delivery in u's own inbox: a link bundle, the simplest kind to send.
func (u *testUser) sendLink(data string) {
	u.t.Helper()
	out := map[string]any{"id": randBytes(16), "kind": "link", "to": []string{u.id}, "data": []byte(data)}
	var res struct {
		Results []sendResult `json:"results"`
	}
	if c := call(u.t, u.ts, "POST", "send", u.token, map[string]any{"deliveries": []any{out}}, &res); c != 200 || res.Results[0].Status != "sent" {
		u.t.Fatalf("send: %d %+v", c, res)
	}
}

func firehoseServer(t *testing.T) *httptest.Server {
	return testServerCfg(t, newStore(t), func(c *config.Config) { c.PublicFirehose = true })
}

type sseEvent struct {
	event, data string
}

// readEvents parses SSE events from a response body until it's closed.
func readEvents(resp *http.Response) <-chan sseEvent {
	ch := make(chan sseEvent, 100)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.event != "" || ev.data != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.event = line[len("event: "):]
			case strings.HasPrefix(line, "data: "):
				ev.data = line[len("data: "):]
			}
		}
	}()
	return ch
}

func openFirehose(t *testing.T, ts *httptest.Server) (*http.Response, <-chan sseEvent) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", ts.URL+"/v0/dev/firehose", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 {
		t.Fatalf("firehose: %d", resp.StatusCode)
	}
	return resp, readEvents(resp)
}

func nextEvent(t *testing.T, ch <-chan sseEvent) sseEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("firehose closed")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no firehose event")
	}
	return sseEvent{}
}

func TestFirehoseOffByDefault(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/v0/dev/firehose")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("firehose when off: %d, want 404", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Code != wire.ErrCodeNotFound || e.Msg != "no such endpoint" {
		t.Fatalf("firehose when off isn't the unknown-path answer: %+v", e)
	}
}

func TestFirehoseEvents(t *testing.T) {
	ts := firehoseServer(t)
	kat := newUser(t, ts, "kat")
	kat.sendLink("before") // stored before anyone listens: replayed

	resp, events := openFirehose(t, ts)
	for k, want := range map[string]string{"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"} {
		if got := resp.Header.Get(k); got != want {
			t.Fatalf("%s: %q, want %q", k, got, want)
		}
	}
	check := func(ev sseEvent, n int, data string) {
		t.Helper()
		if ev.event != "delivery" {
			t.Fatalf("event: %q", ev.event)
		}
		if !strings.HasPrefix(ev.data, `{"n":`) {
			t.Fatalf("data doesn't start with n: %s", ev.data)
		}
		var got struct {
			N        int      `json:"n"`
			TS       string   `json:"ts"`
			For      string   `json:"for"`
			From     string   `json:"from"`
			Delivery wire.Raw `json:"delivery"`
		}
		if err := json.Unmarshal([]byte(ev.data), &got); err != nil {
			t.Fatalf("data: %v: %s", err, ev.data)
		}
		ts, err := time.Parse(time.RFC3339, got.TS)
		if got.N != n || err != nil || !strings.HasSuffix(got.TS, "Z") || time.Since(ts) > time.Minute {
			t.Fatalf("n %d ts %q, want n %d", got.N, got.TS, n)
		}
		if got.For != "kat.chat.test" || got.From != "kat.chat.test" { // a local sender is named by handle too
			t.Fatalf("for %q from %q", got.For, got.From)
		}
		// Censored: the sender, kind, and size stay; the data doesn't (censorDelivery).
		var d struct {
			ID        string          `json:"id"`
			Kind      string          `json:"kind"`
			From      string          `json:"from"`
			DataBytes int             `json:"data_bytes"`
			Data      json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(got.Delivery, &d); err != nil || d.Data != nil || d.DataBytes != len(data) || d.From != kat.id || d.Kind != "link" || len(d.ID) != 16 {
			t.Fatalf("delivery: %v %s", err, got.Delivery)
		}
		if strings.Contains(ev.data, base64.RawURLEncoding.EncodeToString([]byte(data))) {
			t.Fatalf("the data is in the event: %s", ev.data)
		}
	}
	check(nextEvent(t, events), 1, "before")
	kat.sendLink("after")
	check(nextEvent(t, events), 2, "after")
}

// The feed never shows ciphertext, group IDs, or commit receipts, and shows delivery IDs only
// as hashes that are the same for one delivery's copies and different for different ones.
func TestFirehoseCensorsDeliveries(t *testing.T) {
	salt := []byte("a test salt, 32 bytes long......")
	raw := []byte(`{"id":"QUJDREVGR0hJSktMTU5PUA","kind":"mls","mls":"commit","from":"tr:kat","to":["tr:ravi","tr:lee"],"group":"R1JPVVA","epoch":7,"receipt":{"b":"x","s":"y"},"data":"c2VjcmV0IGNpcGhlcnRleHQ"}`)
	out, err := censorDelivery(raw, salt)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"data", "group", "receipt"} {
		if _, ok := d[gone]; ok {
			t.Fatalf("%s is still there: %s", gone, out)
		}
	}
	for _, secret := range []string{"c2VjcmV0", "R1JPVVA", "QUJDREVG"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("%s leaked: %s", secret, out)
		}
	}
	if d["data_bytes"] != float64(len("secret ciphertext")) || d["kind"] != "mls" || d["mls"] != "commit" || d["from"] != "tr:kat" || d["epoch"] != float64(7) || len(d["to"].([]any)) != 2 {
		t.Fatalf("lost what it should keep: %s", out)
	}
	again, _ := censorDelivery(raw, salt)
	other, _ := censorDelivery([]byte(`{"id":"WllaWVpZWlpaWlpaWlpaWg","kind":"link","from":"tr:kat","to":["tr:kat"],"data":""}`), salt)
	newSalt, _ := censorDelivery(raw, []byte("another salt, also 32 bytes long"))
	id := func(b []byte) string { var m map[string]any; json.Unmarshal(b, &m); return m["id"].(string) }
	if id(again) != id(out) || id(other) == id(out) || id(newSalt) == id(out) || len(id(out)) != 16 {
		t.Fatalf("ids: %s %s %s %s", id(out), id(again), id(other), id(newSalt))
	}
}

func TestFirehoseReplaysLast50(t *testing.T) {
	ts := firehoseServer(t)
	kat := newUser(t, ts, "kat")
	for range 55 {
		kat.sendLink("x")
	}
	time.Sleep(100 * time.Millisecond) // let the firehose format them
	_, events := openFirehose(t, ts)
	var first struct {
		N int `json:"n"`
	}
	json.Unmarshal([]byte(nextEvent(t, events).data), &first)
	if first.N != 6 {
		t.Fatalf("first replayed event: n %d, want 6", first.N)
	}
	for range 49 {
		nextEvent(t, events)
	}
	kat.sendLink("live")
	var live struct {
		N int `json:"n"`
	}
	json.Unmarshal([]byte(nextEvent(t, events).data), &live)
	if live.N != 56 {
		t.Fatalf("live event: n %d, want 56", live.N)
	}
}

// A client that never reads is dropped, and publishing never waits for it.
func TestFirehoseStuckClient(t *testing.T) {
	s := &Server{}
	f := &firehose{s: s, in: make(chan firehoseItem, 1), ping: time.Hour, conns: map[*firehoseClient]bool{}}
	stuck := &firehoseClient{ch: make(chan []byte, firehoseClientBuf)}
	f.conns[stuck] = true
	it := store.Item{TS: time.Now().Unix(), Delivery: []byte(`{"kind":"link"}`)}
	done := make(chan struct{})
	go func() {
		for range firehoseClientBuf + 10 {
			f.emit("kat.chat.test", "", it)
		}
		// publish never blocks, even with the queue full and nobody running it.
		for range 10 {
			f.publish("tr:x", it)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publishing blocked on a stuck client")
	}
	if f.conns[stuck] {
		t.Fatal("the stuck client wasn't dropped")
	}
	n := 0
	for range stuck.ch {
		n++
	}
	if n != firehoseClientBuf {
		t.Fatalf("the stuck client got %d events, want its buffer, %d", n, firehoseClientBuf)
	}
}

// Over the network: a connection that stops reading doesn't hold up deliveries.
func TestFirehoseStuckConnectionDoesntBlockSends(t *testing.T) {
	ts := firehoseServer(t)
	kat := newUser(t, ts, "kat")
	resp, err := http.Get(ts.URL + "/v0/dev/firehose") // never read
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	done := make(chan struct{})
	go func() {
		for range 200 {
			kat.sendLink(strings.Repeat("x", 4000))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("sends blocked behind a stuck firehose connection")
	}
}

func TestFirehosePings(t *testing.T) {
	key, err := serverkey.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Name: "chat.test", Registration: "closed", PublicFirehose: true}
	s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), newStore(t))
	s.fire.ping = 50 * time.Millisecond
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/v0/dev/firehose")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != ": ping\n" {
		t.Fatalf("first line: %q %v", line, err)
	}
}

func TestFirehoseConnectionLimit(t *testing.T) {
	ts := firehoseServer(t)
	for range firehoseMaxClients {
		openFirehose(t, ts)
	}
	resp, err := http.Get(ts.URL + "/v0/dev/firehose")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("over the limit: %d, want 503", resp.StatusCode)
	}
	if e := decodeErr(t, resp); e.Code != wire.ErrCodeUnavailable {
		t.Fatalf("error: %+v", e)
	}
}

// A handle on another domain (a user's own) is shown once its handle document points back at
// the identity, checked by the server since browsers can't always read it; one that names
// someone else stays an identifier (SPEC §5.3).
func TestFirehoseNamesOwnDomainHandles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		points func(kat string) string
		want   func(kat string) string
	}{
		{"points back", func(kat string) string { return kat }, func(string) string { return "kat.example" }},
		{"names someone else", func(string) string { return "tr:aaaaaaaaaaaaaaaaaaaaaaaa" }, func(kat string) string { return kat }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var katID string
			doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/tieroute/handle" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream") // a plain static file, no CORS
				json.NewEncoder(w).Encode(map[string]string{"id": tc.points(katID), "home": "chat.test"})
			}))
			t.Cleanup(doc.Close)
			ts := testServerCfg(t, newStore(t), func(c *config.Config) {
				c.PublicFirehose = true
				c.Dev = true
				c.Peers = map[string]string{"kat.example": doc.URL}
			})
			kat := newUser(t, ts, "kat")
			katID = kat.id
			seq, prev := head(t, ts, kat.id)
			entry := signed(t, "chain-entry", map[string]any{
				"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
				"ops": []any{map[string]any{"op": "set-handle", "handle": "kat.example"}},
			}, kat.dev)
			if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, nil); c != 200 {
				t.Fatalf("set-handle: %d", c)
			}
			_, events := openFirehose(t, ts)
			kat.sendLink("hello")
			var got struct {
				For  string `json:"for"`
				From string `json:"from"`
			}
			if err := json.Unmarshal([]byte(nextEvent(t, events).data), &got); err != nil {
				t.Fatal(err)
			}
			if want := tc.want(kat.id); got.For != want || got.From != want {
				t.Fatalf("for %q from %q, want %q", got.For, got.From, want)
			}
		})
	}
}
