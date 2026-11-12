package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// ---- GET stream: live inbox items, ephemeral deliveries, and presence (spec/api/client-stage1.md) ----

// Close codes (spec/api/conventions.md).
const (
	closeProtocol        = 4400
	closeUnauthenticated = 4401
	closeNotAllowed      = 4403
	closeRateLimited     = 4429
	closeGoingAway       = 1001
)

// streamIdle is how long a stream may stay silent before the server closes it.
const streamIdle = 90 * time.Second

// stream is one device's open WebSocket.
type stream struct {
	id     string
	device []byte
	out    chan []byte // frames to write; a stream that falls this far behind is closed
	conn   *ws.Conn
	done   chan struct{}
	once   sync.Once

	// While stored items are replayed, live items wait here, so none goes out twice or
	// out of order.
	mu        sync.Mutex
	replaying bool
	held      []heldItem
}

type heldItem struct {
	frame  []byte
	cursor int64
}

// offer queues a frame without blocking. cursor is the inbox cursor of a stored item, or
// -1 for anything else. It reports false if the stream is too far behind.
func (st *stream) offer(frame []byte, cursor int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.replaying && cursor >= 0 {
		st.held = append(st.held, heldItem{frame, cursor})
		return true
	}
	select {
	case st.out <- frame:
		return true
	default:
		return false
	}
}

// endReplay sends the items held during the replay that it didn't cover, then goes live.
func (st *stream) endReplay(last int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.replaying = false
	held := st.held
	st.held = nil
	for _, h := range held {
		if h.cursor <= last {
			continue
		}
		select {
		case st.out <- h.frame:
		default:
			return false
		}
	}
	return true
}

func (st *stream) close(code int, reason string) {
	st.once.Do(func() {
		close(st.done)
		st.conn.Close(code, reason)
	})
}

// streams tracks open streams per identity.
type streams struct {
	mu sync.Mutex
	m  map[string]map[*stream]bool
}

func (ss *streams) add(st *stream) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.m[st.id] == nil {
		ss.m[st.id] = map[*stream]bool{}
	}
	ss.m[st.id][st] = true
}

// remove drops st, and reports whether it was the identity's last stream.
func (ss *streams) remove(st *stream) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.m[st.id], st)
	if len(ss.m[st.id]) == 0 {
		delete(ss.m, st.id)
		return true
	}
	return false
}

func (ss *streams) of(id string) []*stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := make([]*stream, 0, len(ss.m[id]))
	for st := range ss.m[id] {
		out = append(out, st)
	}
	return out
}

func (ss *streams) connected(id string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return len(ss.m[id]) > 0
}

// push sends a frame to every open stream of id. cursor is a stored item's cursor, or -1.
func (s *Server) push(id string, frame map[string]any, cursor int64) {
	b, err := wire.Marshal(frame)
	if err != nil {
		return
	}
	for _, st := range s.streams.of(id) {
		if !st.offer(b, cursor) {
			// Too far behind: close it. The client reconnects and replays from its cursor.
			st.close(closeGoingAway, "too slow; reconnect and replay")
		}
	}
}

// pushItem sends a stored inbox item to the owner's streams.
func (s *Server) pushItem(owner string, it store.Item) {
	c, err := strconv.ParseInt(it.Cursor, 10, 64)
	if err != nil {
		c = -1
	}
	s.push(owner, map[string]any{"t": "item", "item": itemJSON(it)}, c)
}

func itemJSON(it store.Item) map[string]any {
	m := map[string]any{"ts": it.TS}
	if it.Cursor != "" {
		m["cursor"] = it.Cursor
	}
	if it.Delivery != nil {
		m["delivery"] = wire.Raw(it.Delivery)
	} else {
		m["notice"] = wire.Raw(it.Notice)
	}
	return m
}

// closeDevice ends a removed device's streams (SPEC §7.6).
func (s *Server) closeDevice(id string, device []byte) {
	for _, st := range s.streams.of(id) {
		if bytes.Equal(st.device, device) {
			st.close(closeNotAllowed, "this device was removed")
		}
	}
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Upgrade(w, r, "tieroute.v1")
	if err != nil {
		return // Upgrade wrote the HTTP error
	}
	ctx := context.WithoutCancel(r.Context())

	// The first frame authenticates (spec/api/conventions.md).
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	op, msg, err := conn.Read()
	var auth struct {
		T     string `json:"t"`
		Token string `json:"token"`
		After string `json:"after,omitempty"`
	}
	if err != nil {
		conn.Close(closeUnauthenticated, "")
		return
	}
	if op != ws.OpText || wire.Unmarshal(msg, &auth) != nil || auth.T != "auth" {
		conn.Close(closeUnauthenticated, "the first frame must be auth")
		return
	}
	sum := sha256.Sum256([]byte(auth.Token))
	id, dev, err := s.st.Sessions().LookupToken(ctx, sum[:], now())
	if err != nil {
		conn.Close(closeUnauthenticated, "")
		return
	}
	st := &stream{id: id, device: dev, out: make(chan []byte, 256), conn: conn, done: make(chan struct{}), replaying: true}

	// Register before replaying, so nothing that arrives meanwhile is missed. Items pushed
	// live during the replay are skipped if the replay already sent them.
	s.streams.add(st)
	s.presenceConnected(ctx, id)
	defer func() {
		st.close(ws.CloseNormal, "")
		if s.streams.remove(st) {
			s.presenceDisconnected(id)
		}
	}()

	go s.streamWriter(st)
	_, _, gap, _ := s.st.Inbox().List(ctx, id, dev, auth.After, 1)
	s.sendFrame(st, map[string]any{"t": "ready", "gap": gap})
	var last int64 = -1
	if c, err := strconv.ParseInt(auth.After, 10, 64); err == nil {
		last = c
	}
	after := auth.After
	for {
		items, next, _, err := s.st.Inbox().List(ctx, id, dev, after, 500)
		if err != nil {
			break
		}
		for _, it := range items {
			s.sendFrame(st, map[string]any{"t": "item", "item": itemJSON(it)})
			if c, err := strconv.ParseInt(it.Cursor, 10, 64); err == nil {
				last = c
			}
			after = it.Cursor
		}
		if next == "" {
			break
		}
	}
	if !st.endReplay(last) {
		st.close(closeGoingAway, "too slow; reconnect and replay")
		return
	}
	s.presenceSnapshot(ctx, st)

	for {
		conn.SetReadDeadline(time.Now().Add(streamIdle))
		op, msg, err := conn.Read()
		if err != nil {
			return
		}
		if op != ws.OpText {
			st.close(closeProtocol, "frames are text")
			return
		}
		var f struct {
			T    string          `json:"t"`
			N    json.RawMessage `json:"n"`
			Upto string          `json:"upto"`
		}
		if wire.Unmarshal(msg, &f) != nil {
			st.close(closeProtocol, "frames are JSON objects")
			return
		}
		switch f.T {
		case "ping":
			s.sendFrame(st, map[string]any{"t": "pong", "n": wire.Raw(f.N)})
		case "pong":
		case "ack":
			s.ack(ctx, id, dev, f.Upto)
		default:
			s.sendFrame(st, map[string]any{"t": "error", "error": wire.ErrCodeUnknownKind, "ref": wire.Raw(msg)})
		}
	}
}

func (s *Server) sendFrame(st *stream, frame map[string]any) {
	b, err := wire.Marshal(frame)
	if err != nil {
		return
	}
	select {
	case st.out <- b:
	case <-st.done:
	}
}

func (s *Server) streamWriter(st *stream) {
	for {
		select {
		case b := <-st.out:
			if err := st.conn.WriteText(b); err != nil {
				st.close(closeGoingAway, "")
				return
			}
		case <-st.done:
			return
		}
	}
}

// ack records a device's position and prunes what every device has acked (SPEC §10.4).
func (s *Server) ack(ctx context.Context, id string, dev []byte, upto string) {
	s.st.Inbox().Ack(ctx, id, dev, upto)
	if st, _, err := s.identity(ctx, id); err == nil {
		var devices [][]byte
		for k := range st.Devices {
			devices = append(devices, unhex(k))
		}
		s.st.Inbox().Prune(ctx, id, devices, now()-inboxRetention)
	}
}

// ---- ephemeral deliveries: only to devices connected now, never stored (SPEC §13.3) ----

// deliverEphemeral passes d to its local recipients' open streams, if their allowlists
// take it, and sends it once to other servers, without the outbox: it's never retried.
func (s *Server) deliverEphemeral(ctx context.Context, d delivery, origin string, local bool) {
	for _, to := range d.To {
		if !s.isLocal(ctx, to) || !s.streams.connected(to) || !s.allowed(ctx, d, to, origin) {
			continue
		}
		b, err := wire.Marshal(d)
		if err != nil {
			continue
		}
		s.push(to, map[string]any{"t": "item", "item": map[string]any{"ts": now(), "delivery": wire.Raw(b)}}, -1)
	}
	if !local || s.fed == nil {
		return
	}
	byHome := map[string][]string{}
	for _, to := range d.To {
		if !s.isLocal(ctx, to) {
			if st, _, err := s.lookup(ctx, to, ""); err == nil {
				byHome[st.Home] = append(byHome[st.Home], to)
			}
		}
	}
	for home, tos := range byHome {
		out := d
		out.To = tos
		body, err := wire.Marshal(map[string]any{"deliveries": []delivery{out}})
		if err != nil {
			continue
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := s.fed.Call(ctx, home, "deliver", body); err != nil && !errors.Is(err, context.Canceled) {
				s.log.Debug("ephemeral delivery dropped", "dest", home, "err", err)
			}
		}()
	}
}
