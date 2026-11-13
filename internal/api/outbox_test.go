package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// A rate-limited peer must not lose messages: 429 is retried after its "retry",
// while other 4xx responses are dropped (spec/api/s2s-stage2.md).
func TestOutboxRetriesRateLimits(t *testing.T) {
	for _, c := range []struct {
		status    int
		wantQueue bool
	}{{429, true}, {408, true}, {403, false}, {503, true}} {
		var hits atomic.Int32
		var peer *httptest.Server
		peer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/tieroute/server" { // follow your nose (SPEC §8.1)
				writeBody(w, 200, map[string]any{"name": "b.test", "roles": []string{"home"}, "keys": []any{},
					"apis": []any{map[string]any{"v": 1, "s2s": peer.URL + "/s2s/"}}})
				return
			}
			hits.Add(1)
			writeBody(w, c.status, wire.Error{Code: "rate-limited", Retry: 120})
		}))
		key, _ := serverkey.LoadOrCreate(t.TempDir())
		st := newStore(t)
		cfg := &config.Config{Name: "a.test", Handles: "a.test", Dev: true, Peers: map[string]string{"b.test": peer.URL}}
		s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
		ctx := context.Background()
		s.enqueue(ctx, "b.test", "deliver", map[string]any{"x": 1})
		s.flushOutbox(ctx)
		peer.Close()

		if hits.Load() != 1 {
			t.Fatalf("%d: peer hit %d times", c.status, hits.Load())
		}
		due, _ := st.Outbox().Due(ctx, now()+10_000, 10)
		if queued := len(due) == 1; queued != c.wantQueue {
			t.Fatalf("%d: still queued = %v, want %v", c.status, queued, c.wantQueue)
		}
		if c.status == 429 {
			if soon, _ := st.Outbox().Due(ctx, now()+100, 10); len(soon) != 0 {
				t.Fatal("429: retried before Retry-After")
			}
		}
	}
}

// One backoff schedule per destination (SPEC §10.5): a failing server gets one try per
// round, not one per queued delivery. A refusal is final and tells the sender.
func TestOutboxBackoffPerDestination(t *testing.T) {
	var hits atomic.Int32
	status := atomic.Int32{}
	status.Store(503)
	var peer *httptest.Server
	peer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/tieroute/server" {
			writeBody(w, 200, map[string]any{"name": "b.test", "roles": []string{"home"}, "keys": []any{},
				"apis": []any{map[string]any{"v": 1, "s2s": peer.URL + "/s2s/"}}})
			return
		}
		hits.Add(1)
		writeBody(w, int(status.Load()), wire.Error{Code: "unavailable"})
	}))
	defer peer.Close()
	key, _ := serverkey.LoadOrCreate(t.TempDir())
	st := newStore(t)
	cfg := &config.Config{Name: "a.test", Handles: "a.test", Dev: true, Peers: map[string]string{"b.test": peer.URL}}
	s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	ctx := context.Background()
	for range 5 {
		s.enqueue(ctx, "b.test", "deliver", map[string]any{"deliveries": []any{}})
	}
	s.flushOutbox(ctx)
	if n := hits.Load(); n != 1 {
		t.Fatalf("5 queued deliveries to a failing server: %d calls, want 1", n)
	}
	if due, _ := st.Outbox().Due(ctx, now()+7, 10); len(due) != 0 {
		t.Fatal("deliveries came due before the first backoff step (10 s × 0.75)")
	}
	if due, _ := st.Outbox().Due(ctx, now()+13, 10); len(due) != 5 {
		t.Fatalf("after the first step: %d due, want all 5", len(due))
	}
}

// fakePeer is a server that answers its server document and hands every S2S call to h.
func fakePeer(t *testing.T, name string, h http.HandlerFunc) *httptest.Server {
	var peer *httptest.Server
	peer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/tieroute/server" {
			writeBody(w, 200, map[string]any{"name": name, "roles": []string{"home"}, "keys": []any{},
				"apis": []any{map[string]any{"v": 1, "s2s": peer.URL + "/s2s/"}}})
			return
		}
		h(w, r)
	}))
	t.Cleanup(peer.Close)
	return peer
}

// Each destination has its own worker: a server that doesn't answer holds up only what's
// queued for it, whether the requests were waiting when the outbox started or were queued
// while it ran. Each destination still gets its requests in the order they were queued.
func TestOutboxDownPeerDoesntDelayOthers(t *testing.T) {
	hang := make(chan struct{})
	down := fakePeer(t, "down.test", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(hang) }) // runs before down.Close, so it can finish
	got := make(chan string, 10)
	up := fakePeer(t, "up.test", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sig, err := wire.DecodeSigned(b)
		var req struct {
			Body struct {
				N int `json:"n"`
			} `json:"body"`
		}
		if err != nil || sig.Open(&req) != nil {
			t.Error("a bad s2s request")
		}
		got <- string(rune('0' + req.Body.N))
		writeBody(w, 202, map[string]any{})
	})
	key, _ := serverkey.LoadOrCreate(t.TempDir())
	st := newStore(t)
	cfg := &config.Config{Name: "a.test", Handles: "a.test", Dev: true, Peers: map[string]string{"down.test": down.URL, "up.test": up.URL}}
	s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Queued before the outbox starts, as after a restart: the unreachable server first.
	s.enqueue(ctx, "down.test", "deliver", map[string]any{"n": 0})
	s.enqueue(ctx, "up.test", "deliver", map[string]any{"n": 1})
	go s.RunOutbox(ctx)
	wait := func(want string) {
		t.Helper()
		select {
		case n := <-got:
			if n != want {
				t.Fatalf("up.test got request %s, want %s", n, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("up.test waited for request %s behind down.test", want)
		}
	}
	wait("1")
	// Queued while it runs: sent at once, in order, though down.test is still hanging.
	for !s.waitingOn("down.test") {
		time.Sleep(10 * time.Millisecond)
	}
	s.enqueue(ctx, "down.test", "deliver", map[string]any{"n": 9})
	for _, n := range []int{2, 3, 4} {
		s.enqueue(ctx, "up.test", "deliver", map[string]any{"n": n})
	}
	wait("2")
	wait("3")
	wait("4")
}

// waitingOn reports whether dest's worker is running.
func (s *Server) waitingOn(dest string) bool {
	s.out.mu.Lock()
	defer s.out.mu.Unlock()
	return s.out.dest[dest] != nil
}
