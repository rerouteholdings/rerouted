package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// An unsigned S2S request dated too far off is refused for clock-skew. What it claims as
// its sender mustn't make the server keep or log more: many such requests, each from a
// different huge name, leave the clock notes and the log bounded.
func TestSkewedS2SFromUnverifiedSenderStaysBounded(t *testing.T) {
	key, err := serverkey.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cfg := &config.Config{Name: "b.example", PublicURL: "https://b.example", Handles: "b.example", Registration: "closed", Peers: map[string]string{}}
	st := newStore(t)
	t.Cleanup(func() { st.Close() })
	s := New(cfg, key, slog.New(slog.NewTextHandler(&logs, nil)), st)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	send := func(from string) {
		b, _ := json.Marshal(map[string]any{"body": map[string]any{}, "from": from, "nonce": "WlpaWlpaWlpaWlpaWlpaWg",
			"path": "identity/fetch", "to": "b.example", "ts": time.Now().Unix() - 3600})
		req, _ := json.Marshal(map[string]any{"b": string(b), "kid": "k1", "s": strings.Repeat("A", 86), "t": "s2s"})
		resp, err := http.Post(ts.URL+"/.well-known/tieroute/v1/s2s/identity/fetch", wire.MediaType, bytes.NewReader(req))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	// Huge names that aren't server names: refused before the clock is looked at.
	for i := 0; i < 50; i++ {
		send(fmt.Sprintf("%d.", i) + strings.Repeat("a", 64<<10))
	}
	s.clock.mu.Lock()
	entries, keyBytes := len(s.clock.last), 0
	for k := range s.clock.last {
		keyBytes += len(k)
	}
	s.clock.mu.Unlock()
	if keyBytes > 4096 {
		t.Errorf("clock notes: %d entries, %d key bytes", entries, keyBytes)
	}
	if logs.Len() > 4096 {
		t.Errorf("log: %d bytes", logs.Len())
	}
	// Many valid names: past maxClockNotes, they share one note and one log line.
	for i := 0; i < 2*maxClockNotes; i++ {
		send(fmt.Sprintf("peer%d.example", i))
	}
	s.clock.mu.Lock()
	entries = len(s.clock.last)
	s.clock.mu.Unlock()
	if entries > maxClockNotes+1 {
		t.Errorf("clock notes: %d entries", entries)
	}
	if lines := strings.Count(logs.String(), "claiming to be from"); lines > maxClockNotes+1 {
		t.Errorf("%d clock lines logged", lines)
	}
}
