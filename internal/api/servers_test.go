package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

// GET servers/{name} returns another server's document as it was served, members
// rerouted doesn't read included: a community server's roles and community base.
func TestServerDocRelayedAsServed(t *testing.T) {
	doc := `{"apis":[{"client":"https://c.test/tieroute/v2/client","community":"https://c.test/tieroute/v2/community","s2s":"https://c.test/tieroute/v2/s2s","v":2}],"keys":[],"name":"c.test","roles":["community"]}`
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/tieroute/server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, doc)
	}))
	t.Cleanup(remote.Close)

	ts := httptest.NewUnstartedServer(nil)
	key, err := serverkey.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[string]string{"a.test": "http://" + ts.Listener.Addr().String(), "c.test": remote.URL}
	cfg := &config.Config{Name: "a.test", PublicURL: peers["a.test"], Handles: "a.test", Registration: "invite", RegistrationCode: testRegCode, Dev: true, Peers: peers}
	st := newStore(t)
	t.Cleanup(func() { st.Close() })
	s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	ts.Config.Handler = s.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.RunOutbox(ctx)

	kat := newUserOn(t, ts, "kat", "a.test")
	for range 2 { // fetched, then from the cache
		req, _ := http.NewRequest("GET", ts.URL+"/.well-known/tieroute/v1/client/servers/c.test", nil)
		req.Header.Set("Authorization", "Bearer "+kat.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != doc {
			t.Fatalf("servers/c.test: %d %s", resp.StatusCode, b)
		}
	}
}
