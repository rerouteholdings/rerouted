package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// peerServer is peer, also returning the Server.
func (e *cmEnv) peerServer(name string) (*httptest.Server, *Server) {
	e.t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	peers := e.srv.cfg.Peers
	peers[name] = "http://" + ts.Listener.Addr().String()
	key, err := serverkey.LoadOrCreate(e.t.TempDir())
	if err != nil {
		e.t.Fatal(err)
	}
	cfg := &config.Config{Name: name, PublicURL: peers[name], Handles: name, Registration: "invite", RegistrationCode: testRegCode, Dev: true, Peers: peers}
	s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), newStore(e.t))
	ts.Config.Handler = s.Handler()
	ts.Start()
	e.t.Cleanup(ts.Close)
	return ts, s
}

// getEmoji asks a homeserver for an emoji through its client API.
func getEmoji(t *testing.T, ts *httptest.Server, token, server string, id []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+v2Client+"emoji/"+server+"/"+base64.RawURLEncoding.EncodeToString(id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// A recipient on another homeserver gets a community's emoji through its own homeserver
// (SPEC §12.2): fetched from the community server's public emoji/{id}, cached, and capped.
func TestEmojiThroughHomeserver(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = []config.Community{{Name: "games.test", URL: "https://games.test"}}
	})
	bts, b := e.peerServer("b.test")
	e.host = "games.test"
	kat := e.signIn(newV2User(t, e.ts, "kat", "chat.test"))
	m := kat.create("games.test", false)
	blob := append([]byte("an encrypted emoji"), make([]byte, 16)...)
	id := kat.emojiUp(blob)
	if c, cd := kat.emojiPut(signed2(t, "community-emoji", kat.emojiBody(m, id, blob), kat.dev)); c != 204 {
		t.Fatalf("put: %d %s", c, cd)
	}
	ravi := newV2User(t, bts, "ravi", "b.test")

	if c, _ := getEmoji(t, bts, "", "games.test", id); c != 401 {
		t.Fatalf("without a session: %d", c)
	}
	if c, _ := getEmoji(t, bts, ravi.token, "games.test", []byte("short")); c != 400 {
		t.Fatalf("a bad id: %d", c)
	}
	if c, got := getEmoji(t, bts, ravi.token, "games.test", id); c != 200 || !bytes.Equal(got, blob) {
		t.Fatalf("through b.test: %d", c)
	}
	missing := randB(16)
	if c, _ := getEmoji(t, bts, ravi.token, "games.test", missing); c != 404 {
		t.Fatalf("an unknown emoji: %d", c)
	}
	// The community's own homeserver reads its storage.
	k := newV2User(t, e.ts, "sam", "chat.test")
	if c, got := getEmoji(t, e.ts, k.token, "games.test", id); c != 200 || !bytes.Equal(got, blob) {
		t.Fatalf("on the community's own server: %d", c)
	}

	// games.test can't be reached: what b.test cached still works, and nothing else does.
	b.fed.HTTP = &http.Client{Transport: unreachable{}}
	b.v2.fed.HTTP = &http.Client{Transport: unreachable{}}
	if c, got := getEmoji(t, bts, ravi.token, "games.test", id); c != 200 || !bytes.Equal(got, blob) {
		t.Fatalf("from the cache: %d", c)
	}
	if c, _ := getEmoji(t, bts, ravi.token, "games.test", missing); c != 404 {
		t.Fatalf("a remembered 404: %d", c)
	}
	if c, got := getEmoji(t, bts, ravi.token, "games.test", randB(16)); c != 503 || !bytes.Contains(got, []byte(wire.ErrCodeUnavailable)) {
		t.Fatalf("unreachable and not cached: %d %s", c, got)
	}

	// A community server whose answer is over the cap.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/tieroute/server" {
			writeBody(w, 200, map[string]any{"name": "big.test", "roles": []string{"community"},
				"apis": []any{map[string]any{"v": 2, "s2s": "https://big.test/s2s/", "community": "https://big.test/c/"}}, "keys": []any{}})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(make([]byte, maxEmojiBlob+1))
	}))
	t.Cleanup(big.Close)
	e.srv.cfg.Peers["big.test"] = big.URL
	b.v2.fed.HTTP = http.DefaultClient
	if c, _ := getEmoji(t, bts, ravi.token, "big.test", randB(16)); c != 413 {
		t.Fatalf("over the cap: %d", c)
	}
	// A server that isn't a community server.
	if c, _ := getEmoji(t, bts, ravi.token, "chat.test", randB(16)); c != 404 {
		t.Fatalf("chat.test: %d", c)
	}
}
