package api

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// newStore opens a throwaway SQLite store, closed when the test ends.
func newStore(t testing.TB) store.Store {
	t.Helper()
	st, err := sqlite.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testServer(t *testing.T) *httptest.Server { return testServerWith(t, newStore(t)) }

func testServerWith(t *testing.T, st store.Store) *httptest.Server {
	return testServerCfg(t, st, func(*config.Config) {})
}

// testServerCfg starts a test server whose config `change` adjusts.
func testServerCfg(t *testing.T, st store.Store, change func(*config.Config)) *httptest.Server {
	t.Helper()
	key, err := serverkey.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Name: "chat.test", Handles: "chat.test", Registration: "invite", RegistrationCode: testRegCode}
	change(cfg)
	ts := httptest.NewServer(New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func decodeErr(t *testing.T, resp *http.Response) wire.Error {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	var e wire.Error
	if err := wire.Unmarshal(b, &e); err != nil {
		t.Fatalf("error body isn't JSON: %v", err)
	}
	return e
}

func TestServerDoc(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/.well-known/tieroute/server")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != wire.MediaType {
		t.Fatalf("status %d, type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	b, _ := io.ReadAll(resp.Body)
	if c, err := wire.Canonical(b); err != nil || string(c) != string(b) {
		t.Fatalf("server doc isn't JCS: %v\n%s", err, b)
	}
	var doc serverDoc
	if err := wire.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	// Both versions' keys: version 1's Ed25519 key, and version 2's composite key, under
	// another key ID (SPEC §5.1).
	if doc.Name != "chat.test" || len(doc.Roles) != 1 || doc.Roles[0] != "home" || len(doc.Keys) != 2 ||
		len(doc.Keys[0].Pub) != 32 || len(doc.Keys[1].Pub) != wire.CompositePublicKeySize || doc.Keys[0].KID == doc.Keys[1].KID {
		t.Fatalf("unexpected doc: name %q, roles %v, %d keys", doc.Name, doc.Roles, len(doc.Keys))
	}
	// Follow your nose (SPEC §8.1): the APIs are wherever the document says, one base for
	// each wire version while users migrate (SPEC §5.1).
	if len(doc.APIs) != 2 || doc.APIs[0].V != 1 ||
		doc.APIs[0].Client != "https://chat.test/.well-known/tieroute/v1/client/" ||
		doc.APIs[0].S2S != "https://chat.test/.well-known/tieroute/v1/s2s/" ||
		doc.APIs[1].V != 2 ||
		doc.APIs[1].Client != "https://chat.test/.well-known/tieroute/v2/client/" ||
		doc.APIs[1].S2S != "https://chat.test/.well-known/tieroute/v2/s2s/" {
		t.Fatalf("apis: %+v", doc.APIs)
	}
	if doc.Registration != "invite" || doc.Invite != "" {
		t.Fatalf("registration %q, invite %q: the code mustn't be published unless asked", doc.Registration, doc.Invite)
	}
}

// Every client endpoint in SPEC Appendix A is routed: none answers 404.
func TestEveryEndpointRouted(t *testing.T) {
	ts := testServer(t)
	for _, e := range clientEndpoints {
		method, path, _ := strings.Cut(e, " ")
		path = strings.NewReplacer("{id}", "tr:aaaaaaaaaaaaaaaaaaaaaaaa", "{handle}", "x.chat.test", "{device}", "AAAA", "{server}", "chat.test", "{name}", "chat.test", "{group}", "AAAA").Replace(path)
		var body io.Reader
		if method == "POST" {
			body = bytes.NewReader([]byte("{}"))
		}
		req, _ := http.NewRequest(method, ts.URL+"/.well-known/tieroute/v1/client/"+path, body)
		req.Header.Set("Content-Type", wire.MediaType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), "no such endpoint") {
			t.Errorf("%s isn't routed", e)
		}
	}
}

func TestWrongContentType(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Post(ts.URL+"/.well-known/tieroute/v1/client/send", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType || decodeErr(t, resp).Code != wire.ErrCodeBadContentType {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUnknownPath(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/.well-known/tieroute/v1/client/nope")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 || decodeErr(t, resp).Code != wire.ErrCodeNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestTLSAsk(t *testing.T) {
	key, _ := serverkey.LoadOrCreate(t.TempDir())
	cfg := &config.Config{Name: "chat.test", Handles: "chat.test", Registration: "invite", RegistrationCode: testRegCode, TLSAskAllow: []string{"reroute.chat.test"}}
	ts := httptest.NewServer(New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), newStore(t)).Handler())
	t.Cleanup(ts.Close)
	newUser(t, ts, "kat")
	// The server, real handles, and listed extra hostnames get certificates; nothing else does.
	for domain, want := range map[string]int{"chat.test": 200, "kat.chat.test": 200, "reroute.chat.test": 200, "random.chat.test": 404} {
		resp, err := http.Get(ts.URL + "/v0/tls-ask?domain=" + domain)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", domain, resp.StatusCode, want)
		}
	}
}

// Browsers may call the client API from any origin (bearer tokens, no cookies), but not S2S.
func TestCORS(t *testing.T) {
	ts := testServer(t)
	for path, want := range map[string]string{
		"/.well-known/tieroute/v1/client/register": "*",
		"/.well-known/tieroute/server":             "*",
		"/.well-known/tieroute/v1/s2s/deliver":     "",
	} {
		req, _ := http.NewRequest(http.MethodOptions, ts.URL+path, nil)
		req.Header.Set("Origin", "https://app.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != want {
			t.Errorf("%s: allow-origin %q, want %q", path, got, want)
		}
		if want != "" && resp.StatusCode != http.StatusNoContent {
			t.Errorf("%s: preflight %d", path, resp.StatusCode)
		}
	}
}
