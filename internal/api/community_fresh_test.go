package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// A community append checks the signer on a copy of its chain fetched from its home as the
// append arrives, not on the copy cached at sign-in (SPEC §16.2.2). So a device removed a
// moment ago can't append, and its community session ends. A home that can't be reached
// gets 503.
func TestCommunityAppendFetchesChain(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = []config.Community{{Name: "games.test", URL: "https://games.test"}}
	})
	kat := newV2User(t, e.peer("b.test"), "kat", "b.test")
	phone := newComposite(t)
	if c, er := kat.appendSigned(signed2(t, "chain-entry", kat.entry(addDevice(phone, "phone")), kat.dev)); c != 200 {
		t.Fatalf("add-device: %d %+v", c, er)
	}
	e.host = "games.test"
	k := e.signIn(kat)
	m := k.create("games.test", false)
	pk := *kat
	pk.dev = phone
	p := e.signIn(&pk)
	p.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "From the phone"})

	// The laptop removes the phone on b.test. games.test still has the copy from sign-in.
	if c, er := kat.appendSigned(signed2(t, "chain-entry", kat.entry(map[string]any{"op": "remove-device", "key": edOf(phone)}), kat.dev)); c != 200 {
		t.Fatalf("remove-device: %d %+v", c, er)
	}
	if c, code := p.appendOps(m.ch, map[string]any{"op": "set-name", "name": "Stolen"}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a removed device appended: %d %s", c, code)
	}
	if c, _ := e.errOf("GET", "chain", p.tok, nil); c != 401 {
		t.Fatalf("the removed device's session still works: %d", c)
	}
	k.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "Back"})

	// b.test can't be reached: the append waits, rather than trusting the cached copy.
	e.srv.comm.byName["games.test"].srv.fed.HTTP = &http.Client{Transport: unreachable{}}
	if c, code := k.appendOps(m.ch, map[string]any{"op": "set-name", "name": "Offline"}); c != 503 || code != wire.ErrCodeUnavailable {
		t.Fatalf("an append with the home unreachable: %d %s", c, code)
	}
}

// A live session's chain is fetched again after an hour, not a day (SPEC §16.2.2).
func TestCommunityHourlyChainRefresh(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = []config.Community{{Name: "games.test", URL: "https://games.test"}}
	})
	kat := newV2User(t, e.peer("b.test"), "kat", "b.test")
	phone := newComposite(t)
	if c, er := kat.appendSigned(signed2(t, "chain-entry", kat.entry(addDevice(phone, "phone")), kat.dev)); c != 200 {
		t.Fatalf("add-device: %d %+v", c, er)
	}
	e.host = "games.test"
	e.signIn(kat).create("games.test", false)
	pk := *kat
	pk.dev = phone
	p := e.signIn(&pk)
	if c, er := kat.appendSigned(signed2(t, "chain-entry", kat.entry(map[string]any{"op": "remove-device", "key": edOf(phone)}), kat.dev)); c != 200 {
		t.Fatalf("remove-device: %d %+v", c, er)
	}
	c := e.srv.comm.byName["games.test"]
	c.fetched.Store(kat.id, now()-chainRefresh+60)
	c.refreshChains(t.Context())
	if code, _ := e.errOf("GET", "chain", p.tok, nil); code != 200 {
		t.Fatalf("fetched again before the hour was up: %d", code)
	}
	c.fetched.Store(kat.id, now()-chainRefresh-1)
	c.refreshChains(t.Context())
	if code, _ := e.errOf("GET", "chain", p.tok, nil); code != 401 {
		t.Fatalf("the removed device's session outlived the hourly re-fetch: %d", code)
	}
}

// unreachable is a transport for a server that can't reach anyone.
type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unreachable")
}

// peer starts another homeserver, federating with e's server, for identities whose chains
// e's server only has by fetching them.
func (e *cmEnv) peer(name string) *httptest.Server {
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
	return ts
}
