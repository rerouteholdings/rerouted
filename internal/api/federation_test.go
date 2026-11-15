package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// twoServers starts a.test and b.test, which federate over http on localhost (dev mode).
func twoServers(t *testing.T) (a, b *httptest.Server, sa, sb *Server) {
	return twoServersWithStore(t, func() store.Store { return newStore(t) })
}

func twoServersWithStore(t *testing.T, makeStore func() store.Store) (a, b *httptest.Server, sa, sb *Server) {
	t.Helper()
	a, b = httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)
	peers := map[string]string{"a.test": "http://" + a.Listener.Addr().String(), "b.test": "http://" + b.Listener.Addr().String()}
	mk := func(ts *httptest.Server, name string) *Server {
		cfg := &config.Config{Name: name, PublicURL: peers[name], Handles: name, Registration: "invite", RegistrationCode: testRegCode, Dev: true, Peers: peers}
		key := testKey(t, t.TempDir(), cfg)
		st := makeStore()
		t.Cleanup(func() { st.Close() })
		s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
		ts.Config.Handler = s.Handler()
		ts.Start()
		t.Cleanup(ts.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go s.RunOutbox(ctx)
		return s
	}
	sa, sb = mk(a, "a.test"), mk(b, "b.test")
	return
}

// eventually polls u's inbox until it has n items.
func (u *testUser) eventually(n int) []inboxItem {
	u.t.Helper()
	var got []inboxItem
	for i := 0; i < 100; i++ {
		got = append(got, u.inbox()...)
		if len(got) >= n {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	u.t.Fatalf("%s: wanted %d inbox items, got %d", u.handle, n, len(got))
	return nil
}

// waitFor polls u's inbox until a delivery from `from` carries `data`.
func (u *testUser) waitFor(from, data string) {
	u.t.Helper()
	for i := 0; i < 100; i++ {
		for _, it := range u.inbox() {
			if it.Delivery != nil && it.Delivery.From == from && string(it.Delivery.Data) == data {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	u.t.Fatalf("%s never got %q from %s", u.handle, data, from)
}

func TestFederatedFlow(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")

	// Kat, on a.test, resolves Bob's handle on b.test through her own server.
	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, &res); c != 200 || res.ID != bob.id || res.Home != "b.test" {
		t.Fatalf("resolve: %d %+v", c, res)
	}
	var ch struct {
		Entries []any `json:"entries"`
	}
	if c := call(t, a, "GET", "chain/"+bob.id+"?home=b.test", kat.token, nil, &ch); c != 200 || len(ch.Entries) != 1 {
		t.Fatalf("remote chain: %d", c)
	}

	// The contact request crosses servers.
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	if c := call(t, a, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil); c != 202 {
		t.Fatalf("request: %d", c)
	}
	if items := bob.eventually(1); items[0].Notice == nil {
		t.Fatalf("bob didn't get the request: %+v", items)
	}

	// Bob accepts and claims Kat's key package from a.test.
	if c := call(t, b, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}
	var claim struct {
		Packages []struct {
			KP wire.Bytes `json:"kp"`
		} `json:"packages"`
	}
	if c := call(t, b, "POST", "keypackages/claim", bob.token, map[string]any{"id": kat.id}, &claim); c != 200 || len(claim.Packages) != 1 || string(claim.Packages[0].KP) != "kp-kat" {
		t.Fatalf("remote claim: %d %+v", c, claim)
	}

	// Bob's server is the hub. The commit is sequenced there; the Welcome crosses to Kat.
	group := randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	call(t, b, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "direct", "epoch-key": []byte(ek0Pub)}, nil)
	data := []byte("mls-commit-add-kat")
	sum := sha256.Sum256(data)
	commitReq := signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "next": []byte(ek1Pub)}, ek0)
	var sent struct {
		Results []sendResult `json:"results"`
	}
	out := map[string]any{
		"id": randBytes(16), "kind": "mls", "to": []string{bob.id}, "group": group, "epoch": 0, "mls": "commit", "data": data, "commit": commitReq,
		"welcomes": []any{map[string]any{"id": randBytes(16), "to": []string{kat.id}, "data": []byte("mls-welcome")}},
	}
	if call(t, b, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &sent); sent.Results[0].Status != "sent" {
		t.Fatalf("commit: %+v", sent.Results[0])
	}
	items := kat.eventually(1)
	if items[0].Delivery == nil || items[0].Delivery.MLS != "welcome" || items[0].Delivery.From != bob.id {
		t.Fatalf("kat's welcome: %+v", items[0])
	}
	call(t, a, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil)

	// Messages both ways, across servers.
	msg := func(from *testUser, ts *httptest.Server, to *testUser, text string) {
		m := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{from.id, to.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte(text)}
		if call(t, ts, "POST", "send", from.token, map[string]any{"deliveries": []any{m}}, &sent); sent.Results[0].Status != "sent" {
			t.Fatalf("send: %+v", sent.Results[0])
		}
	}
	msg(kat, a, bob, "hi bob")
	bob.waitFor(kat.id, "hi bob")
	msg(bob, b, kat, "hi kat")
	kat.waitFor(bob.id, "hi kat")

	// b.test can't deliver a message "from" Kat, who lives on a.test (SPEC §9.2).
	forged, _ := wire.Marshal(map[string]any{"deliveries": []delivery{{ID: randBytes(16), Kind: "mls", From: kat.id, To: []string{kat.id}, Group: group, Epoch: 1, MLS: "app", Data: []byte("forged")}}})
	// It's refused out loud with wrong-home (SPEC §10.2), not silently.
	var es *fed.ErrStatus
	if _, err := sb.fed.Call(context.Background(), "a.test", "deliver", forged); !errors.As(err, &es) || es.Code != wire.ErrCodeWrongHome || len(es.IDs) != 1 {
		t.Fatalf("deliver call: %v, want 409 wrong-home naming the delivery", err)
	}
	time.Sleep(100 * time.Millisecond)
	for _, it := range kat.inbox() {
		if it.Delivery != nil && string(it.Delivery.Data) == "forged" {
			t.Fatal("a.test accepted a delivery forged by b.test")
		}
	}
}

// SPEC §11.6, the `reg` fallback across servers: a registration relayed to the hub with
// "hub" (client `groups/epoch-key`, 204) and one sent straight to it (S2S
// `group/epoch-key`, 200 {}) can both be repeated once they've taken effect, with the same
// answer; one naming another key can't.
func TestRegFallbackRemoteRetry(t *testing.T) {
	a, b, sa, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")
	group := randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	regPub, reg, _ := ed25519.GenerateKey(rand.Reader)
	call(t, b, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "group", "epoch-key": []byte(ek0Pub)}, nil)
	data := randBytes(40)
	sum := sha256.Sum256(data)
	var sent struct {
		Results []sendResult `json:"results"`
	}
	call(t, b, "POST", "send", bob.token, map[string]any{"deliveries": []any{map[string]any{
		"id": randBytes(16), "kind": "mls", "to": []string{bob.id}, "group": group, "epoch": 0, "mls": "commit", "data": data,
		"commit": signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "reg": []byte(regPub)}, ek0)}}}, &sent)
	if sent.Results[0].Status != "sent" {
		t.Fatalf("commit with reg: %+v", sent.Results[0])
	}
	key := signed(t, "epoch-key", map[string]any{"group": group, "epoch": 1, "next": []byte(ek1Pub)}, reg)
	for i := 0; i < 2; i++ {
		if c := call(t, a, "POST", "groups/epoch-key", kat.token, map[string]any{"hub": "b.test", "key": key}, nil); c != 204 {
			t.Fatalf("relayed registration, try %d: %d", i+1, c)
		}
	}
	body, _ := wire.Marshal(map[string]any{"key": key})
	for i := 0; i < 2; i++ {
		if res, err := sa.fed.Call(context.Background(), "b.test", "group/epoch-key", body); err != nil || string(res) != "{}" {
			t.Fatalf("S2S registration, try %d: %s %v", i+1, res, err)
		}
	}
	ek2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := wire.Marshal(map[string]any{"key": signed(t, "epoch-key", map[string]any{"group": group, "epoch": 1, "next": []byte(ek2Pub)}, reg)})
	var es *fed.ErrStatus
	if _, err := sa.fed.Call(context.Background(), "b.test", "group/epoch-key", other); !errors.As(err, &es) || es.Status != 409 || es.Code != wire.ErrCodeStaleEpoch {
		t.Fatalf("S2S registration naming another key: %v", err)
	}
}
