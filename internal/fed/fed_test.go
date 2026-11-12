package fed

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// spec/vectors/s2s.json: an S2S request signed with a server key named by kid (SPEC §8.3).
func TestVectorS2S(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/s2s.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Key struct {
			Seed string `json:"seed_hex"`
			Pub  string `json:"public_hex"`
		} `json:"server_key"`
		Request struct {
			Signed string `json:"signed"`
		} `json:"request"`
		Receiver string `json:"receiver"`
		Path     string `json:"url_path"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	sig, err := wire.DecodeSigned([]byte(v.Request.Signed))
	if err != nil {
		t.Fatal(err)
	}
	if kid, ok := sig.KeyID(); !ok || kid != "k1" {
		t.Fatalf("kid %q", kid)
	}
	pub, _ := hex.DecodeString(v.Key.Pub)
	if err := sig.Verify("s2s", ed25519.PublicKey(pub)); err != nil {
		t.Fatal(err)
	}
	var req s2sRequest
	if err := sig.OpenClosed(&req); err != nil || req.To != v.Receiver || req.Path != v.Path || len(req.Nonce) != 16 {
		t.Fatalf("body: %+v %v", req, err)
	}
	// Re-signing the same body with the same key reproduces the envelope exactly.
	seed, _ := hex.DecodeString(v.Key.Seed)
	var body map[string]any
	sig.Open(&body)
	again, _ := wire.SignKID("s2s", body, ed25519.NewKeyFromSeed(seed), "k1")
	if enc, _ := again.Encode(); string(enc) != v.Request.Signed {
		t.Fatalf("re-signed:\n %s\n %s", enc, v.Request.Signed)
	}
}

// Handles resolve from the HTTPS document if there is one, and otherwise from the DNS record
// (SPEC §5.3).
func TestResolveHandleEitherRecord(t *testing.T) {
	const kat, ravi = "tr:aaaaaaaaaaaaaaaaaaaaaaaa", "tr:bbbbbbbbbbbbbbbbbbbbbbbb"
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "withdoc.example" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"id":"` + kat + `","home":"a.test"}`))
	}))
	defer doc.Close()
	txt := map[string][]string{
		"_tieroute.withdoc.example":  {"id=" + ravi + " home=b.test"}, // ignored: the document decides
		"_tieroute.dnsonly.example":  {"v=spf1 -all", "id=" + kat + " home=a.test extra=ignored"},
		"_tieroute.conflict.example": {"id=" + kat + " home=a.test", "id=" + ravi + " home=a.test"},
		"_tieroute.nohome.example":   {"id=" + kat},
	}
	f := &Fed{
		HTTP:  doc.Client(),
		Peers: map[string]string{"withdoc.example": doc.URL, "dnsonly.example": doc.URL, "conflict.example": doc.URL, "nohome.example": doc.URL, "nothing.example": doc.URL},
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			if r, ok := txt[name]; ok {
				return r, nil
			}
			return nil, errors.New("no such name")
		},
	}
	ctx := context.Background()
	for _, tc := range []struct {
		handle, id string
	}{
		{"withdoc.example", kat},
		{"dnsonly.example", kat},
		{"conflict.example", ""},
		{"nohome.example", ""},
		{"nothing.example", ""},
	} {
		d, err := f.ResolveHandle(ctx, tc.handle)
		if tc.id == "" {
			if err == nil {
				t.Errorf("%s resolved to %+v, want an error", tc.handle, d)
			}
			continue
		}
		if err != nil || d.ID != tc.id {
			t.Errorf("%s: %+v, %v; want %s", tc.handle, d, err, tc.id)
		}
	}
}

// SPEC §8.4: a peer's clock is read from its Date header, against the middle of the round
// trip, and only differences over a minute are reported.
func TestNoteDate(t *testing.T) {
	var got []int64
	f := &Fed{OnClock: func(peer string, off int64, refused bool) {
		if peer != "b.test" || refused {
			t.Fatalf("hook: %s %v", peer, refused)
		}
		got = append(got, off)
	}}
	sent := time.Now()
	back := sent.Add(2 * time.Second)
	mid := sent.Add(time.Second)
	f.noteDate("b.test", mid.Add(3*time.Minute).UTC().Format(http.TimeFormat), sent, back)
	f.noteDate("b.test", mid.Add(-90*time.Second).UTC().Format(http.TimeFormat), sent, back)
	f.noteDate("b.test", mid.Add(30*time.Second).UTC().Format(http.TimeFormat), sent, back)
	f.noteDate("b.test", "not a date", sent, back)
	if len(got) != 2 || got[0] < 179 || got[0] > 181 || got[1] > -89 || got[1] < -91 {
		t.Fatalf("offsets heard: %v", got)
	}
}

// SPEC §8.3: a request is checked against the sender's key, inside its validity window
// (nbf, exp), and its signature before its nonce; the nonce is recorded only once the
// signature checks out. So a forged or expired-key request can't use up a real
// request's nonce, and only a genuine one counts as seen.
func TestVerifyChecksKeyAndSignatureBeforeNonce(t *testing.T) {
	livePub, live, _ := ed25519.GenerateKey(nil)
	oldPub, old, _ := ed25519.GenerateKey(nil)
	_, forger, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := wire.Marshal(map[string]any{
			"name": "a.test",
			"keys": []any{
				map[string]any{"kid": "live", "pub": wire.Bytes(livePub), "nbf": now - 3600, "exp": now + 3600},
				map[string]any{"kid": "old", "pub": wire.Bytes(oldPub), "nbf": now - 7200, "exp": now - 3600},
				map[string]any{"kid": "later", "pub": wire.Bytes(oldPub), "nbf": now + 3600, "exp": now + 7200},
			},
		})
		w.Write(b)
	}))
	defer doc.Close()
	f := New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
	f.HTTP = doc.Client()
	nonce := make([]byte, 16)
	nonce[0] = 7
	request := func(priv ed25519.PrivateKey, kid string) []byte {
		sig, err := wire.SignKID("s2s", s2sRequest{From: "a.test", To: "b.test", Path: "ping", TS: now, Nonce: nonce, Body: wire.Raw(`{}`)}, priv, kid)
		if err != nil {
			t.Fatal(err)
		}
		enc, _ := sig.Encode()
		return enc
	}
	ctx := context.Background()
	if _, _, err := f.Verify(ctx, request(forger, "live"), "ping"); err == nil {
		t.Fatal("a forged signature verified")
	}
	if _, _, err := f.Verify(ctx, request(old, "old"), "ping"); err == nil {
		t.Fatal("a key past its exp verified")
	}
	if _, _, err := f.Verify(ctx, request(old, "later"), "ping"); err == nil {
		t.Fatal("a key before its nbf verified")
	}
	if from, _, err := f.Verify(ctx, request(live, "live"), "ping"); err != nil || from != "a.test" {
		t.Fatalf("the genuine request, same nonce, after the refused ones: %q %v", from, err)
	}
	if _, _, err := f.Verify(ctx, request(live, "live"), "ping"); err == nil {
		t.Fatal("a replayed nonce verified")
	}
}

// A replayed request is refused even after a restart, which empties memory: nonces are
// kept in storage (SPEC §8.3). And when the sender's server document can't be fetched,
// the request is unavailable, not refused, so a real sender retries.
func TestReplayRefusedAcrossRestart(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	doc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := wire.Marshal(map[string]any{"name": "a.test", "keys": []any{
			map[string]any{"kid": "k", "pub": wire.Bytes(pub), "nbf": now - 3600, "exp": now + 3600},
		}})
		w.Write(b)
	}))
	defer doc.Close()
	st, err := sqlite.OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	start := func() *Fed {
		f := New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
		f.HTTP = doc.Client()
		f.UseNonce = st.Sessions().UseNonce
		return f
	}
	sig, err := wire.SignKID("s2s", s2sRequest{From: "a.test", To: "b.test", Path: "ping", TS: now, Nonce: make([]byte, 16), Body: wire.Raw(`{}`)}, priv, "k")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := sig.Encode()
	ctx := context.Background()
	if _, _, err := start().Verify(ctx, req, "ping"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := start().Verify(ctx, req, "ping"); err == nil {
		t.Fatal("a request replayed after a restart verified")
	}

	doc.Close() // the sender's server document can't be fetched now
	f := New("b.test", serverkey.Key{}, map[string]string{"a.test": doc.URL})
	sig, _ = wire.SignKID("s2s", s2sRequest{From: "a.test", To: "b.test", Path: "ping", TS: now, Nonce: []byte("another nonce 16"), Body: wire.Raw(`{}`)}, priv, "k")
	req, _ = sig.Encode()
	if _, _, err := f.Verify(ctx, req, "ping"); !errors.As(err, new(*UnavailableError)) {
		t.Fatalf("with the sender's document unreachable: %v, want unavailable", err)
	}
}
