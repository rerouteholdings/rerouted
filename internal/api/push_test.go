package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store"
)

// fakeAPNs stands in for Apple's push service: HTTP/2 over TLS, answering each device
// token with the status in `status` (200 by default), and recording what it got.
type fakeAPNs struct {
	t   *testing.T
	ts  *httptest.Server
	got chan apnsRequest

	mu     sync.Mutex
	status map[string]int
}

type apnsRequest struct {
	token  string
	proto  int
	header http.Header
	body   []byte
}

func newFakeAPNs(t *testing.T) *fakeAPNs {
	f := &fakeAPNs{t: t, got: make(chan apnsRequest, 100), status: map[string]int{}}
	f.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tok := strings.TrimPrefix(r.URL.Path, "/3/device/")
		f.got <- apnsRequest{tok, r.ProtoMajor, r.Header.Clone(), b}
		f.mu.Lock()
		st := f.status[tok]
		f.mu.Unlock()
		switch st {
		case 0, 200:
			w.WriteHeader(200)
		case 410:
			w.WriteHeader(410)
			w.Write([]byte(`{"reason":"Unregistered","timestamp":1800000000000}`))
		default:
			w.WriteHeader(st)
			w.Write([]byte(`{"reason":"InternalServerError"}`))
		}
	}))
	f.ts.EnableHTTP2 = true
	f.ts.StartTLS()
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeAPNs) setStatus(tok string, code int) {
	f.mu.Lock()
	f.status[tok] = code
	f.mu.Unlock()
}

// next waits for the next push, and fails if none comes.
func (f *fakeAPNs) next() apnsRequest {
	f.t.Helper()
	select {
	case r := <-f.got:
		return r
	case <-time.After(5 * time.Second):
		f.t.Fatal("no push notification")
	}
	return apnsRequest{}
}

// none fails if a push comes within a moment.
func (f *fakeAPNs) none(why string) {
	f.t.Helper()
	select {
	case r := <-f.got:
		f.t.Fatalf("%s: a push went to %s", why, r.token)
	case <-time.After(300 * time.Millisecond):
	}
}

// pushServer is a test server with push notifications on, sending to a fake APNs.
func pushServer(t *testing.T) (*httptest.Server, *Server, store.Store, *fakeAPNs, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := serverkey.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &config.Config{Name: "chat.test", Handles: "chat.test", Registration: "invite", RegistrationCode: testRegCode,
		APNSKeyID: "ABC123DEFG", APNSTeamID: "TEAM123456", APNSTopic: "llc.example.reroute"}
	cfg.SetAPNSKey(pk)
	st := newStore(t)
	srv := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	f := newFakeAPNs(t)
	srv.pushes.c.UseServer(f.ts.URL, f.ts.Client())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv, st, f, pk
}

// pushCall calls /v0/push/apns.
func pushCall(t *testing.T, ts *httptest.Server, method, token string, body any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, ts.URL+"/v0/push/apns", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func apnsTokens(t *testing.T, st store.Store, id string) []store.APNSToken {
	t.Helper()
	ts, err := st.Push().APNS(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func hexToken(b byte) string { return strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

func TestPushEndpoint(t *testing.T) {
	// Off: 501, like GET turn without a relay.
	off := testServer(t)
	kat := newUser(t, off, "kat")
	if c := pushCall(t, off, "POST", kat.token, map[string]any{"token": hexToken(1), "env": "sandbox"}); c != 501 {
		t.Fatalf("push off: %d, want 501", c)
	}

	ts, _, st, _, _ := pushServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	ravi := newV2User(t, ts, "ravi", "chat.test")
	tok := hexToken(10)
	for _, c := range []struct {
		why   string
		token string
		body  any
		want  int
	}{
		{"no session", "", map[string]any{"token": tok, "env": "sandbox"}, 401},
		{"a bad session", "nope", map[string]any{"token": tok, "env": "sandbox"}, 401},
		{"no token", kat.token, map[string]any{"env": "sandbox"}, 400},
		{"a short token", kat.token, map[string]any{"token": strings.Repeat("a", 31), "env": "sandbox"}, 400},
		{"a long token", kat.token, map[string]any{"token": strings.Repeat("a", 201), "env": "sandbox"}, 400},
		{"not hex", kat.token, map[string]any{"token": strings.Repeat("g", 64), "env": "sandbox"}, 400},
		{"no env", kat.token, map[string]any{"token": tok}, 400},
		{"another env", kat.token, map[string]any{"token": tok, "env": "staging"}, 400},
	} {
		if got := pushCall(t, ts, "POST", c.token, c.body); got != c.want {
			t.Errorf("%s: %d, want %d", c.why, got, c.want)
		}
	}
	req, _ := http.NewRequest("POST", ts.URL+"/v0/push/apns", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+kat.token)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 415 {
		t.Fatalf("text/plain: %v %v", resp, err)
	}

	// Registered for the session's identity and device, uppercase hex stored lowercase.
	if c := pushCall(t, ts, "POST", kat.token, map[string]any{"token": strings.ToUpper(tok), "env": "production"}); c != 204 {
		t.Fatalf("register: %d", c)
	}
	katDev := []byte(kat.dev.Public().(ed25519.PublicKey))
	if ts := apnsTokens(t, st, kat.id); len(ts) != 1 || ts[0].Token != tok || ts[0].Env != "production" || !bytes.Equal(ts[0].Device, katDev) {
		t.Fatalf("kat's tokens: %+v", ts)
	}
	// A device has one token: a new one replaces it.
	tok2 := hexToken(11)
	if c := pushCall(t, ts, "POST", kat.token, map[string]any{"token": tok2, "env": "sandbox"}); c != 204 {
		t.Fatalf("register again: %d", c)
	}
	if ts := apnsTokens(t, st, kat.id); len(ts) != 1 || ts[0].Token != tok2 {
		t.Fatalf("kat's tokens after a new one: %+v", ts)
	}
	// A token registered by another identity moves there.
	if c := pushCall(t, ts, "POST", bob.token, map[string]any{"token": tok2, "env": "sandbox"}); c != 204 {
		t.Fatalf("bob's register: %d", c)
	}
	if len(apnsTokens(t, st, kat.id)) != 0 || len(apnsTokens(t, st, bob.id)) != 1 {
		t.Fatal("the token didn't move to bob")
	}
	// A wire version 2 session works too.
	if c := pushCall(t, ts, "POST", ravi.token, map[string]any{"token": hexToken(12), "env": "sandbox"}); c != 204 {
		t.Fatalf("a version 2 session: %d", c)
	}
	if ts := apnsTokens(t, st, ravi.id); len(ts) != 1 || !bytes.Equal(ts[0].Device, edOf(ravi.dev)) {
		t.Fatalf("ravi's tokens: %+v", ts)
	}
	// Deleting someone else's token does nothing; deleting your own removes it.
	if c := pushCall(t, ts, "DELETE", kat.token, map[string]any{"token": tok2}); c != 204 || len(apnsTokens(t, st, bob.id)) != 1 {
		t.Fatalf("kat deleting bob's token: %d", c)
	}
	if c := pushCall(t, ts, "DELETE", bob.token, map[string]any{"token": tok2}); c != 204 || len(apnsTokens(t, st, bob.id)) != 0 {
		t.Fatalf("bob deleting his token: %d", c)
	}
	if c := pushCall(t, ts, "DELETE", "", map[string]any{"token": tok2}); c != 401 {
		t.Fatalf("deleting without a session: %d", c)
	}
	// Rate-limited per identity.
	got429 := false
	for range 70 {
		if pushCall(t, ts, "POST", kat.token, map[string]any{"token": tok, "env": "sandbox"}) == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("never rate-limited")
	}
}

// verifyProviderToken checks the bearer token APNs got: an ES256 JWT by the test key.
func verifyProviderToken(t *testing.T, h http.Header, pk *ecdsa.PrivateKey) {
	t.Helper()
	tok, ok := strings.CutPrefix(h.Get("authorization"), "bearer ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		t.Fatalf("authorization: %q", h.Get("authorization"))
	}
	var hdr, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(hb, &hdr)
	json.Unmarshal(cb, &claims)
	if hdr["alg"] != "ES256" || hdr["kid"] != "ABC123DEFG" || claims["iss"] != "TEAM123456" {
		t.Fatalf("provider token: %v %v", hdr, claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&pk.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the provider token's signature doesn't verify")
	}
}

// Deliveries worth a notification push one to each of the recipient's devices with a
// token, content-free, over HTTP/2; the sender's own copies, group upkeep, and anything
// for an identity without a token push nothing.
func TestPushSend(t *testing.T) {
	ts, srv, _, f, pk := pushServer(t)
	srv.pushes.window = 0 // coalescing has its own test
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	katTok, bobTok := hexToken(1), hexToken(2)
	if c := pushCall(t, ts, "POST", kat.token, map[string]any{"token": katTok, "env": "sandbox"}); c != 204 {
		t.Fatalf("register: %d", c)
	}

	// A contact request: a notice in Bob's inbox, but Bob has no token yet.
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	if c := call(t, ts, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil); c != 202 {
		t.Fatalf("request: %d", c)
	}
	f.none("a request to an identity with no token")
	if c := pushCall(t, ts, "POST", bob.token, map[string]any{"token": bobTok, "env": "production"}); c != 204 {
		t.Fatalf("bob's register: %d", c)
	}
	if c := call(t, ts, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}

	// Bob adds Kat to a direct chat: his own copy of the commit pushes nothing, and Kat's
	// Welcome pushes her phone.
	group := randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if c := call(t, ts, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "direct", "epoch-key": []byte(ek0Pub)}, nil); c != 204 {
		t.Fatalf("groups/create: %d", c)
	}
	commitData := []byte("mls-commit-add-kat")
	sum := sha256.Sum256(commitData)
	out := map[string]any{
		"id": randBytes(16), "kind": "mls", "to": []string{bob.id}, "group": group, "epoch": 0, "mls": "commit", "data": commitData,
		"commit":   signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "next": []byte(ek1Pub)}, ek0),
		"welcomes": []any{map[string]any{"id": randBytes(16), "to": []string{kat.id}, "data": []byte("mls-welcome")}},
	}
	var res struct {
		Results []sendResult `json:"results"`
	}
	if c := call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &res); c != 200 || res.Results[0].Status != "sent" {
		t.Fatalf("commit: %d %+v", c, res)
	}
	r := f.next()
	if r.token != katTok {
		t.Fatalf("the Welcome pushed %s, want Kat's token", r.token)
	}
	if r.proto != 2 {
		t.Fatalf("HTTP/%d, want HTTP/2", r.proto)
	}
	verifyProviderToken(t, r.header, pk)
	h := r.header
	if h.Get("apns-topic") != "llc.example.reroute" || h.Get("apns-push-type") != "alert" || h.Get("apns-priority") != "10" || h.Get("apns-collapse-id") == "" {
		t.Fatalf("headers: %v", h)
	}
	var exp int64
	json.Unmarshal([]byte(h.Get("apns-expiration")), &exp)
	if d := exp - time.Now().Unix(); d < 23*3600 || d > 25*3600 {
		t.Fatalf("apns-expiration is %d s ahead, want about a day", d)
	}
	var payload struct {
		APS struct {
			Alert struct {
				Title string `json:"title"`
				Body  string `json:"body"`
			} `json:"alert"`
			Sound          string `json:"sound"`
			MutableContent int    `json:"mutable-content"`
			ThreadID       string `json:"thread-id"`
		} `json:"aps"`
	}
	if err := json.Unmarshal(r.body, &payload); err != nil || payload.APS.Alert.Title != "Reroute" || payload.APS.Alert.Body != "New message" ||
		payload.APS.Sound != "default" || payload.APS.MutableContent != 1 || payload.APS.ThreadID != "messages" {
		t.Fatalf("payload %s", r.body)
	}
	if bytes.Contains(r.body, []byte(bob.id)) || bytes.Contains(r.body, []byte("welcome")) {
		t.Fatalf("the payload says something about the delivery: %s", r.body)
	}
	f.none("bob's own commit")

	// An application message from Bob pushes Kat; one from Kat pushes Bob.
	msg := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{bob.id, kat.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("ciphertext")}
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{msg}}, &res)
	if r := f.next(); r.token != katTok {
		t.Fatalf("bob's message pushed %s", r.token)
	}
	f.none("bob's own copy of his message")
	// Typing and receipts are ephemeral: no push.
	msg["id"], msg["ephemeral"] = randBytes(16), true
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{msg}}, &res)
	f.none("an ephemeral delivery")
	// A contact request to Kat pushes her.
	eve := newUser(t, ts, "eve")
	req = signed(t, "contact-request", map[string]any{"from": eve.id, "to": kat.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": kat.invite(false)}, eve.dev)
	if c := call(t, ts, "POST", "contacts/request", eve.token, map[string]any{"request": req}, nil); c != 202 {
		t.Fatalf("eve's request: %d", c)
	}
	if r := f.next(); r.token != katTok {
		t.Fatalf("the request pushed %s", r.token)
	}
	waitStats(t, srv, 3, 0)
}

// At most one push per device per window; a device with a stream open gets none.
func TestPushCoalesceAndStream(t *testing.T) {
	ts, srv, _, f, _ := pushServer(t)
	kat := newUser(t, ts, "kat")
	tok := hexToken(3)
	if c := pushCall(t, ts, "POST", kat.token, map[string]any{"token": tok, "env": "sandbox"}); c != 204 {
		t.Fatalf("register: %d", c)
	}
	srv.pushes.window = 500 * time.Millisecond
	srv.pushNotify(kat.id)
	f.next()
	srv.pushNotify(kat.id)
	srv.pushNotify(kat.id)
	f.none("within the window")
	time.Sleep(300 * time.Millisecond)
	srv.pushNotify(kat.id)
	if r := f.next(); r.token != tok {
		t.Fatal("after the window")
	}

	srv.pushes.window = 0
	c := openStream(t, ts, kat, "")
	srv.pushNotify(kat.id)
	f.none("the device has a stream open")
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for srv.streams.deviceOpen(kat.id, []byte(kat.dev.Public().(ed25519.PublicKey))) {
		if time.Now().After(deadline) {
			t.Fatal("the stream never closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.pushNotify(kat.id)
	f.next()
}

// APNs saying a token is gone (410, or 400 BadDeviceToken) removes it; other failures
// don't.
func TestPushTokenGone(t *testing.T) {
	ts, srv, st, f, _ := pushServer(t)
	srv.pushes.window = 0
	kat := newUser(t, ts, "kat")
	tok := hexToken(4)
	if c := pushCall(t, ts, "POST", kat.token, map[string]any{"token": tok, "env": "sandbox"}); c != 204 {
		t.Fatalf("register: %d", c)
	}
	f.setStatus(tok, 500)
	srv.pushNotify(kat.id)
	f.next()
	time.Sleep(100 * time.Millisecond)
	if len(apnsTokens(t, st, kat.id)) != 1 {
		t.Fatal("a 500 removed the token")
	}
	f.setStatus(tok, 410)
	srv.pushNotify(kat.id)
	f.next()
	deadline := time.Now().Add(5 * time.Second)
	for len(apnsTokens(t, st, kat.id)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the token is still there after 410")
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitStats(t, srv, 0, 2)
}

// A removed device's token goes with it, and so do an identity's tokens when it moves away.
func TestPushTokenDroppedWithDevice(t *testing.T) {
	ts, _, st, _, _ := pushServer(t)
	kat := newUser(t, ts, "kat")
	if c := pushCall(t, ts, "POST", kat.token, map[string]any{"token": hexToken(5), "env": "sandbox"}); c != 204 {
		t.Fatalf("register: %d", c)
	}
	pub2, dev2, _ := ed25519.GenerateKey(rand.Reader)
	seq, prev := head(t, ts, kat.id)
	add := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "add-device", "key": []byte(pub2)}}}, kat.dev)
	if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": add}, nil); c != 200 {
		t.Fatalf("add-device: %d", c)
	}
	sum := sha256.Sum256(add)
	rm := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 2, "prev": sum[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "remove-device", "key": []byte(kat.dev.Public().(ed25519.PublicKey))}}}, dev2)
	if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": rm}, nil); c != 200 {
		t.Fatalf("remove-device: %d", c)
	}
	if ts := apnsTokens(t, st, kat.id); len(ts) != 0 {
		t.Fatalf("the removed device's token is still there: %+v", ts)
	}
}

// waitStats waits for the push counters, which count once APNs has answered.
func waitStats(t *testing.T, srv *Server, sent, failed int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := srv.Stats()
		if s.PushesSent == sent && s.PushesFailed == failed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stats: %+v, want %d sent and %d failed", s, sent, failed)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
