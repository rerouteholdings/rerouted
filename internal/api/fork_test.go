package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// remoteChainLen polls b's view of id's chain until it has n entries.
func remoteChainLen(t *testing.T, b *httptest.Server, token, id string, n int) []wire.Raw {
	t.Helper()
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		call(t, b, "GET", "chain/"+id, token, nil, &ch)
		if len(ch.Entries) == n {
			return ch.Entries
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("remote chain has %d entries, want %d", len(ch.Entries), n)
	return nil
}

// The stolen-laptop case (SPEC §6.4.1): the thief's changes reach Bob's server, then
// Kat's recovery fork replaces them there too, even though it's shorter.
func TestRecoveryForkPropagates(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")
	var res struct{ ID, Home string }
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, &res)
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	call(t, a, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil)
	bob.eventually(1)
	call(t, b, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil)
	remoteChainLen(t, b, bob.token, kat.id, 1)

	// The thief, holding Kat's laptop, adds their own device and removes the laptop.
	thiefPub, thief, _ := ed25519.GenerateKey(rand.Reader)
	katPub := []byte(kat.dev.Public().(ed25519.PublicKey))
	appendEntry := func(signer ed25519.PrivateKey, token string, ops ...any) {
		seq, prev := head(t, a, kat.id)
		e := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(), "ops": ops}, signer)
		if c := call(t, a, "POST", "chain/append", token, map[string]any{"entry": e}, nil); c != 200 {
			t.Fatalf("append: %d", c)
		}
	}
	appendEntry(kat.dev, kat.token, map[string]any{"op": "add-device", "key": []byte(thiefPub), "name": "thief"})
	if c := login(t, a, kat.id, "a.test", thief); c != 200 {
		t.Fatalf("thief login: %d", c)
	}
	var sess struct {
		Token string `json:"token"`
	}
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	call(t, a, "POST", "auth/challenge", "", map[string]any{"id": kat.id, "key": []byte(thiefPub)}, &ch)
	call(t, a, "POST", "auth/session", "", map[string]any{"auth": signed(t, "auth", map[string]any{"id": kat.id, "nonce": ch.Nonce, "server": "a.test", "ts": time.Now().Unix()}, thief)}, &sess)
	appendEntry(thief, sess.Token, map[string]any{"op": "remove-device", "key": katPub})
	remoteChainLen(t, b, bob.token, kat.id, 3)

	// Kat recovers with the recovery key, forking from the genesis.
	newPub, newDev, _ := ed25519.GenerateKey(rand.Reader)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	next := sha256.Sum256(nextPub)
	var gen struct {
		Entries []wire.Raw `json:"entries"`
	}
	call(t, a, "GET", "chain/"+kat.id, "", nil, &gen)
	g, _ := wire.DecodeSigned(gen.Entries[0])
	genc, _ := g.Encode()
	gsum := sha256.Sum256(genc)
	fix := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": 1, "prev": gsum[:], "ts": time.Now().Unix(),
		"ops": []any{
			map[string]any{"op": "add-device", "key": []byte(newPub), "name": "recovered"},
			map[string]any{"op": "remove-device", "key": katPub},
			map[string]any{"op": "set-recovery", "next": next[:]},
		},
	}, kat.rec)
	if c := call(t, a, "POST", "recover", "", map[string]any{"entry": fix}, nil); c != 200 {
		t.Fatalf("recovery fork: %d", c)
	}

	// a.test switched branches: the thief is out, the new device is in.
	if c := login(t, a, kat.id, "a.test", thief); c != 403 {
		t.Fatalf("thief login after recovery: %d, want 403", c)
	}
	if c := call(t, a, "GET", "inbox", sess.Token, nil, nil); c != 401 {
		t.Fatalf("thief's session after recovery: %d, want 401", c)
	}
	if c := login(t, a, kat.id, "a.test", newDev); c != 200 {
		t.Fatalf("new device login: %d", c)
	}
	// b.test accepted the shorter recovery branch through identity push.
	got := remoteChainLen(t, b, bob.token, kat.id, 2)
	last, _ := wire.DecodeSigned(got[1])
	if lenc, _ := last.Encode(); string(lenc) != string(fix) {
		t.Fatal("b.test's chain doesn't end with the recovery entry")
	}

	// The thief's branch can't be pushed back: replaying the old fetch doesn't win.
	if c := call(t, a, "POST", "recover", "", map[string]any{"entry": fix}, nil); c != 409 && c != 400 {
		t.Fatalf("replayed recovery: %d", c)
	}
}

func TestLinkProof(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	bob := newUser(t, ts, "bob")
	newPub, newDev, _ := ed25519.GenerateKey(rand.Reader)
	proof := func(code string, k ed25519.PrivateKey) int {
		p := signed(t, "link-proof", map[string]any{"id": kat.id, "code": code, "ts": time.Now().Unix()}, k)
		return call(t, ts, "POST", "link/proof", "", map[string]any{"proof": p}, nil)
	}
	path := "link/proof/" + wire.B64(newPub)
	if c := call(t, ts, "GET", path, kat.token, nil, nil); c != 404 {
		t.Fatalf("before any proof: %d", c)
	}
	if c := proof("ABCD-EFGH", newDev); c != 202 {
		t.Fatalf("post proof: %d", c)
	}
	var res struct {
		Proof wire.Raw `json:"proof"`
	}
	if c := call(t, ts, "GET", path, kat.token, nil, &res); c != 200 || res.Proof == nil {
		t.Fatalf("get proof: %d", c)
	}
	// Only the account's own devices see it.
	if c := call(t, ts, "GET", path, bob.token, nil, nil); c != 404 {
		t.Fatalf("someone else's proof: %d, want 404", c)
	}
	// An existing device can't post one; guesses run out.
	if c := proof("ABCD-EFGH", kat.dev); c != 409 {
		t.Fatalf("proof from a current device: %d, want 409", c)
	}
	for i := 0; i < 4; i++ {
		proof("WRNG-CODE", newDev)
	}
	if c := proof("WRNG-CODE", newDev); c != 429 {
		t.Fatalf("sixth try: %d, want 429", c)
	}
}

// SPEC §7.2: link proofs and parked keys are unauthenticated, so they're limited per
// source address and per identity.
func TestLinkProofLimits(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	bob := newUser(t, ts, "bob")
	post := func(id, addr string, code string) int {
		_, dev, _ := ed25519.GenerateKey(rand.Reader)
		body := map[string]any{"id": id, "ts": time.Now().Unix()}
		if code != "" {
			body["code"] = code
		} else {
			body["hpke"] = randBytes(hpkeKeySize)
		}
		b, _ := wire.Marshal(map[string]any{"proof": signed(t, "link-proof", body, dev)})
		req, _ := http.NewRequest("POST", ts.URL+"/.well-known/tieroute/v1/client/link/proof", bytes.NewReader(b))
		req.Header.Set("Content-Type", wire.MediaType)
		req.Header.Set("X-Forwarded-For", addr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Per source address: parks and code proofs alike, for any identity.
	for i := 0; i < linkProofsPerAddress; i++ {
		if c := post([]string{kat.id, bob.id}[i%2], "192.0.2.1", []string{"", "ABCD-EFGH"}[i%2]); c != 202 {
			t.Fatalf("request %d from one address: %d", i, c)
		}
	}
	if c := post(bob.id, "192.0.2.1", ""); c != 429 {
		t.Fatalf("one too many from one address: %d, want 429", c)
	}
	// Per identity: from a new address each time, with a new device key each time.
	for i := 0; i < linkProofsPerIdentity-linkProofsPerAddress/2; i++ {
		if c := post(kat.id, fmt.Sprintf("198.51.100.%d", i+1), ""); c != 202 {
			t.Fatalf("request %d for one identity: %d", i, c)
		}
	}
	if c := post(kat.id, "203.0.113.1", "ABCD-EFGH"); c != 429 {
		t.Fatalf("one too many for one identity: %d, want 429", c)
	}
	if c := post(bob.id, "203.0.113.1", ""); c != 202 {
		t.Fatalf("another identity from a fresh address: %d", c)
	}
}
