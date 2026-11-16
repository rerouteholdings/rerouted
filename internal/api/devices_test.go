package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// head returns an identity's current chain head (seq and hash), through the public chain read.
func head(t *testing.T, ts *httptest.Server, id string) (uint64, []byte) {
	t.Helper()
	var res struct {
		Entries []wire.Raw `json:"entries"`
	}
	if c := call(t, ts, "GET", "chain/"+id, "", nil, &res); c != 200 {
		t.Fatalf("public chain read: %d", c)
	}
	last, _ := wire.DecodeSigned(res.Entries[len(res.Entries)-1])
	enc, _ := last.Encode()
	sum := sha256.Sum256(enc)
	return uint64(len(res.Entries) - 1), sum[:]
}

func login(t *testing.T, ts *httptest.Server, id, server string, dev ed25519.PrivateKey) int {
	t.Helper()
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	if c := call(t, ts, "POST", "auth/challenge", "", map[string]any{"id": id, "key": []byte(dev.Public().(ed25519.PublicKey))}, &ch); c != 200 {
		return c
	}
	auth := signed(t, "auth", map[string]any{"id": id, "nonce": ch.Nonce, "server": server, "ts": time.Now().Unix()}, dev)
	return call(t, ts, "POST", "auth/session", "", map[string]any{"auth": auth}, nil)
}

func TestRecover(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	_, newDev, _ := ed25519.GenerateKey(rand.Reader)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	next := sha256.Sum256(nextPub)

	// The new device can't sign in yet.
	if c := login(t, ts, kat.id, "chat.test", newDev); c != 403 {
		t.Fatalf("login before recovery: %d, want 403", c)
	}
	seq, prev := head(t, ts, kat.id)
	entry := func(signer ed25519.PrivateKey) wire.Raw {
		return signed(t, "chain-entry", map[string]any{
			"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
			"ops": []any{
				map[string]any{"op": "add-device", "key": []byte(newDev.Public().(ed25519.PublicKey)), "name": "recovered"},
				map[string]any{"op": "set-recovery", "next": next[:]},
			},
		}, signer)
	}
	// A device key can't use the recovery endpoint (and can't sign set-recovery at all).
	if c := call(t, ts, "POST", "recover", "", map[string]any{"entry": entry(kat.dev)}, nil); c != 400 && c != 403 {
		t.Fatalf("device-signed recover: %d, want 400/403", c)
	}
	// The recovery key can.
	if c := call(t, ts, "POST", "recover", "", map[string]any{"entry": entry(kat.rec)}, nil); c != 200 {
		t.Fatalf("recover: %d", c)
	}
	if c := login(t, ts, kat.id, "chat.test", newDev); c != 200 {
		t.Fatalf("login after recovery: %d", c)
	}
	// Kat's other device is told the recovery code was used.
	found := false
	for _, it := range kat.inbox() {
		if it.Notice != nil {
			var n struct {
				T     string `json:"t"`
				Level string `json:"level"`
			}
			wire.Unmarshal(it.Notice, &n)
			found = found || (n.T == "chain-alert" && n.Level == "alarm")
		}
	}
	if !found {
		t.Fatal("no alarm notice after recovery")
	}
}

func TestPushAndRemoteHub(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")

	// Connect them (Kat asks, Bob accepts), with Bob's server as the hub.
	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, &res)
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	call(t, a, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil)
	bob.eventually(1)
	call(t, b, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil)
	group := randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, ek1, _ := ed25519.GenerateKey(rand.Reader)
	ek2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	call(t, b, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "direct", "epoch-key": []byte(ek0Pub)}, nil)
	var sent struct {
		Results []sendResult `json:"results"`
	}
	commit := func(u *testUser, ts *httptest.Server, epoch int, ek ed25519.PrivateKey, next ed25519.PublicKey, hub string) sendResult {
		data := randBytes(40)
		sum := sha256.Sum256(data)
		cr := signed(t, "commit-request", map[string]any{"group": group, "epoch": epoch, "hash": sum[:], "next": []byte(next)}, ek)
		out := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id, bob.id}, "group": group, "epoch": epoch, "mls": "commit", "data": data, "commit": cr}
		if hub != "" {
			out["hub"] = hub
		}
		call(t, ts, "POST", "send", u.token, map[string]any{"deliveries": []any{out}}, &sent)
		return sent.Results[0]
	}
	if r := commit(bob, b, 0, ek0, ek1Pub, ""); r.Status != "sent" {
		t.Fatalf("bob's commit: %+v", r)
	}
	call(t, a, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil)

	// Kat, on a.test, commits in a group whose hub is b.test: a.test forwards it (S2S commit).
	if r := commit(kat, a, 1, ek1, ek2Pub, "b.test"); r.Status != "sent" || r.Receipt == nil {
		t.Fatalf("remote-hub commit: %+v", r)
	}
	// Replaying epoch 1 loses: the hub moved on.
	if r := commit(kat, a, 1, ek1, ek2Pub, "b.test"); r.Error != "stale-epoch" {
		t.Fatalf("stale remote commit: %+v", r)
	}

	// Kat adds a device. b.test learns through identity push, and tells Bob.
	_, dev2, _ := ed25519.GenerateKey(rand.Reader)
	seq, prev := head(t, a, kat.id)
	entry := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "add-device", "key": []byte(dev2.Public().(ed25519.PublicKey)), "name": "second"}},
	}, kat.dev)
	if c := call(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, nil); c != 200 {
		t.Fatalf("append: %d", c)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, it := range bob.inbox() {
			if it.Notice != nil {
				var n struct {
					T  string `json:"t"`
					ID string `json:"id"`
				}
				wire.Unmarshal(it.Notice, &n)
				if n.T == "chain-update" && n.ID == kat.id {
					var ch struct {
						Entries []any `json:"entries"`
					}
					call(t, b, "GET", "chain/"+kat.id, bob.token, nil, &ch)
					if len(ch.Entries) != 2 {
						t.Fatalf("b.test's cached chain has %d entries, want 2", len(ch.Entries))
					}
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("bob never got a chain-update notice")
}
