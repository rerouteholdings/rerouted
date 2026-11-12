package api

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// accountState is what a homeserver holds of an identity's account data, key wraps, and backups.
type accountState struct {
	version   int64
	segments  int
	vias      map[string]bool
	recCommit []byte
}

func readAccount(t *testing.T, st store.Store, id string) accountState {
	t.Helper()
	ctx := context.Background()
	v, _, err := st.Account().Data(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	segs, err := st.Backups().List(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := st.Account().Keys(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	out := accountState{version: v, segments: len(segs), vias: map[string]bool{}}
	for _, raw := range keys {
		var k wrappedKey
		if wire.Unmarshal(raw, &k) == nil {
			out.vias[k.Via] = true
			if k.Via == "recovery" {
				out.recCommit = k.Commit
			}
		}
	}
	return out
}

// A return migration (an identity coming back to a homeserver that kept its tombstone)
// starts clean: the account data, backups, and passphrase wrap from the earlier stay are
// gone, in the same transaction as the registration, so an old copy can't be mistaken for
// the current one. Recovery wraps stay, under their own lifecycle. A first arrival is
// unaffected, and a retry of the accepted return can't clear what was written after it.
func TestReturnMoveClearsEarlierStay(t *testing.T) {
	stores := map[string]store.Store{}
	a, b, _, _ := twoServersWithStore(t, func() store.Store {
		st := newStore(t)
		if len(stores) == 0 {
			stores["a"] = st
		} else {
			stores["b"] = st
		}
		return st
	})
	kat := newUserOn(t, a, "kat", "a.test")
	code := codeOf(kat)
	// The first stay on a.test: recovery and passphrase wraps, account data, a backup.
	if setWrap(t, a, kat, "recovery", code.commit(1), "recovery wrap") != 204 {
		t.Fatal("recovery wrap")
	}
	pass := map[string]any{"via": "passphrase", "ct": randBytes(44), "argon2": map[string]any{"salt": randBytes(16), "m": 65536, "t": 3, "p": 1}}
	if c := call(t, a, "POST", "account/keys", kat.token, map[string]any{"set": pass}, nil); c != 204 {
		t.Fatalf("passphrase wrap: %d", c)
	}
	if c := call(t, a, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, nil); c != 200 {
		t.Fatalf("account data: %d", c)
	}
	if c := call(t, a, "POST", "backup/put", kat.token, map[string]any{"seq": 1, "ct": randBytes(64)}, nil); c != 204 {
		t.Fatalf("backup: %d", c)
	}
	// First arrival on b.test: whatever b.test had is untouched (it had nothing), and
	// a.test keeps the tombstone's data until she comes back.
	kat.moveTo(a, b, "b.test", nil)
	if got := readAccount(t, stores["a"], kat.id); got.version != 1 || got.segments != 1 || !got.vias["passphrase"] {
		t.Fatalf("a.test after she left: %+v", got)
	}
	if c := call(t, b, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, nil); c != 200 {
		t.Fatalf("account data at b.test: %d", c)
	}
	// She returns to a.test.
	entries := kat.chainOf(b)
	entry := kat.moveEntry(entries, "a.test", "kat.a.test")
	res := kat.reserveMove(a, entries, entry, "a.test")
	if c, e := kat.appendMove(b, entry, res); c != 200 {
		t.Fatalf("append the return: %d %+v", c, e)
	}
	chain := kat.chainOf(b)
	h := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "a.test", "head": h[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	req := map[string]any{"chain": chain, "move": mv, "invite": testRegCode}
	if c := call(t, a, "POST", "register", "", req, nil); c != 200 {
		t.Fatalf("register the return: %d", c)
	}
	got := readAccount(t, stores["a"], kat.id)
	if got.version != 0 || got.segments != 0 || got.vias["passphrase"] {
		t.Fatalf("the earlier stay's data survived the return: %+v", got)
	}
	if !got.vias["recovery"] || string(got.recCommit) != string(code.commit(1)) {
		t.Fatalf("the return touched the recovery wrap: %+v", got)
	}
	if got := readAccount(t, stores["b"], kat.id); got.version != 1 {
		t.Fatalf("b.test's copy changed: %+v", got)
	}
	// After acceptance, she writes; a retry of the same registration (even freshly
	// signed) is a no-op that keeps it.
	if c := kat.signIn(a, "a.test"); c != 200 {
		t.Fatalf("sign in: %d", c)
	}
	if c := call(t, a, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, nil); c != 200 {
		t.Fatalf("account data after the return: %d", c)
	}
	if c := call(t, a, "POST", "backup/put", kat.token, map[string]any{"seq": 5, "ct": randBytes(64)}, nil); c != 204 {
		t.Fatalf("backup after the return: %d", c)
	}
	for _, retry := range []wire.Raw{mv, signed(t, "move", map[string]any{"id": kat.id, "server": "a.test", "head": h[:], "ts": time.Now().Unix() + 1, "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)} {
		req["move"] = retry
		if c := call(t, a, "POST", "register", "", req, nil); c != 200 {
			t.Fatalf("retry: %d", c)
		}
	}
	if got := readAccount(t, stores["a"], kat.id); got.version != 1 || got.segments != 1 || !got.vias["recovery"] {
		t.Fatalf("a retry cleared data written after the return was accepted: %+v", got)
	}
}
