package api

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// SPEC §6.6, §7.1: someone who moved away keeps changing their chain at their new home. The
// old home keeps a tombstone that stops at the move, and still serves it to other servers,
// but its own users asking for the chain get the current one from the new home: a group they
// share with the mover binds entries the tombstone doesn't have.
func TestOldHomeServesMoversCurrentChain(t *testing.T) {
	a, b, sa, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, a, "ravi", "a.test")

	entries := kat.chainOf(a)
	if c := kat.leave(a, b, kat.moveEntry(entries, "b.test", "kat.b.test"), "b.test"); c != 200 {
		t.Fatalf("append the move: %d", c)
	}
	moved := kat.chainOf(a)
	head := sha256.Sum256(moved[len(moved)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": moved, "invite": testRegCode, "move": mv}, nil); c != 200 {
		t.Fatalf("register at b.test: %d", c)
	}
	if c := kat.signIn(b, "b.test"); c != 200 {
		t.Fatalf("sign in at b.test: %d", c)
	}
	// A new entry at the new home: one the tombstone at a.test doesn't have.
	last := sha256.Sum256(moved[len(moved)-1])
	next := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": len(moved), "prev": last[:], "ts": time.Now().Unix(), "ops": []any{map[string]any{"op": "set-handle", "handle": "kitty.b.test"}}}, kat.dev)
	if c := call(t, b, "POST", "chain/append", kat.token, map[string]any{"entry": next}, nil); c != 200 {
		t.Fatalf("append at b.test: %d", c)
	}
	want := len(moved) + 1

	count := func(q string) (int, int) {
		var res struct {
			Entries []wire.Raw `json:"entries"`
		}
		c := call(t, a, "GET", "chain/"+kat.id+q, ravi.token, nil, &res)
		return c, len(res.Entries)
	}
	// a.test keeps the tombstone, which other servers get with identity/fetch (§6.6).
	if tomb, err := sa.st.Chains().Entries(context.Background(), kat.id, -1); err != nil || len(tomb) != len(moved) {
		t.Fatalf("tombstone: %d entries (%v), want %d", len(tomb), err, len(moved))
	}
	if c, n := count(""); c != 200 || n != want {
		t.Fatalf("ravi at the old home gets %d entries (%d), want the current %d", n, c, want)
	}
	if c, n := count("?fresh=1"); c != 200 || n != want {
		t.Fatalf("a fresh copy at the old home: %d entries (%d), want %d", n, c, want)
	}
	if c, n := count("?fresh=1&home=a.test"); c != 200 || n != want {
		t.Fatalf("a fresh copy naming the old home: %d entries (%d), want %d", n, c, want)
	}
}
