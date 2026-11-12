package api

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

func TestMoveRejectsUnprovenLocalChain(t *testing.T) {
	for _, complete := range []bool{false, true} {
		name := "prefix"
		if complete {
			name = "complete-without-receipt"
		}
		t.Run(name, func(t *testing.T) {
			a, b, _, sb := twoServersWithStore(t, func() store.Store { return newStore(t) })
			kat := newUserOn(t, a, "kat", "a.test")
			ravi := newUserOn(t, b, "ravi", "b.test")
			entry := kat.moveEntry(kat.chainOf(a), "b.test", "kat.b.test")
			if c := kat.leave(a, b, entry, "b.test"); c != 200 {
				t.Fatal(c)
			}
			entries := kat.chainOf(a)
			ctx := context.Background()
			if err := sb.st.Chains().Create(ctx, kat.id, entries[0], "kat.b.test"); err != nil {
				t.Fatal(err)
			}
			if complete {
				if err := sb.st.Chains().Append(ctx, kat.id, 0, entries[1]); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := sb.st.Chains().Entries(ctx, kat.id, -1)
			head := sha256.Sum256(entries[len(entries)-1])
			group := randBytes(32)
			mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{ravi.id}, "groups": []wire.Bytes{group}}, kat.dev)
			want := 409
			if complete {
				want = 200
			}
			for _, check := range []bool{true, false} {
				if c := call(t, b, "POST", "register", "", map[string]any{"chain": entries, "move": mv, "invite": testRegCode, "check": check}, nil); c != want {
					t.Fatalf("check=%v: %d", check, c)
				}
			}
			after, _ := sb.st.Chains().Entries(ctx, kat.id, -1)
			if !store.SameChain(before, after) {
				t.Fatal("unproven local chain changed")
			}
			if _, err := sb.st.Contacts().Get(ctx, kat.id, ravi.id); err == nil {
				t.Fatal("rejection imported contact")
			}
			if ok, _ := sb.st.Contacts().GroupAllowed(ctx, kat.id, group); ok {
				t.Fatal("rejection imported group")
			}
		})
	}
}
