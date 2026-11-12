package api

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// A move the old home appended still registers after the destination garbage-collected
// its reservation: registration never needs one (SPEC §6.6).
func TestLateRegistrationAfterReservationGC(t *testing.T) {
	a, b, _, sb := twoServersWithStore(t, func() store.Store { return newStore(t) })
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	res := kat.reserveMove(b, entries, entry, "b.test")
	if c, e := kat.appendMove(a, entry, res); c != 200 {
		t.Fatalf("append: %d %+v", c, e)
	}
	ctx := context.Background()
	if rs, _ := sb.st.Chains().Reservations(ctx, kat.id); len(rs) != 1 {
		t.Fatalf("%d reservations stored, want 1", len(rs))
	}
	// Not before the handle hold ends...
	if n, err := sb.st.Chains().PruneReservations(ctx, now()+reservationTTL+1); err != nil || n != 0 {
		t.Fatalf("pruned %d (%v) while the hold stands", n, err)
	}
	// ...and then it goes.
	if n, err := sb.st.Chains().PruneReservations(ctx, now()+reservationTTL+reservationHold+1); err != nil || n != 1 {
		t.Fatalf("pruned %d (%v) after the hold, want 1", n, err)
	}
	chain := kat.chainOf(a)
	h := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": h[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode}, nil); c != 200 {
		t.Fatalf("late registration: %d", c)
	}
	if c := kat.signIn(b, "b.test"); c != 200 {
		t.Fatalf("sign in: %d", c)
	}
}

// Checks and registrations of the same move, at once: every one succeeds, and once the
// move is registered no reservation is left behind (registering consumes them, and a
// check after it sees the receipt and reserves nothing).
func TestMoveConcurrentCheckAndRegister(t *testing.T) {
	a, b, _, sb := twoServersWithStore(t, func() store.Store { return newStore(t) })
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	res := kat.reserveMove(b, entries, entry, "b.test")
	if c, e := kat.appendMove(a, entry, res); c != 200 {
		t.Fatalf("append: %d %+v", c, e)
	}
	chain := kat.chainOf(a)
	h := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": h[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	var wg sync.WaitGroup
	codes := make(chan int, 40)
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c, _ := kat.checkMove(b, entries, entry, "b.test")
			codes <- c
		}()
		go func() {
			defer wg.Done()
			codes <- call(t, b, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode}, nil)
		}()
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("a concurrent check or registration: %d", c)
		}
	}
	if rs, _ := sb.st.Chains().Reservations(context.Background(), kat.id); len(rs) != 0 {
		t.Fatalf("%d reservations left after registration", len(rs))
	}
	if c := kat.signIn(b, "b.test"); c != 200 {
		t.Fatalf("sign in: %d", c)
	}
}

// Reservation storage on its own, for both stores: a check stores it, a repeat refreshes
// it, a check without Reserve stores nothing, the hold blocks other identities until it
// ends, and only a committed registration consumes it.
func TestReservationStore(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	c := st.Chains()
	if err := c.Create(ctx, "kat", []byte("genesis"), "kat.old.test"); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Unix()
	r := &store.MoveReservation{ID: "kat", Entry: []byte("entry hash"), Handle: "kat.new.test", Exp: t0 + 600, Hold: t0 + 600 + reservationHold}
	m := store.MoveRegistration{ID: "kat", Handle: "kat.new.test", Operation: []byte("op"), Entries: [][]byte{[]byte("genesis"), []byte("away")}, Expected: [][]byte{[]byte("genesis")}, Check: true}
	// Kat's chain here is genesis only, so this is a strict extension of it.
	if ok, err := c.RegisterMove(ctx, m); ok || err != nil {
		t.Fatalf("check without Reserve: %v %v", ok, err)
	}
	if rs, _ := c.Reservations(ctx, "kat"); len(rs) != 0 {
		t.Fatal("a check without Reserve stored one")
	}
	m.Reserve = r
	if ok, err := c.RegisterMove(ctx, m); !ok || err != nil {
		t.Fatalf("check with Reserve: %v %v", ok, err)
	}
	r2 := *r
	r2.Exp, r2.Hold = r.Exp+60, r.Hold+60
	m.Reserve = &r2
	if ok, err := c.RegisterMove(ctx, m); !ok || err != nil {
		t.Fatalf("asking again: %v %v", ok, err)
	}
	if rs, _ := c.Reservations(ctx, "kat"); len(rs) != 1 || rs[0].Exp != r2.Exp || rs[0].Handle != "kat.new.test" {
		t.Fatalf("reservations: %+v", rs)
	}
	// Another identity can't take the handle, by signup or by move.
	if err := c.Create(ctx, "grabber", []byte("g"), "kat.new.test"); err != store.ErrHandleTaken {
		t.Fatalf("signup for a held handle: %v", err)
	}
	if _, err := c.RegisterMove(ctx, store.MoveRegistration{ID: "grabber2", Handle: "kat.new.test", Operation: []byte("op2"), Entries: [][]byte{[]byte("x")}, Check: true}); err != store.ErrHandleTaken {
		t.Fatalf("another identity's check for a held handle: %v", err)
	}
	if _, err := c.ByHandle(ctx, "kat.new.test"); err != store.ErrNotFound {
		t.Fatal("a hold isn't ownership")
	}
	// The registration consumes it.
	m.Check, m.Reserve = false, nil
	if ok, err := c.RegisterMove(ctx, m); !ok || err != nil {
		t.Fatalf("register: %v %v", ok, err)
	}
	if rs, _ := c.Reservations(ctx, "kat"); len(rs) != 0 {
		t.Fatal("registration didn't consume the reservation")
	}
	// An expired hold doesn't block anyone, and is pruned.
	old := store.MoveReservation{ID: "ravi", Entry: []byte("e"), Handle: "ravi.new.test", Exp: t0 - 100, Hold: t0 - 1}
	if err := c.Create(ctx, "ravi", []byte("rg"), "ravi.old.test"); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.RegisterMove(ctx, store.MoveRegistration{ID: "ravi", Handle: "ravi.new.test", Operation: []byte("rop"), Entries: [][]byte{[]byte("rg"), []byte("away")}, Expected: [][]byte{[]byte("rg")}, Check: true, Reserve: &old}); !ok || err != nil {
		t.Fatalf("reserve: %v %v", ok, err)
	}
	if err := c.Create(ctx, "someone", []byte("s"), "ravi.new.test"); err != nil {
		t.Fatalf("signup after the hold ended: %v", err)
	}
	if n, err := c.PruneReservations(ctx, t0); err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
}
