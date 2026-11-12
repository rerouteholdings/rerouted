package api

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// pausingAccount pauses the first UpdateKeys inside its decision, where the store holds
// the lock (mem) or the transaction (sqlite) that chain writes also need.
type pausingAccount struct {
	store.Account
	reached, proceed chan struct{}
	once             *sync.Once
}

func newPausingAccount(a store.Account) pausingAccount {
	return pausingAccount{a, make(chan struct{}), make(chan struct{}), &sync.Once{}}
}

func (a pausingAccount) UpdateKeys(ctx context.Context, id string, decide func([][]byte, []store.KeySlot) ([]store.KeyChange, error)) error {
	return a.Account.UpdateKeys(ctx, id, func(chain [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		a.once.Do(func() { close(a.reached); <-a.proceed })
		return decide(chain, slots)
	})
}

// ageWrap rewrites a slot as stored `ago` seconds earlier.
func ageWrap(t *testing.T, st store.Store, id, slot string, ago int64) {
	t.Helper()
	found := false
	err := st.Account().UpdateKeys(context.Background(), id, func(_ [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		for _, k := range slots {
			if k.Slot == slot {
				found = true
				return []store.KeyChange{{Slot: slot, Wrapped: k.Wrapped, Stored: now() - ago}}, nil
			}
		}
		return nil, nil
	})
	if err != nil || !found {
		t.Fatalf("aging %s: %v, found %v", slot, err, found)
	}
}

func hasSlot(t *testing.T, st store.Store, id, slot string) bool {
	t.Helper()
	_, err := st.Account().Key(context.Background(), id, slot)
	return err == nil
}

// Formerly TestKnownHazardCleanupRacesRecoveryAppend: cleanup checks the chain, a recovery
// transition commits to the wrap, then cleanup deletes it. Now the check and the delete
// are one step that chain writes wait for, and a fresh staged wrap is kept anyway.
func TestRecoveryCleanupRacesAppend(t *testing.T) {
	for _, aged := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "aged"}[aged], func(t *testing.T) {
			base := newStore(t)
			paused := newPausingAccount(base.Account())
			ts := testServerWith(t, accountFaultStore{base, paused})
			kat := newUser(t, ts, "kat")
			a, b := codeOf(kat), newTestCode()
			raw, _ := wire.Marshal(map[string]any{"via": "recovery-next", "commit": b.commit(1), "ct": randBytes(44)})
			if err := base.Account().SetKey(context.Background(), kat.id, stagedSlot(b.commit(1)), raw); err != nil {
				t.Fatal(err)
			}
			if aged {
				ageWrap(t, base, kat.id, stagedSlot(b.commit(1)), stagedGrace+60)
			}
			entry := recoveryEntry(t, ts, kat.id, a.key(1), b.commit(1))
			cleaned := make(chan int, 1)
			go func() { cleaned <- cleanupWraps(t, ts, kat, b.commit(1)) }()
			<-paused.reached // cleanup has read the chain and the wraps, and not decided yet
			appended := make(chan int, 1)
			go func() {
				appended <- call(t, ts, "POST", "recover", "", map[string]any{"entry": entry}, nil)
			}()
			select {
			case c := <-appended:
				t.Fatalf("a chain append (%d) completed between cleanup's check and its delete", c)
			case <-time.After(300 * time.Millisecond):
			}
			close(paused.proceed)
			if c := <-cleaned; c != 204 {
				t.Fatalf("cleanup: %d", c)
			}
			if c := <-appended; c != 200 {
				t.Fatalf("recover: %d", c)
			}
			if !aged && !hasSlot(t, base, kat.id, stagedSlot(b.commit(1))) {
				t.Fatal("cleanup deleted the wrap after a concurrent recovery committed to it")
			}
			// Aged, cleanup decided first, on a chain without the commitment: the
			// known limit of the grace period (SPEC §7.4). What can't
			// happen is the append landing between that decision and the delete.
		})
	}
}

// A promotion decided on a chain that doesn't yet commit to the code is refused, even
// with the rotation landing concurrently, and can be retried after.
func TestRecoveryPromotionRacesAppend(t *testing.T) {
	base := newStore(t)
	paused := newPausingAccount(base.Account())
	ts := testServerWith(t, accountFaultStore{base, paused})
	kat := newUser(t, ts, "kat")
	a, b := codeOf(kat), newTestCode()
	raw, _ := wire.Marshal(map[string]any{"via": "recovery", "commit": a.commit(1), "ct": []byte("A")})
	if err := base.Account().SetKey(context.Background(), kat.id, "recovery", raw); err != nil {
		t.Fatal(err)
	}
	entry := recoveryEntry(t, ts, kat.id, a.key(1), b.commit(1))
	promoted := make(chan int, 1)
	go func() { promoted <- setWrap(t, ts, kat, "recovery", b.commit(1), "B") }()
	<-paused.reached
	appended := make(chan int, 1)
	go func() {
		appended <- call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, nil)
	}()
	select {
	case c := <-appended:
		t.Fatalf("a chain append (%d) completed inside a promotion's decision", c)
	case <-time.After(300 * time.Millisecond):
	}
	close(paused.proceed)
	if c := <-promoted; c != 409 {
		t.Fatalf("promotion decided before the rotation: %d, want 409", c)
	}
	if c := <-appended; c != 200 {
		t.Fatalf("rotation: %d", c)
	}
	if ct, _ := currentWrap(t, ts, kat); ct != "A" {
		t.Fatalf("recovery wrap: %q", ct)
	}
	if c := setWrap(t, ts, kat, "recovery", b.commit(1), "B"); c != 204 {
		t.Fatalf("promotion after the rotation: %d", c)
	}
}

// An unreferenced staged wrap is kept through its grace period, then can go; one the chain
// commits to is kept whatever its age until it's promoted.
func TestRecoveryWrapGrace(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	a, b, c := codeOf(kat), newTestCode(), newTestCode()
	setWrap(t, ts, kat, "recovery", a.commit(1), "A")
	setWrap(t, ts, kat, "recovery-next", b.commit(1), "B")
	cleanupWraps(t, ts, kat, nil)
	cleanupWraps(t, ts, kat, b.commit(1))
	if !hasSlot(t, st, kat.id, stagedSlot(b.commit(1))) {
		t.Fatal("a fresh staged wrap was removed: its rotation may still land")
	}
	ageWrap(t, st, kat.id, stagedSlot(b.commit(1)), stagedGrace+1)
	cleanupWraps(t, ts, kat, nil)
	if hasSlot(t, st, kat.id, stagedSlot(b.commit(1))) {
		t.Fatal("an unreferenced staged wrap past its grace period was kept")
	}
	setWrap(t, ts, kat, "recovery-next", c.commit(1), "C")
	ageWrap(t, st, kat.id, stagedSlot(c.commit(1)), 10*stagedGrace)
	if rotate(t, ts, kat, a.key(1), c.commit(1)) != 200 {
		t.Fatal("rotation")
	}
	cleanupWraps(t, ts, kat, nil)
	cleanupWraps(t, ts, kat, c.commit(1))
	if !hasSlot(t, st, kat.id, stagedSlot(c.commit(1))) {
		t.Fatal("an old staged wrap the chain commits to was removed before promotion")
	}
}

// Staged and retained wraps are capped. At the cap, new staging (and a promotion that
// would retain one more) is refused; nothing is evicted.
func TestRecoveryWrapCapNeverEvicts(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	cur := codeOf(kat)
	setWrap(t, ts, kat, "recovery", cur.commit(1), "code 0")
	rotations := 0
	for ; rotations < 100; rotations++ {
		next := newTestCode()
		c := setWrap(t, ts, kat, "recovery-next", next.commit(1), "staged")
		if c == 429 {
			break
		}
		if c != 204 || rotate(t, ts, kat, cur.key(1), next.commit(1)) != 200 {
			t.Fatalf("rotation %d: %d", rotations, c)
		}
		if c := setWrap(t, ts, kat, "recovery", next.commit(1), "promoted"); c != 204 {
			t.Fatalf("promotion %d: %d", rotations, c)
		}
		cleanupWraps(t, ts, kat, next.commit(1))
		cur = next
	}
	if rotations != maxRecoveryWraps {
		t.Fatalf("staging refused after %d rotations, want %d", rotations, maxRecoveryWraps)
	}
	retained := 0
	st.Account().UpdateKeys(context.Background(), kat.id, func(_ [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		for _, k := range slots {
			if strings.HasPrefix(k.Slot, retainedPrefix) {
				retained++
			}
		}
		return nil, nil
	})
	if retained != maxRecoveryWraps {
		t.Fatalf("%d retained wraps, want %d (none evicted)", retained, maxRecoveryWraps)
	}
	if items := listWraps(t, ts, kat); len(items) != 1 || items[0].Via != "recovery" {
		t.Fatalf("listed: %+v (retained wraps aren't listed)", items)
	}
	// A rotation that never staged can't push a promotion past the cap either.
	next := newTestCode()
	if rotate(t, ts, kat, cur.key(1), next.commit(1)) != 200 {
		t.Fatal("unstaged rotation")
	}
	if c := setWrap(t, ts, kat, "recovery", next.commit(1), "unstaged"); c != 429 {
		t.Fatalf("promotion at the cap: %d, want 429", c)
	}
	if _, commit := currentWrap(t, ts, kat); !bytes.Equal(commit, cur.commit(1)) {
		t.Fatal("the current wrap changed")
	}
}
