package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Interpose at the transaction boundary, after the API's authorization checks.
type moveBoundaryStore struct {
	store.Store
	before func(store.MoveRegistration)
}
type moveBoundaryChains struct {
	store.Chains
	s *moveBoundaryStore
}

func (s *moveBoundaryStore) Chains() store.Chains { return moveBoundaryChains{s.Store.Chains(), s} }
func (c moveBoundaryChains) RegisterMove(ctx context.Context, m store.MoveRegistration) (bool, error) {
	if c.s.before != nil && !m.Probe {
		c.s.before(m)
	}
	return c.Chains.RegisterMove(ctx, m)
}

func TestMoveConcurrentAndAuthorizationBoundary(t *testing.T) {
	var stores []*moveBoundaryStore
	a, b, _, sb := twoServersWithStore(t, func() store.Store {
		st := newStore(t)
		wrapped := &moveBoundaryStore{Store: st}
		stores = append(stores, wrapped)
		return wrapped
	})
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, b, "ravi", "b.test")
	noor := newUserOn(t, b, "noor", "b.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	if c := kat.leave(a, b, entry, "b.test"); c != 200 {
		t.Fatal(c)
	}
	entries = kat.chainOf(a)
	head := sha256.Sum256(entries[len(entries)-1])
	group := []wire.Bytes{randBytes(32), randBytes(32)}
	request := func(key ed25519.PrivateKey, other string, g wire.Bytes) map[string]any {
		return map[string]any{"chain": entries, "invite": testRegCode, "move": signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{other}, "groups": []wire.Bytes{g}}, key)}
	}
	stores[1].before = func(store.MoveRegistration) { t.Error("unauthorized operation reached storage") }
	_, outsider, _ := ed25519.GenerateKey(rand.Reader)
	if c := call(t, b, "POST", "register", "", request(outsider, ravi.id, group[0]), nil); c != 400 {
		t.Fatalf("outsider: %d", c)
	}
	stores[1].before = nil
	requests := []map[string]any{request(kat.dev, ravi.id, group[0]), request(kat.dev, noor.id, group[1])}
	// Both authorization paths observe absence before either transaction starts.
	var arrived sync.WaitGroup
	arrived.Add(2)
	stores[1].before = func(store.MoveRegistration) { arrived.Done(); arrived.Wait() }
	codes := make([]int, 2)
	var done sync.WaitGroup
	for i := range requests {
		done.Add(1)
		go func(i int) { defer done.Done(); codes[i] = call(t, b, "POST", "register", "", requests[i], nil) }(i)
	}
	done.Wait()
	stores[1].before = nil
	winner := 0
	if codes[0] != 200 {
		winner = 1
	}
	if codes[winner] != 200 || codes[1-winner] != 409 {
		t.Fatalf("concurrent outcomes: %v", codes)
	}
	ctx := context.Background()
	ids := []string{ravi.id, noor.id}
	if _, err := sb.st.Contacts().Get(ctx, kat.id, ids[winner]); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.st.Contacts().Get(ctx, kat.id, ids[1-winner]); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("losing operation leaked contacts")
	}
	if ok, _ := sb.st.Contacts().GroupAllowed(ctx, kat.id, group[1-winner]); ok {
		t.Fatal("losing operation leaked group")
	}
	// Concurrent freshly signed retries cannot import the lists again.
	if err := sb.st.Contacts().Delete(ctx, kat.id, ids[winner]); err != nil {
		t.Fatal(err)
	}
	if err := sb.st.Contacts().DisallowGroup(ctx, kat.id, group[winner]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix() + int64(i) + 1, "contacts": []string{ids[winner]}, "groups": []wire.Bytes{group[winner]}}, kat.dev)
		retry := map[string]any{"chain": entries, "invite": testRegCode, "move": mv}
		done.Add(1)
		go func() {
			defer done.Done()
			if c := call(t, b, "POST", "register", "", retry, nil); c != 200 {
				t.Errorf("fresh retry: %d", c)
			}
		}()
	}
	done.Wait()
	if _, err := sb.st.Contacts().Get(ctx, kat.id, ids[winner]); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("retry restored contact")
	}
	if ok, _ := sb.st.Contacts().GroupAllowed(ctx, kat.id, group[winner]); ok {
		t.Fatal("retry restored group")
	}
}

func TestMoveRechecksLocalStateAtCommit(t *testing.T) {
	var stores []*moveBoundaryStore
	a, b, sa, _ := twoServersWithStore(t, func() store.Store {
		st := newStore(t)
		wrapped := &moveBoundaryStore{Store: st}
		stores = append(stores, wrapped)
		return wrapped
	})
	kat := newUserOn(t, a, "kat", "a.test")
	away := kat.moveEntry(kat.chainOf(a), "b.test", "kat.b.test")
	if c := kat.leave(a, b, away, "b.test"); c != 200 {
		t.Fatal(c)
	}
	entries := kat.chainOf(a)
	// Prepare a device-signed return confirmed by b.
	back := kat.moveEntry(entries, "a.test", "kat.a.test")
	entries = append(entries, back)
	head := sha256.Sum256(back)
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "a.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	ctx := context.Background()
	// Seed b's tombstone so the normal previous-home confirmation succeeds.
	if err := stores[1].Store.Chains().Create(ctx, kat.id, entries[0], "kat.b.test"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(entries); i++ {
		if err := stores[1].Store.Chains().Append(ctx, kat.id, uint64(i-1), entries[i]); err != nil {
			t.Fatal(err)
		}
	}

	stores[0].before = func(m store.MoveRegistration) {
		// A competing local append wins after validation but before the transaction.
		if err := stores[0].Store.Chains().Append(ctx, kat.id, 1, back); err != nil {
			t.Error(err)
		}
	}
	req := map[string]any{"chain": entries, "move": mv, "invite": testRegCode}
	if c := call(t, a, "POST", "register", "", req, nil); c != 409 {
		t.Fatalf("stale observation: %d", c)
	}
	stores[0].before = nil
	got, _ := sa.st.Chains().Entries(ctx, kat.id, -1)
	if len(got) != 3 {
		t.Fatal("competing append was lost")
	}
	// With no receipt, an exact complete legacy chain is acknowledged without writes.
	if c := call(t, a, "POST", "register", "", req, nil); c != 200 {
		t.Fatalf("uncommitted operation retry: %d", c)
	}
}
