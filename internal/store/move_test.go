package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

func TestAtomicMoveRegistration(t *testing.T) {
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	m := store.MoveRegistration{ID: "kat", Handle: "kat.test", Operation: []byte("signed move"), Entries: [][]byte{[]byte("genesis"), []byte("arrival")}, Contacts: []store.Contact{{ID: "ravi", State: store.StateContact}}, Groups: [][]byte{[]byte("group")}}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Chains().RegisterMove(canceled, m); err == nil {
		t.Fatal("canceled write succeeded")
	}
	if _, err := s.Chains().Entries(ctx, m.ID, -1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("canceled write left chain: %v", err)
	}
	check := m
	check.Check = true
	if _, err := s.Chains().RegisterMove(ctx, check); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chains().ByHandle(ctx, m.Handle); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("check reserved handle")
	}
	// Competing signed operations for the same head must not merge their lists.
	other := m
	other.Operation = []byte("different signed move")
	other.Contacts = []store.Contact{{ID: "noor", State: store.StateContact}}
	other.Groups = [][]byte{[]byte("other group")}
	start := make(chan struct{})
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for i, op := range []store.MoveRegistration{m, other} {
		wg.Add(1)
		go func(i int, op store.MoveRegistration) {
			defer wg.Done()
			<-start
			_, err := s.Chains().RegisterMove(ctx, op)
			if err == nil {
				results <- i
			} else if !errors.Is(err, store.ErrConflict) {
				t.Errorf("registration: %v", err)
			}
		}(i, op)
	}
	close(start)
	wg.Wait()
	close(results)
	winner := -1
	count := 0
	for i := range results {
		winner = i
		count++
	}
	if count != 1 {
		t.Fatalf("%d winners", count)
	}
	win, lose := m, other
	if winner == 1 {
		win, lose = other, m
	}
	if _, err := s.Contacts().Get(ctx, win.ID, win.Contacts[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Contacts().Get(ctx, lose.ID, lose.Contacts[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("loser's contacts written")
	}
	if ok, _ := s.Contacts().GroupAllowed(ctx, lose.ID, lose.Groups[0]); ok {
		t.Fatal("loser's group written")
	}
	if err := s.Contacts().Delete(ctx, win.ID, win.Contacts[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Contacts().DisallowGroup(ctx, win.ID, win.Groups[0]); err != nil {
		t.Fatal(err)
	}
	// Exact retry is harmless after edits, chain advance, and a move away.
	for _, next := range [][]byte{nil, []byte("newer chain"), []byte("move away")} {
		if next != nil {
			have, _ := s.Chains().Entries(ctx, win.ID, -1)
			if err := s.Chains().Append(ctx, win.ID, uint64(len(have)-1), next); err != nil {
				t.Fatal(err)
			}
		}
		before, _ := s.Chains().Entries(ctx, win.ID, -1)
		if _, err := s.Chains().RegisterMove(ctx, win); err != nil {
			t.Fatal(err)
		}
		after, _ := s.Chains().Entries(ctx, win.ID, -1)
		if !store.SameChain(before, after) {
			t.Fatal("retry rolled back chain")
		}
		if _, err := s.Contacts().Get(ctx, win.ID, win.Contacts[0].ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("retry restored contact")
		}
		if ok, _ := s.Contacts().GroupAllowed(ctx, win.ID, win.Groups[0]); ok {
			t.Fatal("retry restored group")
		}
	}
	// A stale local-state observation cannot replace newer state.
	stale := other
	stale.Operation = []byte("return")
	stale.Expected = m.Entries
	if _, err := s.Chains().RegisterMove(ctx, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
}
