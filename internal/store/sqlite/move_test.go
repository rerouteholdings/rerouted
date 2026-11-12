package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

func TestMoveRollbackAndDurableRetry(t *testing.T) {
	for _, table := range []string{"chains", "contacts", "groups_allowed", "move_registrations"} {
		t.Run(table, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			ctx := context.Background()
			m := store.MoveRegistration{ID: "kat", Handle: "kat.test", Operation: []byte("move"), Entries: [][]byte{[]byte("genesis"), []byte("arrival")}, Contacts: []store.Contact{{ID: "ravi", State: store.StateContact}}, Groups: [][]byte{[]byte("group")}}
			// Fail each phase, including the receipt after every other write has run.
			if _, err := s.db.Exec("CREATE TRIGGER fail_move BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Chains().RegisterMove(ctx, m); err == nil {
				t.Fatal("injected failure succeeded")
			}
			for _, table := range []string{"chains", "handles", "contacts", "groups_allowed", "move_registrations"} {
				var n int
				if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
					t.Fatalf("%s: %d, %v", table, n, err)
				}
			}
			if _, err := s.db.Exec("DROP TRIGGER fail_move"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Chains().RegisterMove(ctx, m); err != nil {
				t.Fatal(err)
			}
			if err := s.Contacts().Delete(ctx, m.ID, "ravi"); err != nil {
				t.Fatal(err)
			}
			if err := s.Contacts().DisallowGroup(ctx, m.ID, []byte("group")); err != nil {
				t.Fatal(err)
			}
			if err := s.Chains().Append(ctx, m.ID, 1, []byte("away")); err != nil {
				t.Fatal(err)
			}
			// A return transaction that fails must preserve the tombstone and old lists.
			ret := m
			ret.Operation = []byte("return")
			ret.Expected, _ = s.Chains().Entries(ctx, m.ID, -1)
			ret.Entries = append(append([][]byte(nil), ret.Expected...), []byte("return"))
			if _, err := s.db.Exec("CREATE TRIGGER fail_move BEFORE INSERT ON move_registrations BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Chains().RegisterMove(ctx, ret); err == nil {
				t.Fatal("return failure succeeded")
			}
			got, _ := s.Chains().Entries(ctx, m.ID, -1)
			if !store.SameChain(got, ret.Expected) {
				t.Fatal("return rollback lost tombstone")
			}
			if _, err := s.db.Exec("DROP TRIGGER fail_move"); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Chains().RegisterMove(ctx, m); err != nil {
				t.Fatal(err)
			}
			got, _ = s.Chains().Entries(ctx, m.ID, -1)
			if len(got) != 3 {
				t.Fatal("durable retry rolled back move away")
			}
			if _, err := s.Contacts().Get(ctx, m.ID, "ravi"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("durable retry restored contact")
			}
			if ok, _ := s.Contacts().GroupAllowed(ctx, m.ID, []byte("group")); ok {
				t.Fatal("durable retry restored group")
			}
			if _, err := s.Chains().RegisterMove(ctx, ret); err != nil {
				t.Fatal(err)
			}
		})
	}
}
