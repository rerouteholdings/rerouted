package api

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

var errAccountIO = errors.New("injected account storage failure")

// failingAccount fails UpdateKeys: before reading anything ("read"), or by handing the
// store an invalid change after decide's own ("apply"), so the store has to undo the
// valid changes that came first.
type failingAccount struct {
	store.Account
	fail string
}

func (a failingAccount) UpdateKeys(ctx context.Context, id string, decide func([][]byte, []store.KeySlot) ([]store.KeyChange, error)) error {
	if a.fail == "read" {
		return errAccountIO
	}
	return a.Account.UpdateKeys(ctx, id, func(chain [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		changes, err := decide(chain, slots)
		return append(changes, store.KeyChange{Slot: "broken"}), err
	})
}

type accountFaultStore struct {
	store.Store
	account store.Account
}

func (s accountFaultStore) Account() store.Account { return s.account }

// storeWithTrigger opens a store, and returns a function that makes writes of one kind
// to account_keys fail: a real failure inside the transaction, after earlier writes in it
// succeeded.
func storeWithTrigger(t *testing.T) (store.Store, func(on string)) {
	path := filepath.Join(t.TempDir(), "r.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return st, func(on string) {
		if _, err := db.Exec("CREATE TRIGGER fail_keys BEFORE " + on + " ON account_keys WHEN (SELECT count(*) FROM account_keys) > 0 BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
			t.Fatal(err)
		}
	}
}

// A storage failure anywhere in a wrap update is a 503, and leaves every wrap as it was:
// an older client's staged slot isn't lost in a failed move to its own slot, and a failed promotion
// neither replaces nor retains anything.
func TestStagedWrapStorageErrors(t *testing.T) {
	for _, failure := range []string{"read", "apply", "trigger-insert", "trigger-delete"} {
		t.Run(failure, func(t *testing.T) {
			base, trigger := storeWithTrigger(t)
			var account store.Account = base.Account()
			if failure == "read" || failure == "apply" {
				account = failingAccount{base.Account(), failure}
			}
			ts := testServerWith(t, accountFaultStore{base, account})
			kat := newUser(t, ts, "kat")
			ctx := context.Background()
			a, b := codeOf(kat), newTestCode()
			legacy, _ := wire.Marshal(map[string]any{"via": "recovery-next", "ct": randBytes(44), "commit": randBytes(32)})
			current, _ := wire.Marshal(map[string]any{"via": "recovery", "ct": randBytes(44), "commit": a.commit(1)})
			for slot, raw := range map[string][]byte{"recovery-next": legacy, "recovery": current} {
				if err := base.Account().SetKey(ctx, kat.id, slot, raw); err != nil {
					t.Fatal(err)
				}
			}
			if rotate(t, ts, kat, a.key(1), b.commit(1)) != 200 {
				t.Fatal("rotation")
			}
			switch failure {
			case "trigger-insert":
				trigger("INSERT")
			case "trigger-delete":
				trigger("DELETE")
			}
			for what, code := range map[string]int{
				"cleanup": cleanupWraps(t, ts, kat, nil),
				"promote": setWrap(t, ts, kat, "recovery", b.commit(1), "B"),
				"stage":   setWrap(t, ts, kat, "recovery-next", newTestCode().commit(1), "C"),
			} {
				if code != 503 {
					t.Errorf("%s: storage failure acknowledged as %d, want 503", what, code)
				}
			}
			keys, err := base.Account().Keys(ctx, kat.id)
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != 2 {
				t.Errorf("%d wraps after failed updates, want the 2 there were", len(keys))
			}
			if got, err := base.Account().Key(ctx, kat.id, "recovery-next"); err != nil || !bytes.Equal(got, legacy) {
				t.Errorf("legacy wrap lost on failed migration: %v", err)
			}
			if got, err := base.Account().Key(ctx, kat.id, "recovery"); err != nil || !bytes.Equal(got, current) {
				t.Errorf("recovery wrap changed by a failed promotion: %v", err)
			}
		})
	}
}
