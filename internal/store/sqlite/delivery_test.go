package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// A delivery that fails to reach the inbox isn't recorded as seen either, so a retry
// stores it. Before Deliver, the ID was recorded first and the item lost for good.
func TestDeliverStoresWholeOrNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Fails the inbox insert, which comes after the seen record in the same transaction.
	if _, err := db.Exec("CREATE TRIGGER fail_inbox BEFORE INSERT ON inbox BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	it := store.Item{TS: 1000, Delivery: []byte(`{"id":"x"}`)}
	if _, _, err := st.Inbox().Deliver(ctx, "kat", []byte{1}, it); err == nil {
		t.Fatal("the injected failure didn't fail Deliver")
	}
	if _, err := db.Exec("DROP TRIGGER fail_inbox"); err != nil {
		t.Fatal(err)
	}
	cur, isNew, err := st.Inbox().Deliver(ctx, "kat", []byte{1}, it)
	if err != nil || !isNew || cur == "" {
		t.Fatalf("retry after the failure: %q %v %v", cur, isNew, err)
	}
	if cur, isNew, err := st.Inbox().Deliver(ctx, "kat", []byte{1}, it); err != nil || isNew || cur != "" {
		t.Fatalf("a repeat: %q %v %v", cur, isNew, err)
	}
	items, _, _, err := st.Inbox().List(ctx, "kat", []byte("dev"), "", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("inbox: %d items, %v", len(items), err)
	}
	// Another owner's copy of the same ID is its own.
	if _, isNew, err := st.Inbox().Deliver(ctx, "ravi", []byte{1}, it); err != nil || !isNew {
		t.Fatalf("same ID, another owner: %v %v", isNew, err)
	}
	// Pruning forgets IDs seen before the cutoff, and only those.
	if n, err := st.Inbox().PruneSeen(ctx, 1001); err != nil || n != 2 {
		t.Fatalf("pruned %d (%v), want 2", n, err)
	}
}
