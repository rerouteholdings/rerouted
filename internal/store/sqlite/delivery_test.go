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

// DeliverAll stores a group delivery's copies together: a failure for one owner leaves
// none of them, and repeats, within the call or from before, get no cursor.
func TestDeliverAllStoresTogether(t *testing.T) {
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
	ctx := context.Background()
	it := store.Item{TS: 1000, Delivery: []byte(`{"id":"x"}`)}
	copies := func(owners ...string) []store.Delivered {
		var ds []store.Delivered
		for _, o := range owners {
			ds = append(ds, store.Delivered{Owner: o, ID: []byte{7}, Item: it})
		}
		return ds
	}
	if _, err := db.Exec("CREATE TRIGGER fail_ravi BEFORE INSERT ON inbox WHEN NEW.owner = 'ravi' BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Inbox().DeliverAll(ctx, copies("kat", "ravi", "lena")); err == nil {
		t.Fatal("the injected failure didn't fail DeliverAll")
	}
	if items, _, _, _ := st.Inbox().List(ctx, "kat", []byte("dev"), "", 10); len(items) != 0 {
		t.Fatal("a failed DeliverAll left kat's copy")
	}
	if _, err := db.Exec("DROP TRIGGER fail_ravi"); err != nil {
		t.Fatal(err)
	}
	if _, isNew, err := st.Inbox().Deliver(ctx, "lena", []byte{7}, it); err != nil || !isNew {
		t.Fatalf("lena's copy first: %v %v", isNew, err)
	}
	curs, err := st.Inbox().DeliverAll(ctx, copies("kat", "ravi", "kat", "lena"))
	if err != nil {
		t.Fatal(err)
	}
	if curs[0] == "" || curs[1] == "" || curs[2] != "" || curs[3] != "" {
		t.Fatalf("cursors %q: want new, new, repeat, repeat", curs)
	}
	for _, o := range []string{"kat", "ravi", "lena"} {
		if items, _, _, _ := st.Inbox().List(ctx, o, []byte("dev"), "", 10); len(items) != 1 {
			t.Fatalf("%s has %d copies, want 1", o, len(items))
		}
	}
}
