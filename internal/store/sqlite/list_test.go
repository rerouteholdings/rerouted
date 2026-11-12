package sqlite

import (
	"context"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// List never panics on a limit below 1: it returns pages of one.
func TestListLimitBelowOne(t *testing.T) {
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for i := range 3 {
		if _, err := st.Inbox().Append(ctx, "kat", store.Item{TS: 1, Delivery: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
		if err := st.Contacts().Put(ctx, "kat", store.Contact{ID: string(rune('a' + i)), State: store.StateContact}); err != nil {
			t.Fatal(err)
		}
	}
	for _, limit := range []int{0, -1} {
		if items, next, _, err := st.Inbox().List(ctx, "kat", []byte("dev"), "", limit); err != nil || len(items) != 1 || next == "" {
			t.Fatalf("inbox, limit %d: %d items, next %q, %v", limit, len(items), next, err)
		}
		if cs, next, err := st.Contacts().List(ctx, "kat", "", limit); err != nil || len(cs) != 1 || next == "" {
			t.Fatalf("contacts, limit %d: %d, next %q, %v", limit, len(cs), next, err)
		}
	}
}
