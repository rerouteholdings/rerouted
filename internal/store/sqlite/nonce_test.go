package sqlite

import (
	"context"
	"testing"
)

// A request nonce is fresh once until it expires, and pruning removes only expired ones.
func TestUseNonce(t *testing.T) {
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	x := st.Sessions()
	for _, c := range []struct {
		now, exp int64
		fresh    bool
	}{
		{100, 700, true},   // first use
		{200, 800, false},  // replay while it's live
		{700, 1300, false}, // still live at its expiry second
		{701, 1301, true},  // expired: a new use takes the record over
	} {
		fresh, err := x.UseNonce(ctx, "s2s|a.test|01", c.exp, c.now)
		if err != nil || fresh != c.fresh {
			t.Fatalf("at %d: fresh %v (%v), want %v", c.now, fresh, err, c.fresh)
		}
	}
	if _, err := x.UseNonce(ctx, "s2s|a.test|02", 500, 100); err != nil {
		t.Fatal(err)
	}
	if n, err := x.PruneNonces(ctx, 600); err != nil || n != 1 {
		t.Fatalf("pruned %d (%v), want 1", n, err)
	}
	if fresh, err := x.UseNonce(ctx, "s2s|a.test|01", 2000, 900); err != nil || fresh {
		t.Fatalf("pruning removed a live nonce: %v %v", fresh, err)
	}
}
