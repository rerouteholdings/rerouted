package sqlite

import (
	"context"
	"testing"
)

// Each use keeps a token alive for at least 30 more days, but only writes when the stored expiry
// has fallen under 30 days away, so a burst of requests costs one write.
func TestLookupTokenExtends(t *testing.T) {
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	x := st.Sessions()
	hash := []byte("token-hash")
	if err := x.CreateToken(ctx, hash, "kat.example.com", []byte{1}, "laptop", 1000+tokenTTL); err != nil {
		t.Fatal(err)
	}
	expires := func() int64 {
		var e int64
		if err := st.db.QueryRow("SELECT expires FROM tokens WHERE hash = ?", hash).Scan(&e); err != nil {
			t.Fatal(err)
		}
		return e
	}

	// A use moves the expiry past 30 days from now.
	if _, _, err := x.LookupToken(ctx, hash, 1010); err != nil {
		t.Fatal(err)
	}
	if got, want := expires(), int64(1010+tokenTTL+tokenSlack); got != want {
		t.Fatalf("after the first use: expires %d, want %d", got, want)
	}
	// Another use within the minute leaves it: it's still 30 days or more away.
	if _, _, err := x.LookupToken(ctx, hash, 1060); err != nil {
		t.Fatal(err)
	}
	if got, want := expires(), int64(1010+tokenTTL+tokenSlack); got != want {
		t.Fatalf("a use within the minute wrote: expires %d, want %d", got, want)
	}
	// After the minute, a use extends it again, never short of 30 days.
	if _, _, err := x.LookupToken(ctx, hash, 1080); err != nil {
		t.Fatal(err)
	}
	if got := expires(); got < 1080+tokenTTL {
		t.Fatalf("expires %d, under 30 days from the last use", got)
	}
	// Unused for 30 days and a minute, it's gone.
	if _, _, err := x.LookupToken(ctx, hash, 1080+tokenTTL+tokenSlack+1); err == nil {
		t.Fatal("an expired token still worked")
	}
}
