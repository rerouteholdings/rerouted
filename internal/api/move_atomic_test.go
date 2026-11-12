package api

import (
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

func TestMoveReturnAndReplay(t *testing.T) {
	a, b, sa, sb := twoServersWithStore(t, func() store.Store { return newStore(t) })
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, b, "ravi", "b.test")
	group := randBytes(32)
	ctx := context.Background()
	migrate := func(from, to *httptest.Server, home, handle string, contacts []string, groups []wire.Bytes) map[string]any {
		t.Helper()
		entry := kat.moveEntry(kat.chainOf(from), home, handle)
		entries := append(kat.chainOf(from), entry)
		head := sha256.Sum256(entries[len(entries)-1])
		mv := signed(t, "move", map[string]any{"id": kat.id, "server": home, "head": head[:], "ts": time.Now().Unix(), "contacts": contacts, "groups": groups}, kat.dev)
		req := map[string]any{"chain": entries, "move": mv, "invite": testRegCode, "check": true}
		var pre struct {
			Reservation wire.Raw `json:"reservation"`
		}
		if c := call(t, to, "POST", "register", "", req, &pre); c != 200 || pre.Reservation == nil {
			t.Fatalf("preflight %s: %d", home, c)
		}
		if c := call(t, from, "POST", "chain/append", kat.token, map[string]any{"entry": entry, "reservation": pre.Reservation}, nil); c != 200 {
			t.Fatalf("leave for %s: %d", home, c)
		}
		delete(req, "check")
		if c := call(t, to, "POST", "register", "", req, nil); c != 200 {
			t.Fatalf("arrive %s: %d", home, c)
		}
		if c := kat.signIn(to, home); c != 200 {
			t.Fatalf("sign in %s: %d", home, c)
		}
		return req
	}
	first := migrate(a, b, "b.test", "kat.b.test", []string{ravi.id}, []wire.Bytes{group})
	if err := sb.st.Contacts().Delete(ctx, kat.id, ravi.id); err != nil {
		t.Fatal(err)
	}
	if err := sb.st.Contacts().DisallowGroup(ctx, kat.id, group); err != nil {
		t.Fatal(err)
	}
	replayNumber := int64(0)
	replay := func() {
		t.Helper()
		// resume_move creates a new signature and timestamp on every retry.
		replayNumber++
		original := first["chain"].([]wire.Raw)
		head := sha256.Sum256(original[len(original)-1])
		first["move"] = signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix() + replayNumber, "contacts": []string{ravi.id}, "groups": []wire.Bytes{group}}, kat.dev)
		before, _ := sb.st.Chains().Entries(ctx, kat.id, -1)
		if c := call(t, b, "POST", "register", "", first, nil); c != 200 {
			t.Fatalf("exact replay: %d", c)
		}
		after, _ := sb.st.Chains().Entries(ctx, kat.id, -1)
		if !store.SameChain(before, after) {
			t.Fatal("replay changed newer chain")
		}
		if _, err := sb.st.Contacts().Get(ctx, kat.id, ravi.id); err == nil {
			t.Fatal("replay restored removed contact")
		}
		if ok, _ := sb.st.Contacts().GroupAllowed(ctx, kat.id, group); ok {
			t.Fatal("replay restored removed group")
		}
	}
	replay()
	// A distinct signed operation for an already accepted head is not a retry.
	entries := kat.chainOf(b)
	head := sha256.Sum256(entries[len(entries)-1])
	changed := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": entries, "move": changed, "invite": testRegCode}, nil); c != 409 {
		t.Fatalf("different operation: %d", c)
	}
	// Move back to the genesis home, whose tombstone is still present.
	migrate(b, a, "a.test", "kat.a.test", []string{}, []wire.Bytes{})
	replay()
	// Return to b again, replacing its old lists rather than merging them.
	if err := sb.st.Contacts().Put(ctx, kat.id, store.Contact{ID: ravi.id, State: store.StateContact}); err != nil {
		t.Fatal(err)
	}
	if err := sb.st.Contacts().AllowGroup(ctx, kat.id, group); err != nil {
		t.Fatal(err)
	}
	migrate(a, b, "b.test", "kat.b.test", []string{}, []wire.Bytes{})
	replay()
	if got, _ := sa.st.Chains().Entries(ctx, kat.id, -1); len(got) != 4 {
		t.Fatalf("old home tombstone length: %d", len(got))
	}
}
