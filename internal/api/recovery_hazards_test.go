package api

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Former opt-in hazards (REROUTED_KNOWN_HAZARDS=1), now ordinary regressions. The third,
// cleanup racing a recovery append, is TestRecoveryCleanupRacesAppend.

// Cleanup after a recovery advances the chain's commitment keeps the staged wrap: the chain
// still commits to its code (key 1, in the genesis entry here).
func TestRecoveryCleanupAfterAdvancement(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	ctx := context.Background()
	commit := sha256.Sum256(kat.rec[32:])
	wrap, err := wire.Marshal(map[string]any{"via": "recovery-next", "commit": commit[:], "ct": randBytes(44)})
	if err != nil {
		t.Fatal(err)
	}
	// Seed the slot older clients used, so the migration to per-code slots is covered too.
	if err := st.Account().SetKey(ctx, kat.id, "recovery-next", wrap); err != nil {
		t.Fatal(err)
	}
	seq, prev := head(t, ts, kat.id)
	entry := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-recovery", "next": randBytes(32)}},
	}, kat.rec)
	if code := call(t, ts, "POST", "recover", "", map[string]any{"entry": entry}, nil); code != 200 {
		t.Fatalf("recover: %d", code)
	}
	if code := call(t, ts, "POST", "account/keys", kat.token, map[string]any{"remove": "recovery-next"}, nil); code != 204 {
		t.Fatalf("cleanup: %d", code)
	}
	keys, err := st.Account().Keys(ctx, kat.id)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("cleanup deleted the unpromoted wrap after recovery advanced the chain commitment")
	}
}

// A promotion naming a code the chain doesn't commit to is refused, and the current wrap
// stays.
func TestRecoveryStalePromotion(t *testing.T) {
	ts := testServerWith(t, newStore(t))
	kat := newUser(t, ts, "kat")
	current := sha256.Sum256(kat.rec[32:])
	set := func(commit []byte, ct []byte) int {
		return call(t, ts, "POST", "account/keys", kat.token, map[string]any{"set": map[string]any{"via": "recovery", "commit": commit, "ct": ct}}, nil)
	}
	winner := randBytes(44)
	if code := set(current[:], winner); code != 204 {
		t.Fatalf("current promotion: %d", code)
	}
	if code := set(randBytes(32), randBytes(44)); code == 204 {
		t.Fatal("stale promotion overwrote the current recovery wrap")
	}
	if ct, _ := currentWrap(t, ts, kat); ct != string(winner) {
		t.Fatal("the current recovery wrap changed")
	}
}

func TestMoveRejectsPrefixWithoutAllowlists(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, b, "ravi", "b.test")
	move := kat.moveEntry(kat.chainOf(a), "b.test", "kat.b.test")
	if code := kat.leave(a, b, move, "b.test"); code != 200 {
		t.Fatalf("append: %d", code)
	}
	entries := kat.chainOf(a)
	ctx := context.Background()
	// A matching prefix is not evidence that any registration allowlists were persisted.
	if err := sb.st.Chains().Create(ctx, kat.id, entries[0], "kat.b.test"); err != nil {
		t.Fatal(err)
	}
	head := sha256.Sum256(entries[len(entries)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{ravi.id}, "groups": []wire.Bytes{}}, kat.dev)
	code := call(t, b, "POST", "register", "", map[string]any{"chain": entries, "move": mv, "invite": testRegCode}, nil)
	if code != 409 {
		t.Fatalf("unproven prefix: %d, want 409", code)
	}
	if _, err := sb.st.Contacts().Get(ctx, kat.id, ravi.id); err == nil {
		t.Fatal("rejected prefix imported contacts")
	}
	if got, _ := sb.st.Chains().Entries(ctx, kat.id, -1); len(got) != 1 {
		t.Fatal("rejected prefix changed chain")
	}
}
