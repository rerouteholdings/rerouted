package api

import (
	"context"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// SPEC §7.4: wrapped keys, and account data whose writes are versioned.
func TestAccountData(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	rec := map[string]any{"via": "recovery", "ct": randBytes(44)}
	if c := call(t, ts, "POST", "account/keys", kat.token, map[string]any{"set": rec}, nil); c != 204 {
		t.Fatalf("set recovery: %d", c)
	}
	if c := call(t, ts, "POST", "account/keys", kat.token, map[string]any{"set": map[string]any{"via": "passphrase", "ct": randBytes(44)}}, nil); c != 400 {
		t.Fatalf("a passphrase copy without argon2: %d, want 400", c)
	}
	pass := map[string]any{"via": "passphrase", "ct": randBytes(44), "argon2": map[string]any{"salt": randBytes(16), "m": 65536, "t": 3, "p": 1}}
	call(t, ts, "POST", "account/keys", kat.token, map[string]any{"set": pass}, nil)
	var keys struct {
		Items []map[string]any `json:"items"`
	}
	call(t, ts, "GET", "account/keys", kat.token, nil, &keys)
	if len(keys.Items) != 2 {
		t.Fatalf("keys: %+v", keys.Items)
	}
	if c := call(t, ts, "POST", "account/keys", kat.token, map[string]any{"remove": "recovery"}, nil); c != 400 {
		t.Fatalf("removing the recovery copy: %d, want 400", c)
	}
	call(t, ts, "POST", "account/keys", kat.token, map[string]any{"remove": "passphrase"}, nil)
	call(t, ts, "GET", "account/keys", kat.token, nil, &keys)
	if len(keys.Items) != 1 || keys.Items[0]["via"] != "recovery" {
		t.Fatalf("after removing the passphrase copy: %+v", keys.Items)
	}

	var data struct {
		Version int64      `json:"version"`
		CT      wire.Bytes `json:"ct"`
	}
	call(t, ts, "GET", "account/data", kat.token, nil, &data)
	if data.Version != 0 || data.CT != nil {
		t.Fatalf("never written: %+v", data)
	}
	first := randBytes(64)
	if c := call(t, ts, "POST", "account/data", kat.token, map[string]any{"ct": first, "replaces": 0}, &data); c != 200 || data.Version != 1 {
		t.Fatalf("first write: %d %+v", c, data)
	}
	// Another device, still at version 0, writes: refused, so it merges first.
	if c := call(t, ts, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, nil); c != 409 {
		t.Fatalf("a stale write: %d, want 409", c)
	}
	call(t, ts, "GET", "account/data", kat.token, nil, &data)
	if data.Version != 1 || string(data.CT) != string(first) {
		t.Fatalf("after the stale write: %+v", data)
	}
}

// Distinct commitments have separate slots. A losing rotation's fresh staged wrap is kept
// through its grace period, then removed by commitment; the winner's is kept until it's
// promoted. An older client's single staged slot is moved to its own slot and kept by the same rules.
func TestStagedWrapsByCommitment(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	ctx := context.Background()
	a, won, lost := codeOf(kat), newTestCode(), newTestCode()
	staged := func() map[string]string {
		out := map[string]string{}
		for _, k := range listWraps(t, ts, kat) {
			if k.Via == "recovery-next" {
				out[string(k.CT)] = wire.B64(k.Commit)
			}
		}
		return out
	}
	if setWrap(t, ts, kat, "recovery", a.commit(1), "old code's wrap") != 204 || setWrap(t, ts, kat, "recovery-next", lost.commit(1), "loser's") != 204 || setWrap(t, ts, kat, "recovery-next", won.commit(1), "winner's") != 204 {
		t.Fatal("storing the wraps")
	}
	if got := staged(); len(got) != 2 {
		t.Fatalf("two rotations' staged wraps, got %v", got)
	}
	if rotate(t, ts, kat, a.key(1), won.commit(1)) != 200 {
		t.Fatal("the winner's rotation")
	}
	// The losing rotation tidies up its own, by commitment: kept while fresh, removed after.
	cleanupWraps(t, ts, kat, lost.commit(1))
	if got := staged(); len(got) != 2 {
		t.Fatalf("a fresh staged wrap was removed: %v", got)
	}
	ageWrap(t, st, kat.id, stagedSlot(lost.commit(1)), stagedGrace)
	if c := cleanupWraps(t, ts, kat, lost.commit(1)); c != 204 {
		t.Fatalf("remove by commitment: %d", c)
	}
	if got := staged(); len(got) != 1 || got["winner's"] == "" {
		t.Fatalf("after the loser's cleanup: %v", got)
	}
	// An older client removes without a commitment: the winner's stays, since the chain commits to it.
	cleanupWraps(t, ts, kat, nil)
	if got := staged(); got["winner's"] == "" {
		t.Fatal("a commitless remove deleted the wrap the chain commits to")
	}
	// Once promoted (the recovery wrap is for that code), it can go.
	if setWrap(t, ts, kat, "recovery", won.commit(1), "winner's, promoted") != 204 {
		t.Fatal("promote")
	}
	cleanupWraps(t, ts, kat, won.commit(1))
	if got := staged(); len(got) != 0 {
		t.Fatalf("after promotion and cleanup: %v", got)
	}
	// Older clients kept one staged wrap, in a slot named "recovery-next": it's moved to its own slot,
	// and kept by the same rules.
	old := newTestCode()
	legacy, _ := wire.Marshal(map[string]any{"via": "recovery-next", "ct": []byte("old staged"), "commit": old.commit(1)})
	if err := st.Account().SetKey(ctx, kat.id, "recovery-next", legacy); err != nil {
		t.Fatal(err)
	}
	cleanupWraps(t, ts, kat, nil)
	if got := staged(); got["old staged"] == "" || len(got) != 1 {
		t.Fatalf("the old staged wrap after a commitless remove: %v", got)
	}
	if hasSlot(t, st, kat.id, "recovery-next") || !hasSlot(t, st, kat.id, stagedSlot(old.commit(1))) {
		t.Fatal("the old staged wrap wasn't moved to its own slot")
	}
}
