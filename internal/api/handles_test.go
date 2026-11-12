package api

import (
	"context"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// An operator can release a handle (rerouted release-handle): a new identity registers it,
// and it resolves to the new identity, while the old one keeps its chain and session.
func TestReleaseHandle(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	old := newUser(t, ts, "nc")
	if id, err := st.Chains().ReleaseHandle(context.Background(), "nc.chat.test"); err != nil || id != old.id {
		t.Fatalf("release: %q, %v", id, err)
	}
	if _, err := st.Chains().ReleaseHandle(context.Background(), "nc.chat.test"); err != store.ErrNotFound {
		t.Fatalf("releasing it again: %v, want not found", err)
	}
	fresh := newUser(t, ts, "nc") // registering the name again works
	var got struct {
		ID string `json:"id"`
	}
	if c := call(t, ts, "GET", "resolve/nc.chat.test", fresh.token, nil, &got); c != 200 || got.ID != fresh.id || fresh.id == old.id {
		t.Fatalf("resolve after release: %d %q (old %q, new %q)", c, got.ID, old.id, fresh.id)
	}
	if c := call(t, ts, "GET", "chain/"+old.id, old.token, nil, nil); c != 200 {
		t.Fatalf("the old identity's chain: %d", c)
	}
}

// A handle registered here stops resolving once the identity's chain names another one
// (SPEC §5.3), signed in or not; the new handle is the domain's job to publish.
func TestResolveFollowsTheChain(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	seq, prev := head(t, ts, kat.id)
	entry := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-handle", "handle": "kat.example"}},
	}, kat.dev)
	if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, nil); c != 200 {
		t.Fatalf("set-handle: %d", c)
	}
	for _, token := range []string{kat.token, ""} {
		if c := call(t, ts, "GET", "resolve/kat.chat.test", token, nil, nil); c != 404 {
			t.Fatalf("the old handle still resolves (token %t): %d", token != "", c)
		}
	}
}
