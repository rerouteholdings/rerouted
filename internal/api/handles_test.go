package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
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

// setHandle appends a set-handle signed by u's device, and returns the status and error.
// handle is a string, or nil to clear it.
func (u *testUser) setHandle(handle any) (int, wire.Error) {
	u.t.Helper()
	seq, prev := head(u.t, u.ts, u.id)
	entry := signed(u.t, "chain-entry", map[string]any{"id": u.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-handle", "handle": handle}}}, u.dev)
	var e wire.Error
	c := call(u.t, u.ts, "POST", "chain/append", u.token, map[string]any{"entry": entry}, &e)
	return c, e
}

// resolvesTo reports what `handle` resolves to on ts's API at base (version 1's if it's
// ""), or "".
func resolvesTo(t *testing.T, ts *httptest.Server, base, token, handle string) string {
	t.Helper()
	var res struct {
		ID string `json:"id"`
	}
	var c int
	if base == v2Client {
		c = call2(t, ts, "GET", "resolve/"+handle, token, nil, &res)
	} else {
		c = call(t, ts, "GET", "resolve/"+handle, token, nil, &res)
	}
	if c != 200 {
		return ""
	}
	return res.ID
}

// registerV1 registers a version 1 identity named `handle` on ts, and returns the status.
func registerV1(t *testing.T, ts *httptest.Server, handle string) int {
	t.Helper()
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub)
	g := signed(t, "chain-entry", map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey))},
		map[string]any{"op": "set-home", "home": "chat.test"},
		map[string]any{"op": "set-handle", "handle": handle},
		map[string]any{"op": "set-recovery", "next": commit[:]},
	}}, dev)
	return call(t, ts, "POST", "register", "", map[string]any{"genesis": g, "invite": testRegCode}, nil)
}

// SPEC §5.3: changing your handle. The new name here has to be free; the old one is held
// for 30 days, resolving as no longer valid, and only its identity can take it back; then
// it's freed, unless the operator keeps it.
func TestHandleChange(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	ctx := context.Background()
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")

	if c, e := kat.setHandle("katherine.chat.test"); c != 200 {
		t.Fatalf("rename: %d %+v", c, e)
	}
	if got := resolvesTo(t, ts, "", bob.token, "katherine.chat.test"); got != kat.id {
		t.Fatalf("the new handle resolves to %q", got)
	}
	if got := resolvesTo(t, ts, "", bob.token, "kat.chat.test"); got != "" {
		t.Fatal("the old handle still resolves")
	}
	// Held for kat: nobody else registers it, or renames to it.
	if c := registerV1(t, ts, "kat.chat.test"); c != 409 {
		t.Fatalf("registering a held name: %d", c)
	}
	seq, _ := head(t, ts, bob.id)
	if c, e := bob.setHandle("kat.chat.test"); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("renaming to a held name: %d %+v", c, e)
	}
	if c, e := bob.setHandle("katherine.chat.test"); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("renaming to a name in use: %d %+v", c, e)
	}
	if after, _ := head(t, ts, bob.id); after != seq {
		t.Fatal("a refused rename was stored")
	}
	if c, e := bob.setHandle("admin.chat.test"); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("a reserved name: %d %+v", c, e)
	}
	if c, e := bob.setHandle("b.o.chat.test"); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("two labels under the handle domain: %d %+v", c, e)
	}
	// A name on another domain is the user's to publish.
	if c, e := bob.setHandle("bob.example.org"); c != 200 {
		t.Fatalf("a handle on another domain: %d %+v", c, e)
	}
	if c := registerV1(t, ts, "bob.chat.test"); c != 409 {
		t.Fatalf("bob's old name, held after he left it for his own domain: %d", c)
	}

	// Kat takes her old name back; the one she leaves is held now.
	if c, e := kat.setHandle("kat.chat.test"); c != 200 {
		t.Fatalf("taking a held name back: %d %+v", c, e)
	}
	if got := resolvesTo(t, ts, "", bob.token, "kat.chat.test"); got != kat.id {
		t.Fatalf("the name taken back resolves to %q", got)
	}
	if c := registerV1(t, ts, "katherine.chat.test"); c != 409 {
		t.Fatalf("registering the name she just left: %d", c)
	}
	// 30 days later, it's freed.
	if n, err := st.Chains().PruneHandles(ctx, time.Now().Unix()+store.HandleHold-60); err != nil || n != 0 {
		t.Fatalf("freed before the hold ended: %d %v", n, err)
	}
	if n, err := st.Chains().PruneHandles(ctx, time.Now().Unix()+store.HandleHold+60); err != nil || n != 2 {
		t.Fatalf("freeing after the hold: %d %v", n, err)
	}
	if c, e := bob.setHandle("katherine.chat.test"); c != 200 {
		t.Fatalf("renaming to a freed name: %d %+v", c, e)
	}
	if got := resolvesTo(t, ts, "", kat.token, "katherine.chat.test"); got != bob.id {
		t.Fatalf("the freed name resolves to %q", got)
	}

	// The operator keeps a name instead: it isn't freed when the hold ends.
	if c, _ := kat.setHandle("kitty.chat.test"); c != 200 {
		t.Fatal("rename")
	}
	if id, err := st.Chains().KeepHandle(ctx, "kat.chat.test"); err != nil || id != kat.id {
		t.Fatalf("keep: %q %v", id, err)
	}
	st.Chains().PruneHandles(ctx, time.Now().Unix()+store.HandleHold+60)
	if c := registerV1(t, ts, "kat.chat.test"); c != 409 {
		t.Fatalf("registering a name the operator keeps: %d", c)
	}
	if _, err := st.Chains().ReleaseHandle(ctx, "kat.chat.test"); err != nil {
		t.Fatal(err)
	}
	if c := registerV1(t, ts, "kat.chat.test"); c != 200 {
		t.Fatalf("registering a released name: %d", c)
	}

	// Clearing the handle holds the name too.
	if c, e := kat.setHandle(nil); c != 200 {
		t.Fatalf("clearing the handle: %d %+v", c, e)
	}
	if c := registerV1(t, ts, "kitty.chat.test"); c != 409 {
		t.Fatalf("registering a name its identity cleared: %d", c)
	}
}

// A recovery-signed entry is never refused over a name (SPEC §5.3, §6.4.1): one that asks
// for a name another identity holds is stored without it.
func TestHandleRecoveryNeverRefused(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	seq, prev := head(t, ts, kat.id)
	next, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(next)
	entry := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "set-handle", "handle": "bob.chat.test"},
		map[string]any{"op": "set-recovery", "next": commit[:]},
	}}, kat.rec)
	if c := call(t, ts, "POST", "recover", "", map[string]any{"entry": entry}, nil); c != 200 {
		t.Fatalf("recover with a taken name: %d", c)
	}
	if got := resolvesTo(t, ts, "", kat.token, "bob.chat.test"); got != bob.id {
		t.Fatalf("bob's name resolves to %q", got)
	}
	// Her old name is held for her, and she can take it back.
	if c := registerV1(t, ts, "kat.chat.test"); c != 409 {
		t.Fatalf("her old name: %d", c)
	}
	if c, e := kat.setHandle("kat.chat.test"); c != 200 {
		t.Fatalf("back to her old name: %d %+v", c, e)
	}
}

// Wire version 2 (SPEC §5.3): the same rules, in the one namespace of handles both
// versions share.
func TestV2HandleChange(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat, ravi := newV2User(t, ts, "kat", "chat.test"), newV2User(t, ts, "ravi", "chat.test")
	set := func(u *v2User, handle string) (int, wire.Error) {
		return u.appendSigned(signed2(t, "chain-entry", u.entry(map[string]any{"op": "set-handle", "handle": handle}), u.dev))
	}
	if c, e := set(kat, "katherine.chat.test"); c != 200 {
		t.Fatalf("rename: %d %+v", c, e)
	}
	if got := resolvesTo(t, ts, v2Client, ravi.token, "katherine.chat.test"); got != kat.id {
		t.Fatalf("the new handle resolves to %q", got)
	}
	if got := resolvesTo(t, ts, v2Client, ravi.token, "kat.chat.test"); got != "" {
		t.Fatal("the old handle still resolves")
	}
	if c, e := set(ravi, "kat.chat.test"); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("a held name: %d %+v", c, e)
	}
	if c := registerV1(t, ts, "kat.chat.test"); c != 409 {
		t.Fatalf("a version 1 registration of a version 2 identity's held name: %d", c)
	}
	st.Chains().PruneHandles(context.Background(), time.Now().Unix()+store.HandleHold+60)
	if c, e := set(ravi, "kat.chat.test"); c != 200 {
		t.Fatalf("a freed name: %d %+v", c, e)
	}
}

// A move away holds the name at the old home for 30 days (SPEC §5.3, §6.6).
func TestV2MoveHoldsName(t *testing.T) {
	a, b, sa, _ := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	call2(t, a, "GET", "chain/"+kat.id, "", nil, &ch)
	entry := signed2(t, "chain-entry", kat.entry(map[string]any{"op": "set-home", "home": "b.test"}, map[string]any{"op": "set-handle", "handle": "kat.b.test"}), kat.dev)
	head := sha256.Sum256(entry)
	move := signed2(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	var check struct {
		Reservation wire.Raw `json:"reservation"`
	}
	if c := call2(t, b, "POST", "register", "", map[string]any{"chain": append(ch.Entries, entry), "move": move, "invite": testRegCode, "check": true}, &check); c != 200 {
		t.Fatalf("check: %d", c)
	}
	if c, e := kat.appendSigned(entry); c != 403 {
		t.Fatalf("without the reservation: %d %+v", c, e)
	}
	if c := call2(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry, "reservation": check.Reservation}, nil); c != 200 {
		t.Fatalf("append the move: %d", c)
	}
	// kat.a.test is held at a.test: nobody registers it there.
	other := newComposite(t)
	g := signed2(t, "chain-entry", map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		addDevice(other, ""), map[string]any{"op": "set-home", "home": "a.test"},
		map[string]any{"op": "set-handle", "handle": "kat.a.test"},
		map[string]any{"op": "set-recovery", "next": newComposite(t).Public().Hash()},
	}}, other)
	var e wire.Error
	if c := call2(t, a, "POST", "register", "", map[string]any{"genesis": g, "invite": testRegCode}, &e); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("registering the name of someone who moved away: %d %+v", c, e)
	}
	sa.st.Chains().PruneHandles(context.Background(), time.Now().Unix()+store.HandleHold+60)
	if c := call2(t, a, "POST", "register", "", map[string]any{"genesis": g, "invite": testRegCode}, &e); c != 200 {
		t.Fatalf("after the hold: %d %+v", c, e)
	}
}
