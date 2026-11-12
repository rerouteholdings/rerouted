package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// chainOf returns u's chain entries as the server stores them.
func (u *testUser) chainOf(ts *httptest.Server) []wire.Raw {
	u.t.Helper()
	var res struct {
		Entries []wire.Raw `json:"entries"`
	}
	if c := call(u.t, ts, "GET", "chain/"+u.id, "", nil, &res); c != 200 {
		u.t.Fatalf("chain: %d", c)
	}
	return res.Entries
}

// moveEntry signs the entry that moves u to `home` with handle `handle` (SPEC §6.6).
func (u *testUser) moveEntry(entries []wire.Raw, home, handle string) wire.Raw {
	head := sha256.Sum256(entries[len(entries)-1])
	return signed(u.t, "chain-entry", map[string]any{
		"id": u.id, "seq": len(entries), "prev": head[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-home", "home": home}, map[string]any{"op": "set-handle", "handle": handle}},
	}, u.dev)
}

// signIn gets u a session on ts.
func (u *testUser) signIn(ts *httptest.Server, server string) int {
	u.t.Helper()
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	pub := []byte(u.dev.Public().(ed25519.PublicKey))
	if c := call(u.t, ts, "POST", "auth/challenge", "", map[string]any{"id": u.id, "key": pub}, &ch); c != 200 {
		return c
	}
	auth := signed(u.t, "auth", map[string]any{"id": u.id, "nonce": ch.Nonce, "server": server, "ts": time.Now().Unix()}, u.dev)
	var sess struct {
		Token string `json:"token"`
	}
	c := call(u.t, ts, "POST", "auth/session", "", map[string]any{"auth": auth}, &sess)
	if c == 200 {
		u.ts, u.token = ts, sess.Token
	}
	return c
}

// SPEC §6.6, §8.2: moving to another homeserver. The old home appends the move and ends
// every session; the new one takes the whole chain, with the contact and group allowlists.
func TestMoveHomeserver(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")
	group := randBytes(32)

	// A move the old home never appended isn't taken.
	entries := kat.chainOf(a)
	forged := kat.moveEntry(entries, "b.test", "kat.b.test")
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": append(entries, forged), "invite": testRegCode}, nil); c != 400 {
		t.Fatalf("a move a.test didn't append: %d, want 400", c)
	}

	move := kat.moveEntry(entries, "b.test", "kat.b.test")
	if c := kat.leave(a, b, move, "b.test"); c != 200 {
		t.Fatalf("append the move: %d", c)
	}
	// The old home's session still works, for the move's alarm: if a thief made the move,
	// the owner has to see it and recover (SPEC §6.4.1).
	var inbox struct {
		Items []inboxItem `json:"items"`
	}
	if c := call(t, a, "GET", "inbox", kat.token, nil, &inbox); c != 200 || len(inbox.Items) == 0 {
		t.Fatalf("the move's alarm at the old home: %d, %d items", c, len(inbox.Items))
	}
	// a.test keeps the chain as a tombstone, and serves it.
	if got := kat.chainOf(a); len(got) != 2 {
		t.Fatalf("tombstone: %d entries", len(got))
	}

	chain := kat.chainOf(a)
	head := sha256.Sum256(chain[len(chain)-1])
	moveAs := func(key ed25519.PrivateKey, server string, contacts []string) wire.Raw {
		return signed(t, "move", map[string]any{"id": kat.id, "server": server, "head": head[:], "ts": time.Now().Unix(), "contacts": contacts, "groups": []wire.Bytes{group}}, key)
	}
	register := func(mv wire.Raw) int {
		req := map[string]any{"chain": chain, "invite": testRegCode}
		if mv != nil {
			req["move"] = mv
		}
		return call(t, b, "POST", "register", "", req, nil)
	}
	// The chain is public: whoever has seen it can't register it here with allowlists of
	// their choosing. Only a move signed by one of kat's current devices counts.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if c := register(nil); c != 400 {
		t.Fatalf("a move with no signed move: %d, want 400", c)
	}
	if c := register(moveAs(stranger, "b.test", []string{bob.id})); c != 400 {
		t.Fatalf("a move signed by someone else: %d, want 400", c)
	}
	if c := register(moveAs(kat.dev, "c.test", []string{bob.id})); c != 400 {
		t.Fatalf("a signed move naming another server: %d, want 400", c)
	}
	if c := register(moveAs(kat.dev, "b.test", []string{bob.id})); c != 200 {
		t.Fatalf("register the move at b.test: %d", c)
	}
	// The same move again, its reply lost, still works.
	if c := register(moveAs(kat.dev, "b.test", []string{bob.id})); c != 200 {
		t.Fatalf("an exact retry of the move: %d", c)
	}
	if c := kat.signIn(b, "b.test"); c != 200 {
		t.Fatalf("sign in at the new home: %d", c)
	}
	var cs struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"items"`
	}
	if c := call(t, b, "GET", "contacts", kat.token, nil, &cs); c != 200 || len(cs.Items) != 1 || cs.Items[0].ID != bob.id || cs.Items[0].State != "contact" {
		t.Fatalf("contacts came along: %d %+v", c, cs)
	}
	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call(t, b, "GET", "resolve/kat.b.test", "", nil, &res); c != 200 || res.ID != kat.id {
		t.Fatalf("new handle: %d %+v", c, res)
	}
	// The group allowlist came along: a group message from bob reaches her.
	msg := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 3, "mls": "app", "data": []byte("after the move")}
	call(t, b, "POST", "send", bob.token, map[string]any{"deliveries": []any{msg}}, nil)
	kat.waitFor(bob.id, "after the move")
}

// SPEC §6.6: a client asks the new server whether it would take a move ("check") before
// giving the old home the move entry. A refusal then changes nothing anywhere, where a
// refusal after the append would leave a chain naming a home with no account.
func TestMoveCheck(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	newUserOn(t, b, "taken", "b.test")

	entries := kat.chainOf(a)
	check := func(handle string, withMove bool, invite string) int {
		entry := kat.moveEntry(entries, "b.test", handle)
		head := sha256.Sum256(entry)
		req := map[string]any{"chain": append(append([]wire.Raw(nil), entries...), entry), "invite": invite, "check": true}
		if withMove {
			req["move"] = signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
		}
		return call(t, b, "POST", "register", "", req, nil)
	}
	if c := check("kat.b.test", false, testRegCode); c != 400 {
		t.Fatalf("check without a signed move: %d, want 400", c)
	}
	if c := check("kat.b.test", true, "wrong"); c != 403 {
		t.Fatalf("check with a bad invite: %d, want 403", c)
	}
	if c := check("taken.b.test", true, testRegCode); c != 409 {
		t.Fatalf("check for a taken handle: %d, want 409", c)
	}
	if c := check("kat.b.test", true, testRegCode); c != 200 {
		t.Fatalf("check a good move: %d, want 200", c)
	}
	// A check registers nothing.
	if c := kat.signIn(b, "b.test"); c == 200 {
		t.Fatal("signed in at b.test after only a check")
	}
	if c := call(t, b, "GET", "resolve/kat.b.test", "", nil, nil); c == 200 {
		t.Fatal("the handle resolves after only a check")
	}
	// "check" is for moves only.
	if c := call(t, b, "POST", "register", "", map[string]any{"genesis": entries[0], "invite": testRegCode, "check": true}, nil); c != 400 {
		t.Fatalf("check with a genesis: %d, want 400", c)
	}
}

// SPEC §6.6: a registration that comes after the move entry's 10 minutes, because the reply
// was lost or the app closed in between, still works: the old home checked the entry's clock
// when it appended it. Only the signed move has to be recent.
func TestLateMoveRegistration(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserDated(t, a, "kat", "a.test", time.Now().Unix()-599)
	entries := kat.chainOf(a)
	prev := sha256.Sum256(entries[len(entries)-1])
	// Dated as early as the old home allows, then registered after that has run out.
	entry := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": len(entries), "prev": prev[:], "ts": time.Now().Unix() - 598,
		"ops": []any{map[string]any{"op": "set-home", "home": "b.test"}, map[string]any{"op": "set-handle", "handle": "kat.b.test"}},
	}, kat.dev)
	if c := kat.leave(a, b, entry, "b.test"); c != 200 {
		t.Fatalf("append the move: %d", c)
	}
	// A recovery-signed move is first accepted by the new server, so it still has to be
	// recent when it gets there.
	ron := newUserDated(t, a, "ron", "a.test", time.Now().Unix()-599)
	rentries := ron.chainOf(a)
	rprev := sha256.Sum256(rentries[len(rentries)-1])
	nextRec, _, _ := ed25519.GenerateKey(rand.Reader)
	nextCommit := sha256.Sum256(nextRec)
	rmove := signed(t, "chain-entry", map[string]any{
		"id": ron.id, "seq": len(rentries), "prev": rprev[:], "ts": time.Now().Unix() - 598,
		"ops": []any{
			map[string]any{"op": "set-home", "home": "b.test"},
			map[string]any{"op": "set-handle", "handle": "ron.b.test"},
			map[string]any{"op": "set-recovery", "next": nextCommit[:]},
		},
	}, ron.rec)
	time.Sleep(3 * time.Second)
	chain := kat.chainOf(a)
	head := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode}, nil); c != 200 {
		t.Fatalf("a late registration of an appended move: %d, want 200", c)
	}
	if c := kat.signIn(b, "b.test"); c != 200 {
		t.Fatalf("sign in at the new home: %d", c)
	}

	rhead := sha256.Sum256(rmove)
	rmv := signed(t, "move", map[string]any{"id": ron.id, "server": "b.test", "head": rhead[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, ron.dev)
	var e wire.Error
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": append(rentries, rmove), "move": rmv, "invite": testRegCode}, &e); c != 400 || e.Code != wire.ErrCodeClockSkew {
		t.Fatalf("an old recovery-signed move: %d %q, want 400 clock-skew", c, e.Code)
	}
}

// SPEC §7.2: a link bundle is a delivery to the sender's own identity, and only that.
func TestLinkDeliveries(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	var res struct {
		Results []sendResult `json:"results"`
	}
	bundle := map[string]any{"id": randBytes(16), "kind": "link", "to": []string{kat.id}, "data": []byte("hpke-sealed")}
	call(t, ts, "POST", "send", kat.token, map[string]any{"deliveries": []any{bundle}}, &res)
	if res.Results[0].Status != "sent" {
		t.Fatalf("link to self: %+v", res.Results[0])
	}
	items := kat.inbox()
	if len(items) != 1 || items[0].Delivery.Kind != "link" || string(items[0].Delivery.Data) != "hpke-sealed" {
		t.Fatalf("kat's inbox: %+v", items)
	}
	bundle = map[string]any{"id": randBytes(16), "kind": "link", "to": []string{bob.id}, "data": []byte("x")}
	call(t, ts, "POST", "send", kat.token, map[string]any{"deliveries": []any{bundle}}, &res)
	if res.Results[0].Status == "sent" {
		t.Fatal("a link bundle to someone else was sent")
	}
	if items := bob.inbox(); len(items) != 0 {
		t.Fatalf("bob got %d items", len(items))
	}
}

// SPEC §7.2: a new device parks its one-time HPKE key with a proof that has no code; that
// doesn't use up one of the five code attempts.
func TestParkHPKEKey(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	newPub, newDev, _ := ed25519.GenerateKey(nil)
	hpke := randBytes(hpkeKeySize)
	post := func(body map[string]any) int {
		return call(t, ts, "POST", "link/proof", "", map[string]any{"proof": signed(t, "link-proof", body, newDev)}, nil)
	}
	for i := 0; i < 7; i++ {
		if c := post(map[string]any{"id": kat.id, "hpke": hpke, "ts": time.Now().Unix()}); c != 202 {
			t.Fatalf("park %d: %d", i, c)
		}
	}
	if c := post(map[string]any{"id": kat.id, "hpke": randBytes(100), "ts": time.Now().Unix()}); c != 400 {
		t.Fatalf("a key of the wrong size: %d", c)
	}
	var got struct {
		Proof wire.Raw `json:"proof"`
	}
	path := "link/proof/" + wire.B64(newPub)
	if c := call(t, ts, "GET", path, kat.token, nil, &got); c != 200 {
		t.Fatalf("fetch the parked key: %d", c)
	}
	// A code proof replaces it, and a later park doesn't overwrite the code.
	if c := post(map[string]any{"id": kat.id, "hpke": hpke, "code": "ABCD1234", "ts": time.Now().Unix()}); c != 202 {
		t.Fatalf("code proof: %d", c)
	}
	post(map[string]any{"id": kat.id, "hpke": hpke, "ts": time.Now().Unix()})
	call(t, ts, "GET", path, kat.token, nil, &got)
	s, _ := wire.DecodeSigned(got.Proof)
	var body struct {
		Code string `json:"code"`
	}
	if s.Open(&body) != nil || body.Code != "ABCD1234" {
		t.Fatalf("the code proof was overwritten: %+v", body)
	}
}

// REROUTED_PAUSE_MOVES: with moves paused, a device-signed move is refused at both ends
// before anything is stored, so the identity stays where it is, and routing doesn't change.
// A recovery-signed entry still goes through.
func TestPausedMoves(t *testing.T) {
	a, b, sa, sb := twoServers(t)
	sa.cfg.PauseMoves, sb.cfg.PauseMoves = true, true
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)

	// The new home, asked first or registered directly: refused, nothing registered.
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	head := sha256.Sum256(entry)
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	for _, check := range []bool{true, false} {
		var e wire.Error
		req := map[string]any{"chain": append(append([]wire.Raw(nil), entries...), entry), "move": mv, "invite": testRegCode, "check": check}
		if c := call(t, b, "POST", "register", "", req, &e); c != 403 || e.Code != wire.ErrCodeNotAllowed || !strings.Contains(e.Msg, "paused") {
			t.Fatalf("register (check %v) while paused: %d %+v", check, c, e)
		}
	}
	if c := kat.signIn(b, "b.test"); c == 200 {
		t.Fatal("b.test took kat while moves are paused")
	}

	// The old home (where a client that never asks starts): refused, and the chain is unchanged.
	var e wire.Error
	if c := call(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, &e); c != 403 || e.Code != wire.ErrCodeNotAllowed {
		t.Fatalf("append a move while paused: %d %+v", c, e)
	}
	if got := kat.chainOf(a); len(got) != len(entries) {
		t.Fatalf("the chain changed: %d entries, had %d", len(got), len(entries))
	}
	if c := call(t, a, "GET", "inbox", kat.token, nil, nil); c != 200 {
		t.Fatalf("kat's session at her home after the refusal: %d", c)
	}

	// A recovery-signed entry (the recovery code's re-commit) still goes through.
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	next := sha256.Sum256(nextPub)
	prev := sha256.Sum256(entries[len(entries)-1])
	rec := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": len(entries), "prev": prev[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-recovery", "next": next[:]}}}, kat.rec)
	if c := call(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": rec}, nil); c != 200 {
		t.Fatalf("a recovery-signed entry while moves are paused: %d", c)
	}
	// And device changes are unaffected.
	_, newDev, _ := ed25519.GenerateKey(rand.Reader)
	entries = kat.chainOf(a)
	prev = sha256.Sum256(entries[len(entries)-1])
	add := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": len(entries), "prev": prev[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "add-device", "key": []byte(newDev.Public().(ed25519.PublicKey)), "name": "tablet"}}}, kat.dev)
	if c := call(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": add}, nil); c != 200 {
		t.Fatalf("adding a device while moves are paused: %d", c)
	}
}

// SPEC §6.6: retrying a registration is idempotent. Once the move has been registered, the
// same request again, even with a signed move that's still recent, changes nothing: it can't
// put back a contact or group the user has removed since.
func TestMoveReplayDoesntRestoreAllowlists(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")
	group := randBytes(32)
	entries := kat.chainOf(a)
	move := kat.moveEntry(entries, "b.test", "kat.b.test")
	if c := kat.leave(a, b, move, "b.test"); c != 200 {
		t.Fatalf("append the move: %d", c)
	}
	chain := kat.chainOf(a)
	head := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{bob.id}, "groups": []wire.Bytes{group}}, kat.dev)
	req := map[string]any{"chain": chain, "move": mv, "invite": testRegCode}
	if c := call(t, b, "POST", "register", "", req, nil); c != 200 {
		t.Fatalf("register: %d", c)
	}
	if c := kat.signIn(b, "b.test"); c != 200 {
		t.Fatalf("sign in at b.test: %d", c)
	}
	// Kat removes Bob and leaves the group at her new home.
	if c := call(t, b, "POST", "contacts/remove", kat.token, map[string]any{"id": bob.id}, nil); c != 204 {
		t.Fatalf("remove bob: %d", c)
	}
	if c := call(t, b, "POST", "groups/unregister", kat.token, map[string]any{"group": group}, nil); c != 204 {
		t.Fatalf("unregister the group: %d", c)
	}
	// The same registration again, as a retry or a replay.
	if c := call(t, b, "POST", "register", "", req, nil); c != 200 {
		t.Fatalf("the registration again: %d, want 200 (already done)", c)
	}
	ctx := context.Background()
	if c, err := sb.st.Contacts().Get(ctx, kat.id, bob.id); err == nil {
		t.Fatalf("the replay put Bob back on Kat's contacts (%s)", c.State)
	}
	if ok, _ := sb.st.Contacts().GroupAllowed(ctx, kat.id, group); ok {
		t.Fatal("the replay put the group back on Kat's allowlist")
	}
}

// A legacy partial arrival cannot be distinguished from an unrelated prefix.
func TestMoveRegistrationRejectsPartial(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	bob := newUserOn(t, b, "bob", "b.test")
	entries := kat.chainOf(a)
	move := kat.moveEntry(entries, "b.test", "kat.b.test")
	if c := kat.leave(a, b, move, "b.test"); c != 200 {
		t.Fatalf("append the move: %d", c)
	}
	chain := kat.chainOf(a)
	// Simulate a partial arrival from the old non-atomic implementation.
	ctx := context.Background()
	if err := sb.st.Chains().Create(ctx, kat.id, chain[0], "kat.b.test"); err != nil {
		t.Fatal(err)
	}
	head := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{bob.id}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode}, nil); c != 409 {
		t.Fatalf("partial registration: %d, want 409", c)
	}
	if got, _ := sb.st.Chains().Entries(ctx, kat.id, -1); len(got) != 1 {
		t.Fatal("partial chain changed")
	}
}
