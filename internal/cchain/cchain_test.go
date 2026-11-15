package cchain

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

const testNow = int64(1_800_000_000)
const testServer = "community.example.com"

type ident struct {
	id   string
	key  *wire.CompositePrivateKey
	home string
}

func newIdent(t testing.TB, home string) *ident {
	t.Helper()
	key, err := wire.GenerateCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	rand.Read(b)
	return &ident{id: wire.IdentityID(b), key: key, home: home}
}

type harness struct {
	t    testing.TB
	st   *State
	ids  map[string]*ident
	raws [][]byte
	now  int64
}

func (h *harness) keys(by string, k []byte) (Signer, error) {
	i := h.ids[by]
	if i == nil || !bytes.Equal(i.key.Public().Ed25519(), k) {
		return Signer{}, ErrNotDevice
	}
	return Signer{Pub: i.key.Public(), Home: i.home}, nil
}

func (h *harness) add(i *ident) *ident { h.ids[i.id] = i; return i }

func signEntry(t testing.TB, by *ident, body map[string]any) []byte {
	t.Helper()
	sig, err := wire.SignComposite(TypeEntry, body, by.key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (h *harness) body(by *ident, ops ...map[string]any) map[string]any {
	return map[string]any{"community": h.st.ID, "seq": h.st.Seq + 1, "prev": h.st.Head, "ts": h.now, "by": by.id, "ops": ops}
}

func (h *harness) entry(by *ident, ops ...map[string]any) []byte {
	return signEntry(h.t, by, h.body(by, ops...))
}

// ok appends ops signed by `by`, and fails the test if they're refused.
func (h *harness) ok(by *ident, ops ...map[string]any) *Applied {
	h.t.Helper()
	raw := h.entry(by, ops...)
	st, a, err := h.st.Apply(raw, h.keys, h.now, Append)
	if err != nil {
		h.t.Fatalf("refused: %v", err)
	}
	h.st = st
	h.raws = append(h.raws, raw)
	return a
}

// fail expects the entry refused with code.
func (h *harness) fail(code string, by *ident, ops ...map[string]any) {
	h.t.Helper()
	h.failRaw(code, h.entry(by, ops...))
}

func (h *harness) failRaw(code string, raw []byte) {
	h.t.Helper()
	before := h.st.Clone()
	_, _, err := h.st.Apply(raw, h.keys, h.now, Append)
	var e *Error
	if !errors.As(err, &e) {
		h.t.Fatalf("want %s, got %v", code, err)
	}
	if e.Code != code {
		h.t.Fatalf("want %s, got %v", code, e)
	}
	if !sameState(before, h.st) {
		h.t.Fatal("Apply changed the state it was given")
	}
}

func sameState(a, b *State) bool {
	ea, _ := wire.Marshal(a)
	eb, _ := wire.Marshal(b)
	return bytes.Equal(ea, eb)
}

func sealedVal() map[string]any {
	k := make([]byte, 32)
	rand.Read(k)
	ct := make([]byte, 40)
	rand.Read(ct)
	return map[string]any{"key": k, "ct": ct}
}

func createOp(public bool) map[string]any {
	return map[string]any{"op": "create", "server": testServer, "name": "Night shift", "desc": "A place", "public": public, "approval": false, "everyone": []string{"talk"}}
}

// newCommunity makes a community owned by a fresh identity on kat.example.org.
func newCommunity(t testing.TB) (*harness, *ident) {
	h := &harness{t: t, ids: map[string]*ident{}, now: testNow}
	owner := h.add(newIdent(t, "kat.example.org"))
	raw := signEntry(t, owner, map[string]any{"seq": 0, "ts": testNow, "by": owner.id, "ops": []map[string]any{createOp(true)}})
	st, a, err := Create(raw, testServer, h.keys, testNow, Append)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(a.Enc)
	if !bytes.Equal(st.ID, sum[:]) || !bytes.Equal(st.Head, st.ID) || st.Owner != owner.id || st.Server != testServer {
		t.Fatal("create state")
	}
	h.st, h.raws = st, [][]byte{raw}
	return h, owner
}

func addRole(id uint64, rank int, perms ...string) map[string]any {
	if perms == nil {
		perms = []string{}
	}
	return map[string]any{"op": "add-role", "id": id, "rank": rank, "perms": perms, "name": sealedVal()}
}

func assign(member *ident, roles ...uint64) map[string]any {
	if roles == nil {
		roles = []uint64{}
	}
	return map[string]any{"op": "assign-roles", "member": member.id, "roles": roles}
}

func textChannel(id uint64, see, write []uint64) map[string]any {
	return map[string]any{"op": "add-channel", "id": id, "name": sealedVal(), "see": see, "write": write, "kind": "text", "history": true, "slow": 0}
}

func voiceChannel(id uint64, max, cast int) map[string]any {
	return map[string]any{"op": "add-channel", "id": id, "name": sealedVal(), "see": []uint64{0}, "write": []uint64{0}, "kind": "voice", "max": max, "cast": cast}
}

// staffed sets up roles: 1 admin (rank 100, administrate+moderate+invite+talk), 2 mod
// (rank 50, moderate+talk), 3 member (rank 10, talk+invite), with one identity holding each.
func staffed(t testing.TB) (h *harness, owner, admin, mod, member *ident) {
	h, owner = newCommunity(t)
	admin = h.add(newIdent(t, "a.example.org"))
	mod = h.add(newIdent(t, "b.example.org"))
	member = h.add(newIdent(t, "c.example.org"))
	h.ok(owner,
		addRole(1, 100, "talk", "invite", "moderate", "administrate"),
		addRole(2, 50, "talk", "moderate"),
		addRole(3, 10, "talk", "invite"),
		assign(admin, 1), assign(mod, 2), assign(member, 3))
	return
}

func newCode(t testing.TB) []byte {
	k, err := wire.GenerateCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.Public().Bytes()
}

func TestCreate(t *testing.T) {
	h, owner := newCommunity(t)
	if h.st.Name != "Night shift" || h.st.Desc != "A place" || !h.st.Public || h.st.Everyone != Talk {
		t.Fatalf("state: %+v", h.st)
	}
	mk := func(body map[string]any) []byte { return signEntry(t, owner, body) }
	base := func() map[string]any {
		return map[string]any{"seq": 0, "ts": testNow, "by": owner.id, "ops": []map[string]any{createOp(false)}}
	}
	expect := func(code string, raw []byte, server string, mode Mode) {
		t.Helper()
		_, _, err := Create(raw, server, h.keys, testNow, mode)
		var e *Error
		if !errors.As(err, &e) || e.Code != code {
			t.Fatalf("want %s, got %v", code, err)
		}
	}
	expect(wire.ErrCodeInvalidChain, mk(base()), "other.example.com", Append)
	if _, _, err := Create(mk(base()), "other.example.com", nil, testNow, Replay); err != nil {
		t.Fatal("Replay doesn't check the server:", err)
	}
	b := base()
	b["seq"] = 1
	expect(wire.ErrCodeInvalidChain, mk(b), testServer, Append)
	b = base()
	b["prev"] = make([]byte, 32)
	expect(wire.ErrCodeInvalidChain, mk(b), testServer, Append)
	b = base()
	b["community"] = make([]byte, 32)
	expect(wire.ErrCodeInvalidChain, mk(b), testServer, Append)
	b = base()
	b["ops"] = []map[string]any{createOp(false), createOp(false)}
	expect(wire.ErrCodeInvalidChain, mk(b), testServer, Append)
	b = base()
	b["ops"] = []map[string]any{{"op": "set-settings", "public": true, "approval": true}}
	expect(wire.ErrCodeInvalidChain, mk(b), testServer, Append)
	for _, bad := range []map[string]any{
		{"everyone": []string{"talk", "moderate"}}, {"everyone": []string{"talk", "talk"}},
		{"name": ""}, {"name": " padded"}, {"name": strings.Repeat("x", 65)}, {"name": "fire 🔥"},
		{"name": "e\u0301"}, {"desc": "bad\u202etext"}, {"desc": strings.Repeat("d", 301)},
	} {
		b = base()
		op := createOp(false)
		for k, v := range bad {
			op[k] = v
		}
		b["ops"] = []map[string]any{op}
		expect(wire.ErrCodeInvalidChain, mk(b), testServer, Append)
	}
	b = base()
	op := createOp(false)
	op["everyone"] = []string{"fly"}
	b["ops"] = []map[string]any{op}
	expect(wire.ErrCodeUnknownKind, mk(b), testServer, Append)
	b = base()
	b["ts"] = testNow + 601
	expect(wire.ErrCodeClockSkew, mk(b), testServer, Append)
	stranger := newIdent(t, "x.example.org")
	expect(wire.ErrCodeNotAllowed, signEntry(t, stranger, map[string]any{"seq": 0, "ts": testNow, "by": stranger.id, "ops": []map[string]any{createOp(false)}}), testServer, Append)
}

func TestForm(t *testing.T) {
	h, owner := newCommunity(t)
	h.fail(wire.ErrCodeUnknownKind, owner, map[string]any{"op": "promote"})
	h.fail(wire.ErrCodeUnknownKind, owner, map[string]any{"op": "add-channel", "id": 1, "name": sealedVal(), "see": []uint64{0}, "write": []uint64{0}, "kind": "stage"})
	h.fail(wire.ErrCodeUnknownKind, owner, addRole(1, 5, "fly"))
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "extra": 1})
	h.fail(wire.ErrCodeBadRequest, owner, addRole(1, 0))
	h.fail(wire.ErrCodeBadRequest, owner, addRole(1, 1001))
	slow := textChannel(1, []uint64{0}, []uint64{0})
	slow["slow"] = 21601
	h.fail(wire.ErrCodeBadRequest, owner, slow)
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "add-code", "key": newCode(t), "public": false})
	long := addRole(1, 5)
	long["name"] = map[string]any{"key": make([]byte, 32), "ct": make([]byte, 509)}
	h.fail(wire.ErrCodeBadRequest, owner, long)
	extra := addRole(1, 5)
	extra["name"] = map[string]any{"key": make([]byte, 32), "ct": make([]byte, 40), "iv": "x"}
	h.fail(wire.ErrCodeBadRequest, owner, extra)
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "edit-role", "id": 0})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "ban", "member": owner.id, "domain": "x.example.org"})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "ban", "domain": "1.2.3.4"})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "ban", "member": "kat"})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "add-code", "key": make([]byte, 32), "exp": testNow + 10, "uses": 1})
	b := h.body(owner, map[string]any{"op": "set-name", "name": "x"})
	b["ops"] = []map[string]any{}
	h.failRaw(wire.ErrCodeBadRequest, signEntry(t, owner, b))
	b = h.body(owner, map[string]any{"op": "set-name", "name": "x"})
	b["note"] = "hi"
	h.failRaw(wire.ErrCodeBadRequest, signEntry(t, owner, b))
	// The envelope: another type, or a kid.
	sig, _ := wire.SignComposite("chain-entry", h.body(owner, map[string]any{"op": "set-name", "name": "x"}), owner.key)
	enc, _ := sig.Encode()
	h.failRaw(wire.ErrCodeBadRequest, enc)
	sig, _ = wire.SignCompositeFull(TypeEntry, h.body(owner, map[string]any{"op": "set-name", "name": "x"}), owner.key)
	enc, _ = sig.Encode()
	h.failRaw(wire.ErrCodeBadRequest, enc)
}

func TestPlaceSignatureTime(t *testing.T) {
	h, owner := newCommunity(t)
	set := map[string]any{"op": "set-name", "name": "Day shift"}
	stale := h.entry(owner, set)
	h.ok(owner, set)
	h.failRaw(wire.ErrCodeStaleHead, stale)
	b := h.body(owner, set)
	b["seq"] = h.st.Seq + 2
	h.failRaw(wire.ErrCodeInvalidChain, signEntry(t, owner, b))
	b = h.body(owner, set)
	b["community"] = make([]byte, 32)
	h.failRaw(wire.ErrCodeInvalidChain, signEntry(t, owner, b))
	b = h.body(owner, set)
	delete(b, "prev")
	h.failRaw(wire.ErrCodeInvalidChain, signEntry(t, owner, b))
	h.fail(wire.ErrCodeInvalidChain, owner, createOp(true))

	// k isn't a device of by, and a signature that fails.
	other := h.add(newIdent(t, "x.example.org"))
	b = h.body(owner, set)
	h.failRaw(wire.ErrCodeNotAllowed, signEntry(t, other, b)) // by is owner, k is other's
	sig, _ := wire.SignComposite(TypeEntry, h.body(owner, set), other.key)
	sig.K = wire.Bytes(owner.key.Public().Ed25519())
	enc, _ := sig.Encode()
	h.failRaw(wire.ErrCodeBadSignature, enc)
	boom := errors.New("chain unavailable")
	_, _, err := h.st.Apply(h.entry(owner, set), func(string, []byte) (Signer, error) { return Signer{}, boom }, h.now, Append)
	if !errors.Is(err, boom) {
		t.Fatalf("a lookup failure passes through: %v", err)
	}

	// Time.
	for _, ts := range []int64{h.now + 601, h.now - 601, h.st.TS - 1} {
		b = h.body(owner, set)
		b["ts"] = ts
		h.failRaw(wire.ErrCodeClockSkew, signEntry(t, owner, b))
	}
	b = h.body(owner, set)
	b["ts"] = h.now + 600
	if _, _, err := h.st.Apply(signEntry(t, owner, b), h.keys, h.now, Append); err != nil {
		t.Fatal(err)
	}
	past := h.body(owner, set)
	past["ts"] = h.now // fine in Import even if the server's clock is a year on
	if _, _, err := h.st.Apply(signEntry(t, owner, past), h.keys, h.now+365*86400, Import); err != nil {
		t.Fatal("Import has no past bound:", err)
	}
	future := h.body(owner, set)
	future["ts"] = h.now + 601
	if _, _, err := h.st.Apply(signEntry(t, owner, future), h.keys, h.now, Import); err == nil {
		t.Fatal("Import refuses the future")
	}
	if _, _, err := h.st.Apply(signEntry(t, owner, future), nil, h.now, Replay); err != nil {
		t.Fatal("Replay has no clock:", err)
	}
}

func TestAuthority(t *testing.T) {
	h, owner, admin, mod, member := staffed(t)
	h.fail(wire.ErrCodeNotAllowed, member, map[string]any{"op": "set-name", "name": "Mine"})
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "set-settings", "public": false, "approval": true})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "transfer-ownership", "to": admin.id})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "set-home", "server": "elsewhere.example.com"})
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "add-code", "key": newCode(t), "exp": testNow + 60, "uses": 1})
	h.fail(wire.ErrCodeNotAllowed, member, map[string]any{"op": "timeout", "member": admin.id, "until": testNow + 60})

	ops := make([]map[string]any, 257)
	for i := range ops {
		ops[i] = map[string]any{"op": "set-name", "name": "n"}
	}
	h.fail(wire.ErrCodeNotAllowed, owner, ops...)
	h.ok(owner, ops[:256]...)

	// A banned signer, and a domain-banned one; never the owner.
	h.ok(owner, map[string]any{"op": "ban", "domain": "example.org"})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "set-name", "name": "x"})
	owner.home = "kat.example.org"
	h.ok(owner, map[string]any{"op": "set-name", "name": "Still mine"})
	if !h.st.Banned(admin.id, "a.example.org") || !h.st.Banned(admin.id, "example.org") || h.st.Banned(admin.id, "notexample.org") || h.st.Banned(owner.id, "kat.example.org") {
		t.Fatal("Banned")
	}
	h.ok(owner, map[string]any{"op": "unban", "domain": "example.org"}, map[string]any{"op": "ban", "member": member.id})
	h.fail(wire.ErrCodeNotAllowed, member, assign(member))
}

func TestRoles(t *testing.T) {
	h, owner, admin, mod, member := staffed(t)
	h.fail(wire.ErrCodeNotAllowed, admin, addRole(4, 100, "talk"))  // not below the admin's 100
	h.fail(wire.ErrCodeNotAllowed, mod, addRole(4, 20, "talk"))     // no administrate
	h.ok(admin, addRole(4, 99, "talk"))                             // fine
	h.fail(wire.ErrCodeInvalidChain, admin, addRole(6, 20, "talk")) // skipped id
	h.fail(wire.ErrCodeInvalidChain, admin, addRole(5, 50, "talk")) // rank taken
	h.fail(wire.ErrCodeInvalidChain, admin, addRole(5, 20, "talk", "talk"))
	// A role can't be given a permission the signer lacks: a capped admin.
	h.ok(owner, addRole(5, 90, "administrate"), assign(mod, 2, 5))
	h.fail(wire.ErrCodeNotAllowed, mod, addRole(6, 20, "invite"))
	h.ok(mod, addRole(6, 20, "talk", "moderate"))

	// edit-role.
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "edit-role", "id": 1, "rank": 98})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "edit-role", "id": 3, "rank": 100})
	h.ok(admin, map[string]any{"op": "edit-role", "id": 1, "name": sealedVal(), "color": sealedVal()}) // name only: no rank
	h.ok(admin, map[string]any{"op": "edit-role", "id": 1, "color": nil})
	if h.st.Roles[1].HasColor {
		t.Fatal("null color removes it")
	}
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-role", "id": 3, "rank": 50})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-role", "id": 77, "name": sealedVal()})
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "edit-role", "id": 6, "perms": []string{"talk", "moderate", "invite"}})
	h.ok(admin, map[string]any{"op": "edit-role", "id": 3, "rank": 11, "perms": []string{"talk"}})
	// everyone.
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-role", "id": 0, "perms": []string{"talk", "moderate"}})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-role", "id": 0, "name": sealedVal()})
	h.ok(admin, map[string]any{"op": "edit-role", "id": 0, "perms": []string{"talk", "invite"}})
	if h.st.Everyone != Talk|Invite || !h.st.Has(member.id, Invite) {
		t.Fatal("everyone's perms")
	}
	h.fail(wire.ErrCodeInvalidChain, owner, map[string]any{"op": "remove-role", "id": 0})

	// remove-role: from members and channels, but never leaving a list empty.
	h.ok(owner, textChannel(1, []uint64{3}, []uint64{3}))
	h.fail(wire.ErrCodeInvalidChain, owner, map[string]any{"op": "remove-role", "id": 3})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "remove-role", "id": 1})
	h.ok(owner, map[string]any{"op": "edit-channel", "id": 1, "see": []uint64{0}, "write": []uint64{2, 3}, "name": sealedVal()},
		map[string]any{"op": "remove-role", "id": 3})
	if h.st.Roles[3] != nil || len(h.st.Assigned[member.id]) != 0 || len(h.st.Channels[1].Write) != 1 {
		t.Fatal("remove-role")
	}
	h.fail(wire.ErrCodeInvalidChain, owner, addRole(3, 10)) // role IDs are never reused

	// 20 roles at most.
	var ops []map[string]any
	next := h.st.LastRole + 1
	for len(h.st.Roles)+len(ops) < MaxRoles {
		ops = append(ops, addRole(next, 200+int(next)))
		next++
	}
	h.ok(owner, ops...)
	h.fail(wire.ErrCodeNotAllowed, owner, addRole(next, 999))
}

func TestAssignRoles(t *testing.T) {
	h, owner, admin, mod, member := staffed(t)
	other := h.add(newIdent(t, "d.example.org"))
	h.ok(admin, assign(other, 3))
	h.fail(wire.ErrCodeNotAllowed, admin, assign(other, 1, 3)) // role 1 doesn't rank below the admin
	h.ok(owner, addRole(4, 100+1, "talk"))
	h.fail(wire.ErrCodeNotAllowed, admin, assign(owner))      // the owner
	h.ok(owner, assign(other, 1))                             // other is an admin now
	h.fail(wire.ErrCodeNotAllowed, admin, assign(other))      // an equal
	h.ok(admin, assign(admin, 1, 3))                          // their own roles, below their level
	h.fail(wire.ErrCodeNotAllowed, member, assign(member, 2)) // a plain member adding
	h.ok(member, assign(member))                              // removing their own
	h.ok(admin, assign(member, 3))
	h.fail(wire.ErrCodeNotAllowed, mod, assign(member, 2)) // moderate can only clear
	h.ok(mod, assign(member))                              // a kick
	h.fail(wire.ErrCodeNotAllowed, mod, assign(other))     // above the moderator
	h.fail(wire.ErrCodeInvalidChain, admin, assign(member, 3, 2))
	h.fail(wire.ErrCodeInvalidChain, admin, assign(member, 0))
	h.fail(wire.ErrCodeInvalidChain, admin, assign(member, 42))
	// A role added earlier in the same entry can be assigned.
	h.ok(admin, addRole(5, 30, "talk"), assign(member, 5))
	// A role whose perms the signer lacks can't be handed out.
	h.ok(owner, addRole(6, 40, "administrate"), assign(mod, 2, 6))
	h.ok(owner, addRole(7, 5, "invite"))
	h.fail(wire.ErrCodeNotAllowed, mod, assign(member, 5, 7))
}

func TestChannels(t *testing.T) {
	h, owner, admin, _, member := staffed(t)
	h.ok(admin, textChannel(1, []uint64{0}, []uint64{0}), voiceChannel(2, 25, 2))
	h.fail(wire.ErrCodeInvalidChain, admin, textChannel(4, []uint64{0}, []uint64{0}))
	h.fail(wire.ErrCodeInvalidChain, admin, textChannel(3, []uint64{0, 1}, []uint64{0}))
	h.fail(wire.ErrCodeInvalidChain, admin, textChannel(3, []uint64{3, 1}, []uint64{0}))
	h.fail(wire.ErrCodeInvalidChain, admin, textChannel(3, []uint64{9}, []uint64{0}))
	h.fail(wire.ErrCodeNotAllowed, admin, voiceChannel(3, 65, 2))
	h.fail(wire.ErrCodeNotAllowed, admin, voiceChannel(3, 25, 0))
	h.fail(wire.ErrCodeNotAllowed, admin, voiceChannel(3, 25, 5))
	h.fail(wire.ErrCodeBadRequest, admin, map[string]any{"op": "add-channel", "id": 3, "name": sealedVal(), "see": []uint64{0}, "write": []uint64{0}, "kind": "voice", "max": 5, "cast": 1, "slow": 0})
	h.fail(wire.ErrCodeNotAllowed, member, textChannel(3, []uint64{0}, []uint64{0}))

	ch1 := h.st.Channels[1]
	if !h.st.CanSee(member.id, ch1) || !h.st.CanWrite(member.id, ch1) || h.st.Restricted(ch1) || SeeKey([]uint64{1, 3}) != "1,3" {
		t.Fatal("channel access")
	}
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-channel", "id": 2, "slow": 5})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-channel", "id": 1, "max": 5})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "edit-channel", "id": 2, "max": 65})
	h.fail(wire.ErrCodeBadRequest, admin, map[string]any{"op": "edit-channel", "id": 1})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-channel", "id": 9, "slow": 5})
	h.ok(admin, map[string]any{"op": "edit-channel", "id": 1, "slow": 30, "topic": sealedVal()})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-channel", "id": 1, "see": []uint64{1}})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "edit-channel", "id": 1, "see": []uint64{1}, "name": sealedVal()})
	a := h.ok(admin, map[string]any{"op": "edit-channel", "id": 1, "see": []uint64{1}, "name": sealedVal(), "topic": nil})
	if !a.Ops[0].SeeSet || h.st.Channels[1].HasTopic || !h.st.Restricted(h.st.Channels[1]) || h.st.CanSee(member.id, h.st.Channels[1]) || h.st.Channels[1].Slow != 30 {
		t.Fatal("edit-channel")
	}
	a = h.ok(admin, map[string]any{"op": "edit-channel", "id": 1, "see": []uint64{1}, "write": []uint64{1}})
	if a.Ops[0].SeeSet {
		t.Fatal("an unchanged see isn't a change")
	}
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "order-channels", "ids": []uint64{1}})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "order-channels", "ids": []uint64{1, 1}})
	h.ok(admin, map[string]any{"op": "order-channels", "ids": []uint64{2, 1}})
	h.ok(admin, map[string]any{"op": "remove-channel", "id": 2})
	if len(h.st.Order) != 1 || h.st.Order[0] != 1 {
		t.Fatal("remove-channel takes it out of the order")
	}
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "remove-channel", "id": 2})
	// 100 channels at most.
	var ops []map[string]any
	for id := h.st.LastChannel + 1; len(h.st.Channels)+len(ops) < MaxChannels; id++ {
		ops = append(ops, textChannel(id, []uint64{0}, []uint64{0}))
	}
	h.ok(owner, ops...)
	h.fail(wire.ErrCodeNotAllowed, owner, textChannel(h.st.LastChannel+1, []uint64{0}, []uint64{0}))
}

func TestCodes(t *testing.T) {
	h, owner, admin, mod, member := staffed(t)
	key := newCode(t)
	sum := sha256.Sum256(key)
	h.fail(wire.ErrCodeInvalidChain, member, map[string]any{"op": "add-code", "key": key, "uses": 5})
	h.fail(wire.ErrCodeInvalidChain, member, map[string]any{"op": "add-code", "key": key, "exp": testNow, "uses": 5})
	h.fail(wire.ErrCodeNotAllowed, member, map[string]any{"op": "add-code", "key": key, "exp": testNow + 60, "uses": 1001})
	h.fail(wire.ErrCodeNotAllowed, member, map[string]any{"op": "add-code", "key": key, "exp": testNow + 60, "uses": 0})
	a := h.ok(member, map[string]any{"op": "add-code", "key": key, "exp": testNow + 60, "uses": 5})
	if !bytes.Equal(a.Ops[0].Code, sum[:]) || h.st.Live(sum[:], testNow) == nil || h.st.Live(sum[:], testNow+60) != nil {
		t.Fatal("Live and expiry")
	}
	if c := h.st.Live(sum[:], testNow); c.Creator != member.id || c.Uses != 5 || c.Exp != testNow+60 {
		t.Fatalf("code: %+v", c)
	}
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "revoke-code", "code": sum[:]}) // not creator or admin
	h.ok(member, map[string]any{"op": "revoke-code", "code": sum[:]})
	h.fail(wire.ErrCodeInvalidChain, member, map[string]any{"op": "revoke-code", "code": sum[:]})
	h.fail(wire.ErrCodeInvalidChain, member, map[string]any{"op": "add-code", "key": key, "exp": testNow + 60, "uses": 5}) // a used key

	// Public codes, and set-settings turning them off.
	pub := newCode(t)
	psum := sha256.Sum256(pub)
	h.ok(member, map[string]any{"op": "add-code", "key": pub, "public": true})
	if c := h.st.Live(psum[:], testNow+1e6); c == nil || c.Uses != 0 || c.Exp != 0 {
		t.Fatal("a public code without exp or uses")
	}
	priv := newCode(t)
	vsum := sha256.Sum256(priv)
	h.ok(admin, map[string]any{"op": "add-code", "key": priv, "exp": testNow + 600, "uses": 1})
	h.ok(admin, map[string]any{"op": "set-settings", "public": false, "approval": true})
	if h.st.Live(psum[:], testNow) != nil || h.st.Live(vsum[:], testNow) == nil || !h.st.Approval {
		t.Fatal("turning public off removes public codes only")
	}
	h.fail(wire.ErrCodeInvalidChain, member, map[string]any{"op": "add-code", "key": newCode(t), "public": true})
	// The admin revokes someone else's; a banned creator's code isn't live.
	k2 := newCode(t)
	s2 := sha256.Sum256(k2)
	h.ok(member, map[string]any{"op": "add-code", "key": k2, "exp": testNow + 600, "uses": 3})
	h.ok(owner, map[string]any{"op": "ban", "member": member.id})
	if h.st.Live(s2[:], testNow) != nil {
		t.Fatal("a banned creator's code")
	}
	h.ok(admin, map[string]any{"op": "revoke-code", "code": s2[:]})
	// set-home removes every code.
	h.fail(wire.ErrCodeInvalidChain, owner, map[string]any{"op": "set-home", "server": testServer})
	a = h.ok(owner, map[string]any{"op": "set-home", "server": "new.example.com"})
	if len(h.st.Codes) != 0 || h.st.Server != "new.example.com" || a.Ops[0].Server != "new.example.com" {
		t.Fatal("set-home")
	}
}

func TestModeration(t *testing.T) {
	h, owner, admin, mod, member := staffed(t)
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "timeout", "member": admin.id, "until": testNow + 60})
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "timeout", "member": member.id, "until": testNow + MaxTimeout + 1})
	h.fail(wire.ErrCodeInvalidChain, mod, map[string]any{"op": "timeout", "member": member.id, "until": testNow - 1})
	h.ok(mod, map[string]any{"op": "timeout", "member": member.id, "until": testNow + MaxTimeout})
	if !h.st.TimedOut(member.id, testNow) || h.st.TimedOut(member.id, testNow+MaxTimeout) {
		t.Fatal("TimedOut")
	}
	h.ok(mod, map[string]any{"op": "timeout", "member": member.id, "until": testNow})
	if h.st.TimedOut(member.id, testNow-10) {
		t.Fatal("until equal to ts ends it")
	}
	// Bans.
	h.fail(wire.ErrCodeNotAllowed, mod, map[string]any{"op": "ban", "member": member.id})
	h.fail(wire.ErrCodeNotAllowed, admin, map[string]any{"op": "ban", "member": owner.id})
	h.fail(wire.ErrCodeNotAllowed, owner, map[string]any{"op": "ban", "member": owner.id})
	h.ok(mod, map[string]any{"op": "timeout", "member": member.id, "until": testNow + 60})
	h.ok(admin, map[string]any{"op": "ban", "member": member.id})
	if !h.st.BannedIDs[member.id] || len(h.st.Assigned[member.id]) != 0 || h.st.TimedOut(member.id, testNow) {
		t.Fatal("a ban clears roles and the timeout")
	}
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "ban", "member": member.id})
	h.ok(admin, map[string]any{"op": "ban", "domain": "spam.example"})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "ban", "domain": "spam.example"})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "unban", "domain": "other.example"})
	h.ok(admin, map[string]any{"op": "unban", "member": member.id}, map[string]any{"op": "unban", "domain": "spam.example"})
	h.fail(wire.ErrCodeInvalidChain, admin, map[string]any{"op": "unban", "member": member.id})

	// Ownership.
	h.fail(wire.ErrCodeInvalidChain, owner, map[string]any{"op": "transfer-ownership", "to": owner.id})
	h.ok(owner, map[string]any{"op": "ban", "member": member.id})
	h.fail(wire.ErrCodeInvalidChain, owner, map[string]any{"op": "transfer-ownership", "to": member.id})
	h.ok(owner, assign(owner, 1), map[string]any{"op": "transfer-ownership", "to": admin.id})
	if h.st.Owner != admin.id || h.st.Level(owner.id) != 100 {
		t.Fatal("the old owner keeps their roles, by level")
	}
	h.fail(wire.ErrCodeNotAllowed, owner, map[string]any{"op": "transfer-ownership", "to": owner.id})
	h.fail(wire.ErrCodeNotAllowed, owner, assign(admin))
}

func TestReplayAndImport(t *testing.T) {
	h, owner, admin, _, member := staffed(t)
	h.ok(admin, textChannel(1, []uint64{0}, []uint64{0}), map[string]any{"op": "add-code", "key": newCode(t), "exp": testNow + 600, "uses": 3})
	h.ok(owner, map[string]any{"op": "timeout", "member": member.id, "until": testNow + 600})
	for _, mode := range []Mode{Replay, Import} {
		keys := h.keys
		if mode == Replay {
			keys = nil
		}
		st, err := ReplayChain(h.raws, testServer, keys, testNow+30*86400, mode)
		if err != nil {
			t.Fatal(mode, err)
		}
		if !sameState(st, h.st) {
			t.Fatal("replayed state differs", mode)
		}
	}
	// A tampered entry fails Import, at its signature.
	bad := bytes.Clone(h.raws[1])
	bad = bytes.Replace(bad, []byte(`"rank\":100`), []byte(`"rank\":101`), 1)
	raws := append([][]byte{h.raws[0], bad}, h.raws[2:]...)
	if _, err := ReplayChain(raws, testServer, h.keys, testNow, Import); err == nil {
		t.Fatal("a tampered entry")
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"Night shift", "Café", "日本語のチャンネル", "a", strings.Repeat("x", 64)} {
		if !validName(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"", " x", "x ", "a\tb", "a\u200bb", "a\u2066b", "x☀", "x😀", "Cafe\u0301", strings.Repeat("x", 65)} {
		if validName(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
	if !validDesc("line one\nline two") || validDesc("tab\there") || validDesc("x\u202dy") || !validDesc("") {
		t.Error("descriptions")
	}
	for s, want := range map[string]bool{"a.test": true, "chat.example.com": true, "A.test": false, "localhost": false, "1.2.3.4": false, "-a.test": false, "a..test": false, "a.test.": false} {
		if validServerName(s) != want {
			t.Errorf("server name %q: want %v", s, want)
		}
	}
}

func TestIcon(t *testing.T) {
	h, owner := newCommunity(t)
	hash := make([]byte, 32)
	hash[0] = 7
	icon := func(mime string, size int) map[string]any {
		return map[string]any{"mime": mime, "hash": hash, "size": size}
	}
	h.ok(owner, map[string]any{"op": "set-name", "name": "Night shift", "desc": "d", "icon": icon("image/webp", 1000)})
	if h.st.Icon == nil || h.st.Icon.Mime != "image/webp" || h.st.Icon.Size != 1000 || !bytes.Equal(h.st.Icon.Hash, hash) {
		t.Fatalf("icon %+v", h.st.Icon)
	}
	c := h.st.Clone()
	c.Icon.Hash[0] = 9
	if h.st.Icon.Hash[0] != 7 {
		t.Fatal("Clone shares the icon's hash")
	}
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "icon": icon("image/gif", 10)})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "icon": icon("image/png", 0)})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "icon": icon("image/png", MaxIconSize+1)})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "icon": map[string]any{"mime": "image/png", "hash": make([]byte, 31), "size": 5}})
	extra := icon("image/png", 5)
	extra["url"] = "https://example.com/i.png"
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "icon": extra})
	h.fail(wire.ErrCodeBadRequest, owner, map[string]any{"op": "set-name", "name": "x", "icon": "abc"})
	h.ok(owner, map[string]any{"op": "set-name", "name": "x", "icon": icon("image/png", MaxIconSize)})
	if h.st.Icon == nil || h.st.Icon.Size != MaxIconSize || h.st.Desc != "" {
		t.Fatalf("icon %+v desc %q", h.st.Icon, h.st.Desc)
	}
	// The whole state: a set-name without icon removes it.
	h.ok(owner, map[string]any{"op": "set-name", "name": "x"})
	if h.st.Icon != nil {
		t.Fatal("set-name without icon kept it")
	}
}
