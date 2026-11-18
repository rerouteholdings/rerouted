package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// GET members (SPEC §16.5, re-creating the community's groups): the server's member list,
// with each member's home, for the owner and members with administrate.
func TestCommunityMembersList(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi, mia := e.user("ravi"), e.user("mia")
	kat, m := joined(t, e, ravi, mia)
	kat.mustAppend(m.ch, map[string]any{"op": "add-role", "id": 1, "rank": 10, "perms": []string{"administrate"}, "name": sealed()},
		map[string]any{"op": "assign-roles", "member": mia.id, "roles": []uint64{1}})
	if c, code := e.errOf("GET", "members", ravi.tok, nil); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("members for a plain member: %d %s", c, code)
	}
	if c, _ := e.errOf("GET", "members", e.user("lee").tok, nil); c != 403 {
		t.Fatalf("members for a stranger: %d", c)
	}
	for _, u := range []*cmUser{kat, mia} {
		var res struct {
			Items []struct {
				ID   string `json:"id"`
				Home string `json:"home"`
			} `json:"items"`
		}
		if c := e.call("GET", "members", u.tok, nil, &res); c != 200 || len(res.Items) != 3 {
			t.Fatalf("members for %s: %d %+v", u.handle, c, res)
		}
		seen := map[string]bool{}
		for _, it := range res.Items {
			if it.Home != "chat.test" {
				t.Fatalf("member %s's home: %q", it.ID, it.Home)
			}
			seen[it.ID] = true
		}
		if !seen[kat.id] || !seen[ravi.id] || !seen[mia.id] {
			t.Fatalf("members: %+v", res.Items)
		}
	}
}

// replacedErr calls and returns the status, error code, and group of a replaced error.
func (e *cmEnv) replacedErr(method, path, token string, body any) (int, string, []byte) {
	e.t.Helper()
	var res wire.Error
	c := e.call(method, path, token, body, &res)
	return c, res.Code, res.Group
}

// newReg is a group registration at epoch 0, for groups/create.
func newReg(u *cmUser, g *made, tree string) map[string]any {
	return map[string]any{"group": g.group, "epoch": 0, "epoch-key": g.ekey.Public().Bytes(), "info": []byte("info-0"), "tree": u.uploadTree(tree)}
}

// Re-creating the community's groups (SPEC §16.5): who may, the switch, the old group's
// refusals and readable history, Welcomes into the new group, code joins, and channel
// sequence numbers going on.
func TestCommunityRecreateGroups(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi, mia, lee := e.user("ravi"), e.user("mia"), e.user("lee")
	kat := e.user("kat")
	m := kat.create("chat.test", false)
	code := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code, 100),
		map[string]any{"op": "add-role", "id": 1, "rank": 10, "perms": []string{"administrate"}, "name": sealed()},
		map[string]any{"op": "add-role", "id": 2, "rank": 20, "perms": []string{"talk"}, "name": sealed()},
		textChannel(1, []uint64{0}, []uint64{0}, 0),
		textChannel(2, []uint64{2}, []uint64{2}, 0))
	for _, u := range []*cmUser{ravi, mia, lee} {
		if c, cd := u.codeJoin(m, code, nil); c != 200 {
			t.Fatalf("%s joins: %d %s", u.handle, c, cd)
		}
	}
	kat.mustAppend(m.ch, map[string]any{"op": "assign-roles", "member": mia.id, "roles": []uint64{1}},
		map[string]any{"op": "assign-roles", "member": kat.id, "roles": []uint64{2}},
		map[string]any{"op": "assign-roles", "member": ravi.id, "roles": []uint64{2}})
	// The staff group carries channel 2.
	staff := &made{group: randB(32), ekey: newComposite(t), ch: m.ch}
	sreg := newReg(kat, staff, "staff-0")
	sreg["see"] = []uint64{2}
	if c := e.call("POST", "groups/create", kat.tok, sreg, nil); c != 204 {
		t.Fatalf("staff group: %d", c)
	}
	if c := e.call("POST", "groups/register", ravi.tok, map[string]any{"group": staff.group}, nil); c != 204 {
		t.Fatalf("ravi registers for staff: %d", c)
	}
	if res := kat.say(m, 1, "one"); res.Seq != 1 {
		t.Fatalf("channel 1, first message: %+v", res)
	}
	if res := kat.say(staff, 2, "staff one"); res.Seq != 1 {
		t.Fatalf("channel 2, first message: %+v", res)
	}

	// Replacing the members group: administrate or the owner only, with no see list.
	nm := &made{group: randB(32), ekey: newComposite(t), ch: m.ch}
	reg := newReg(mia, nm, "members-new-0")
	reg["replaces"] = m.group
	if c, code := e.errOf("POST", "groups/create", ravi.tok, reg); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a plain member re-creates: %d %s", c, code)
	}
	reg["see"] = []uint64{2}
	if c, code := e.errOf("POST", "groups/create", mia.tok, reg); c != 400 || code != wire.ErrCodeBadRequest {
		t.Fatalf("replacing the members group with a see list: %d %s", c, code)
	}
	delete(reg, "see")
	reg["replaces"] = randB(32)
	if c, code := e.errOf("POST", "groups/create", mia.tok, reg); c != 400 {
		t.Fatalf("replacing an unknown group: %d %s", c, code)
	}
	reg["replaces"] = m.group
	if c := e.call("POST", "groups/create", mia.tok, reg, nil); c != 204 {
		t.Fatalf("mia re-creates the members group: %d", c)
	}
	// Replacing it again: 409 replaced, naming the new group.
	again := newReg(kat, &made{group: randB(32), ekey: newComposite(t)}, "members-again-0")
	again["replaces"] = m.group
	if c, code, g := e.replacedErr("POST", "groups/create", kat.tok, again); c != 409 || code != wire.ErrCodeReplaced || !bytes.Equal(g, nm.group) {
		t.Fatalf("replacing a replaced group: %d %s %x", c, code, g)
	}
	// A known group ID is already-exists, as ever.
	again["replaces"], again["group"] = nm.group, staff.group
	if c, code := e.errOf("POST", "groups/create", kat.tok, again); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("a known group ID: %d %s", c, code)
	}

	// The old group: commits, sends, registrations, and GroupInfo answer replaced.
	if res := ravi.say(m, 1, "late"); res.Error != wire.ErrCodeReplaced || !bytes.Equal(res.Group, nm.group) {
		t.Fatalf("a message to the old group: %+v", res)
	}
	if _, res := kat.commit(m, nil, nil); res.Error != wire.ErrCodeReplaced || !bytes.Equal(res.Group, nm.group) {
		t.Fatalf("a commit to the old group: %+v", res)
	}
	old := "groups/" + base64.RawURLEncoding.EncodeToString(m.group)
	if c, code, g := e.replacedErr("GET", old+"/info", ravi.tok, nil); c != 409 || code != wire.ErrCodeReplaced || !bytes.Equal(g, nm.group) {
		t.Fatalf("the old group's GroupInfo: %d %s %x", c, code, g)
	}
	if c, code, g := e.replacedErr("POST", "groups/register", ravi.tok, map[string]any{"group": m.group}); c != 409 || code != wire.ErrCodeReplaced || !bytes.Equal(g, nm.group) {
		t.Fatalf("registering for the old group: %d %s %x", c, code, g)
	}
	// Its history stays readable.
	if c := e.call("GET", old+"/commits?after=-1", ravi.tok, nil, nil); c != 200 {
		t.Fatalf("the old group's commits: %d", c)
	}
	resp := e.raw("GET", old+"/tree?epoch=0", ravi.tok)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "tree-epoch-0" {
		t.Fatalf("the old group's tree: %d %q", resp.StatusCode, b)
	}
	// The preview names the new members group.
	var pv struct {
		Group wire.Bytes `json:"group"`
	}
	if c := e.call("GET", "preview", "", nil, &pv); c != 200 || !bytes.Equal(pv.Group, nm.group) {
		t.Fatalf("preview: %d %x", c, pv.Group)
	}

	// Registrations don't carry over: ravi gets the new group once his Welcome is delivered.
	nw := "groups/" + base64.RawURLEncoding.EncodeToString(nm.group)
	if c, _ := e.errOf("GET", nw+"/info", ravi.tok, nil); c != 403 {
		t.Fatalf("ravi reads the new group before his Welcome: %d", c)
	}
	welcomes := []any{map[string]any{"id": randB(16), "to": []string{kat.id, ravi.id}, "devs": [][]byte{edOf(kat.dev), edOf(ravi.dev)}, "data": []byte("welcome")}}
	if _, res := mia.commit(nm, welcomes, nil); res.Status != "sent" {
		t.Fatalf("mia adds everyone: %+v", res)
	}
	// Lee's Welcome goes on its own, after a commit too large to carry it.
	if res := mia.send(map[string]any{"id": randB(16), "kind": "mls", "group": nm.group, "epoch": nm.epoch, "mls": "welcome",
		"to": []string{lee.id}, "devs": [][]byte{edOf(lee.dev)}, "data": []byte("welcome-lee")}); res.Status != "sent" {
		t.Fatalf("a standalone Welcome to the new group: %+v", res)
	}
	for _, u := range []*cmUser{kat, ravi, lee} {
		if c := e.call("GET", nw+"/info", u.tok, nil, nil); c != 200 {
			t.Fatalf("%s reads the new group after the Welcome: %d", u.handle, c)
		}
		found := false
		for _, d := range deliveries(t, u.inbox()) {
			if d.MLS == "welcome" && bytes.Equal(d.Group, nm.group) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s has no Welcome to the new group", u.handle)
		}
	}
	// Channel 1 goes on in the new group, numbered from where it was.
	if res := ravi.say(nm, 1, "two"); res.Status != "sent" || res.Seq != 2 {
		t.Fatalf("channel 1 in the new group: %+v", res)
	}
	got := false
	for _, d := range deliveries(t, lee.inbox()) {
		if d.Channel == 1 && d.Seq == 2 && bytes.Equal(d.Group, nm.group) {
			got = true
		}
	}
	if !got {
		t.Fatal("lee didn't get channel 1's message in the new group")
	}

	// Code joins go into the new group only.
	nina := e.user("nina")
	joinOld := &made{group: nm.group}
	if c, cd := nina.codeJoin(joinOld, code, func(_ map[string]any, d map[string]any) { d["group"] = m.group }); c != 404 {
		t.Fatalf("a code join into the old group: %d %s", c, cd)
	}
	if c, cd := nina.codeJoin(&made{group: m.group}, code, nil); c != 409 {
		t.Fatalf("code access to the old group's GroupInfo: %d %s", c, cd)
	}
	if c, cd := nina.codeJoin(nm, code, nil); c != 200 {
		t.Fatalf("a code join into the new group: %d %s", c, cd)
	}

	// The staff group: a plain member can't, a see list that isn't its own is refused, and
	// the owner can, with its see list or none.
	ns := &made{group: randB(32), ekey: newComposite(t), ch: m.ch}
	sr := newReg(kat, ns, "staff-new-0")
	sr["replaces"] = staff.group
	if c, _ := e.errOf("POST", "groups/create", ravi.tok, sr); c != 403 {
		t.Fatalf("ravi re-creates staff: %d", c)
	}
	sr["see"] = []uint64{0}
	if c, code := e.errOf("POST", "groups/create", kat.tok, sr); c != 400 || code != wire.ErrCodeBadRequest {
		t.Fatalf("staff with another see list: %d %s", c, code)
	}
	sr["see"] = []uint64{2}
	if c := e.call("POST", "groups/create", kat.tok, sr, nil); c != 204 {
		t.Fatalf("kat re-creates staff: %d", c)
	}
	if res := kat.say(staff, 2, "old staff"); res.Error != wire.ErrCodeReplaced || !bytes.Equal(res.Group, ns.group) {
		t.Fatalf("channel 2 in the old staff group: %+v", res)
	}
	if res := kat.say(ns, 2, "staff two"); res.Status != "sent" || res.Seq != 2 {
		t.Fatalf("channel 2 in the new staff group: %+v", res)
	}
	// Channel 2 can't go in the members group, old rules still hold.
	if res := kat.say(nm, 2, "x"); res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("channel 2 in the members group: %+v", res)
	}

	// Replaced twice: the old group names the newest one.
	nm2 := &made{group: randB(32), ekey: newComposite(t), ch: m.ch}
	r2 := newReg(kat, nm2, "members-third-0")
	r2["replaces"] = nm.group
	if c := e.call("POST", "groups/create", kat.tok, r2, nil); c != 204 {
		t.Fatalf("kat re-creates the members group again: %d", c)
	}
	if res := ravi.say(m, 1, "very late"); res.Error != wire.ErrCodeReplaced || !bytes.Equal(res.Group, nm2.group) {
		t.Fatalf("the first group after two re-creations: %+v", res)
	}
	if c, code, g := e.replacedErr("GET", nw+"/info", ravi.tok, nil); c != 409 || code != wire.ErrCodeReplaced || !bytes.Equal(g, nm2.group) {
		t.Fatalf("the second group's GroupInfo: %d %s %x", c, code, g)
	}
}
