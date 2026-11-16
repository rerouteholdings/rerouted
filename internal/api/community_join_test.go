package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Code joins (SPEC §16.6): the hub checks the join proof before sequencing, counts uses, and
// accepts the code-signed commit-request.
func TestCommunityCodeJoin(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi, mia, theo := e.user("kat"), e.user("ravi"), e.user("mia"), e.user("theo")
	m := kat.create("chat.test", false)
	code := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code, 1))

	// Without code access, nothing of the group.
	if c, _ := e.errOf("GET", "groups/"+base64.RawURLEncoding.EncodeToString(m.group)+"/info", ravi.tok, nil); c != 403 {
		t.Fatalf("GroupInfo without a code: %d", c)
	}
	// A forged proof: signed with a key that isn't the code's.
	forged := newComposite(t)
	q := "?code=" + base64.RawURLEncoding.EncodeToString(code.Public().Hash())
	data := pubMsg("forged")
	sum := sha256.Sum256(data)
	d := map[string]any{"group": m.group, "epoch": 0, "data": data, "info": []byte("i"), "tree": ravi.joinTree(),
		"proof":  signedFull2(t, "join-proof", map[string]any{"commit": sum[:], "id": ravi.id, "epoch": 0}, forged),
		"commit": signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": 0, "hash": sum[:], "next": newComposite(t).Public().Bytes()}, forged)}
	if c, code := e.errOf("POST", "join"+q, ravi.tok, d); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("forged join proof: %d %s", c, code)
	}
	// A proof naming someone else, another epoch, or another commit.
	for name, mut := range map[string]func(p, d map[string]any){
		"another joiner": func(p, d map[string]any) { p["id"] = mia.id },
		"another epoch":  func(p, d map[string]any) { p["epoch"] = 7 },
		"another commit": func(p, d map[string]any) { p["commit"] = randB(32) },
	} {
		if c, code := ravi.codeJoin(m, code, mut); c != 403 || code != wire.ErrCodeNotAllowed {
			t.Fatalf("proof for %s: %d %s", name, c, code)
		}
	}
	// A commit-request signed with another key than the proof's.
	if c, code := ravi.codeJoin(m, code, func(p, d map[string]any) {
		dd := d["data"].([]byte)
		s := sha256.Sum256(dd)
		d["commit"] = signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": 0, "hash": s[:], "next": newComposite(t).Public().Bytes()}, forged)
	}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("commit-request with another key: %d %s", c, code)
	}
	// A PrivateMessage isn't an external commit.
	if c, code := ravi.codeJoin(m, code, func(p, d map[string]any) {
		dd := privMsg("not external")
		s := sha256.Sum256(dd)
		d["data"], p["commit"] = dd, s[:]
	}); c != 400 || code != wire.ErrCodeBadRequest {
		t.Fatalf("join with a PrivateMessage: %d %s", c, code)
	}
	// The real thing.
	if c, code := ravi.codeJoin(m, code, nil); c != 200 {
		t.Fatalf("join: %d %s", c, code)
	}
	// The members get the commit with its receipt and the join proof.
	ds := deliveries(t, kat.inbox())
	var got *cDelivery
	for i := range ds {
		if ds[i].MLS == "commit" {
			got = &ds[i]
		}
	}
	if got == nil || got.Proof == nil || got.Receipt == nil || got.From != ravi.id || len(got.To) != 1 || got.To[0] != kat.id {
		t.Fatalf("members' copy of the join: %+v", got)
	}
	r, _ := wire.DecodeSignedV2(got.Receipt)
	var rb struct {
		Hub string `json:"hub"`
	}
	r.Open(&rb)
	if rb.Hub != "chat.test" {
		t.Fatalf("receipt hub %q", rb.Hub)
	}
	// Used up: the second join is refused, by the server's count.
	if c, _ := mia.codeJoin(m, code, nil); c != 403 {
		t.Fatalf("a code past its use limit: %d", c)
	}
	// Straight to POST join, without code access to the GroupInfo first.
	mdata := pubMsg("mia")
	msum := sha256.Sum256(mdata)
	md := map[string]any{"group": m.group, "epoch": m.epoch, "data": mdata, "info": []byte("i"), "tree": mia.joinTree(),
		"proof":  signedFull2(t, "join-proof", map[string]any{"commit": msum[:], "id": mia.id, "epoch": m.epoch}, code),
		"commit": signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": m.epoch, "hash": msum[:], "next": newComposite(t).Public().Bytes()}, code)}
	if c, code := e.errOf("POST", "join"+q, mia.tok, md); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a join past the use limit: %d %s", c, code)
	}
	// A stale epoch, with a fresh code.
	code2 := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code2, 10))
	if c, code := theo.codeJoin(m, code2, func(p, d map[string]any) {
		dd := d["data"].([]byte)
		s := sha256.Sum256(dd)
		p["epoch"], d["epoch"] = 0, 0
		d["commit"] = signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": 0, "hash": s[:], "next": newComposite(t).Public().Bytes()}, code2)
	}); c != 409 || code != wire.ErrCodeStaleEpoch {
		t.Fatalf("join on a stale epoch: %d %s", c, code)
	}
	// A revoked code no longer works.
	kat.mustAppend(m.ch, map[string]any{"op": "revoke-code", "code": code2.Public().Hash()})
	if c, _ := theo.codeJoin(m, code2, nil); c != 403 {
		t.Fatalf("revoked code: %d", c)
	}
}

// Failed joins are limited: 10 an hour per identity.
func TestCommunityFailedJoinLimit(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi := e.user("kat"), e.user("ravi")
	m := kat.create("chat.test", false)
	code := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code, 100))
	q := "?code=" + base64.RawURLEncoding.EncodeToString(randB(32))
	for i := range 10 {
		if c, _ := e.errOf("POST", "join"+q, ravi.tok, map[string]any{}); c != 403 {
			t.Fatalf("failed join %d: %d", i, c)
		}
	}
	if c, code := e.errOf("POST", "join"+q, ravi.tok, map[string]any{}); c != 429 || code != wire.ErrCodeRateLimited {
		t.Fatalf("11th failed join: %d %s", c, code)
	}
}

// Joins with approval (SPEC §16.6 step 5): a request, a moderator's approval claiming key
// packages, and the Welcome that makes the joiner a member.
func TestCommunityApprovalJoin(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi, mia, lee := e.user("kat"), e.user("ravi"), e.user("mia"), e.user("lee")
	m := kat.create("chat.test", true)
	code := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code, 10))
	if c, _ := ravi.codeJoin(m, code, nil); c != 403 {
		t.Fatalf("code join where approval is on: %d", c)
	}
	// Ravi uploads key packages here, then asks.
	if c := e.call("POST", "keypackages/upload", ravi.tok, map[string]any{"packages": []any{ravi.kp(ravi.dev, "ravi-kp")}, "last-resort": ravi.kp(ravi.dev, "ravi-lr")}, nil); c != 200 {
		t.Fatalf("kp upload: %d", c)
	}
	// A binding by another identity is refused.
	if c, _ := e.errOf("POST", "keypackages/upload", ravi.tok, map[string]any{"packages": []any{mia.kp(mia.dev, "x")}}); c != 400 {
		t.Fatalf("someone else's binding: %d", c)
	}
	if c := e.call("POST", "join/request", ravi.tok, map[string]any{}, nil); c != 202 {
		t.Fatalf("join/request: %d", c)
	}
	if c := e.call("POST", "join/request", ravi.tok, map[string]any{}, nil); c != 202 {
		t.Fatalf("join/request again: %d", c)
	}
	notices := 0
	for _, it := range kat.inbox() {
		if bytes.Contains(it.Notice, []byte(`"join-request"`)) {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("%d join-request notices, want 1", notices)
	}
	var list struct {
		Items []struct {
			ID   string `json:"id"`
			Home string `json:"home"`
		} `json:"items"`
	}
	if c := e.call("GET", "join/requests", kat.tok, nil, &list); c != 200 || len(list.Items) != 1 || list.Items[0].ID != ravi.id || list.Items[0].Home != "chat.test" {
		t.Fatalf("join/requests: %+v", list)
	}
	if c, _ := e.errOf("GET", "join/requests", ravi.tok, nil); c != 403 {
		t.Fatalf("a non-member listed requests: %d", c)
	}
	// Mia, a member with moderate, and kat.
	code2 := newComposite(t)
	kat.mustAppend(m.ch, map[string]any{"op": "set-settings", "public": true, "approval": false})
	kat.mustAppend(m.ch, addCodeOp(code2, 10))
	if c, cd := mia.codeJoin(m, code2, nil); c != 200 {
		t.Fatalf("mia joins: %d %s", c, cd)
	}
	kat.mustAppend(m.ch, map[string]any{"op": "set-settings", "public": true, "approval": true},
		map[string]any{"op": "add-role", "id": 1, "rank": 10, "perms": []string{"moderate"}, "name": sealed()},
		map[string]any{"op": "assign-roles", "member": mia.id, "roles": []uint64{1}})
	var got claimed
	if c := e.call("POST", "join/approve", kat.tok, map[string]any{"id": ravi.id}, &got); c != 200 || len(got.Packages) != 1 || string(got.Packages[0].KP) != "ravi-kp" {
		t.Fatalf("approve: %d %+v", c, got)
	}
	checkBinding(t, ravi.id, ravi.dev, got.Packages[0].KP, got.Packages[0].Binding)
	var again claimed
	if c := e.call("POST", "join/approve", kat.tok, map[string]any{"id": ravi.id}, &again); c != 200 || len(again.Packages) != 1 || string(again.Packages[0].KP) != "ravi-kp" {
		t.Fatalf("approve retried: %d %+v", c, again)
	}
	if c, code := e.errOf("POST", "join/approve", mia.tok, map[string]any{"id": ravi.id}); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("a second moderator's approval: %d %s", c, code)
	}
	// Mia can't welcome Ravi: kat holds the approval.
	welcome := []any{map[string]any{"id": randB(16), "to": []string{ravi.id}, "devs": [][]byte{edOf(ravi.dev)}, "data": []byte("welcome")}}
	if _, res := mia.commit(m, welcome, nil); res.Status != "rejected" || res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("welcome without the approval: %+v", res)
	}
	// Nor anyone the request isn't for.
	bad := []any{map[string]any{"id": randB(16), "to": []string{lee.id}, "devs": [][]byte{edOf(lee.dev)}, "data": []byte("welcome")}}
	if _, res := kat.commit(m, bad, nil); res.Status != "rejected" || res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("welcome to a stranger: %+v", res)
	}
	// A device that isn't Ravi's.
	wrongDev := []any{map[string]any{"id": randB(16), "to": []string{ravi.id}, "devs": [][]byte{edOf(lee.dev)}, "data": []byte("welcome")}}
	if _, res := kat.commit(m, wrongDev, nil); res.Status != "rejected" {
		t.Fatalf("welcome to someone else's device: %+v", res)
	}
	if _, res := kat.commit(m, welcome, nil); res.Status != "sent" || res.Receipt == nil {
		t.Fatalf("kat's commit with the welcome: %+v", res)
	}
	// Ravi is a member, has the Welcome, and gets the group's traffic from here on.
	ws := deliveries(t, ravi.inbox())
	if len(ws) != 1 || ws[0].MLS != "welcome" || ws[0].Epoch != m.epoch {
		t.Fatalf("ravi's inbox: %+v", ws)
	}
	if c := e.call("GET", "chain", ravi.tok, nil, nil); c != 200 {
		t.Fatalf("ravi can't read the chain as a member: %d", c)
	}
	if c, _ := e.errOf("POST", "join/approve", kat.tok, map[string]any{"id": ravi.id}); c != 404 {
		t.Fatalf("the request is closed: %d", c)
	}
	// Declining.
	if c := e.call("POST", "join/request", lee.tok, map[string]any{}, nil); c != 202 {
		t.Fatal("lee asks")
	}
	if c := e.call("POST", "join/decline", mia.tok, map[string]any{"id": lee.id}, nil); c != 204 {
		t.Fatalf("decline: %d", c)
	}
	declined := false
	for _, it := range lee.inbox() {
		declined = declined || bytes.Contains(it.Notice, []byte(`"join-declined"`))
	}
	if !declined {
		t.Fatal("no join-declined notice")
	}
}

// Channel messages: the server's checks on who writes where, sequence numbers, slow mode,
// timeouts, and PublicMessages.
func TestCommunityChannelRules(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi := e.user("kat"), e.user("ravi")
	m := kat.create("chat.test", false)
	code := newComposite(t)
	kat.mustAppend(m.ch,
		map[string]any{"op": "add-role", "id": 1, "rank": 10, "perms": []string{"talk"}, "name": sealed()},
		map[string]any{"op": "assign-roles", "member": kat.id, "roles": []uint64{1}},
		textChannel(1, []uint64{0}, []uint64{0}, 0),
		textChannel(2, []uint64{0}, []uint64{1}, 0),
		textChannel(3, []uint64{0}, []uint64{0}, 60),
		addCodeOp(code, 5))
	if c, cd := ravi.codeJoin(m, code, nil); c != 200 {
		t.Fatalf("join: %d %s", c, cd)
	}
	ravi.inbox()
	for i := 1; i <= 3; i++ {
		if res := ravi.say(m, 1, "hello"); res.Status != "sent" || res.Seq != uint64(i) {
			t.Fatalf("message %d: %+v", i, res)
		}
	}
	// Idempotent per id: the same seq back, not numbered again.
	d := map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "app", "channel": 1, "data": privMsg("x")}
	first := ravi.send(d)
	if again := ravi.send(d); again.Seq != first.Seq || first.Seq != 4 {
		t.Fatalf("resent: %+v then %+v", first, again)
	}
	if res := kat.say(m, 1, "next"); res.Seq != 5 {
		t.Fatalf("numbering continued at %d", res.Seq)
	}
	// Kat sees ravi's messages with their seq; ravi doesn't get his own.
	var seqs []uint64
	for _, d := range deliveries(t, kat.inbox()) {
		if d.Channel == 1 {
			seqs = append(seqs, d.Seq)
		}
	}
	if len(seqs) != 4 || seqs[0] != 1 || seqs[3] != 4 {
		t.Fatalf("kat's copies: %v", seqs)
	}
	for _, d := range deliveries(t, ravi.inbox()) {
		if d.From == ravi.id {
			t.Fatal("ravi got his own message")
		}
	}
	// Channel 2 is for role 1 to write.
	if res := ravi.say(m, 2, "x"); res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("writing without a write role: %+v", res)
	}
	if res := kat.say(m, 2, "x"); res.Status != "sent" {
		t.Fatalf("writing with it: %+v", res)
	}
	// No such channel.
	if res := ravi.say(m, 99, "x"); res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("unknown channel: %+v", res)
	}
	// Slow mode: one per 60 s.
	if res := ravi.say(m, 3, "x"); res.Status != "sent" {
		t.Fatalf("first in slow mode: %+v", res)
	}
	if res := ravi.say(m, 3, "x"); res.Error != wire.ErrCodeRateLimited || res.Retry < 1 || res.Retry > 60 {
		t.Fatalf("second in slow mode: %+v", res)
	}
	// PublicMessages are refused on send.
	if res := ravi.send(map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "app", "channel": 1, "data": pubMsg("x")}); res.Error != wire.ErrCodeBadRequest {
		t.Fatalf("PublicMessage via send: %+v", res)
	}
	// A timeout: ravi's sends and uploads are refused until it ends.
	kat.mustAppend(m.ch, map[string]any{"op": "timeout", "member": ravi.id, "until": time.Now().Unix() + 600})
	if res := ravi.say(m, 1, "x"); res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("a timed-out member's message: %+v", res)
	}
	if c, _ := e.do("POST", "media/upload", ravi.tok, "application/octet-stream", []byte("file"), nil); c != 403 {
		t.Fatalf("a timed-out member's upload: %d", c)
	}
	// Protocol traffic (no channel) still flows.
	if res := ravi.send(map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "app", "data": privMsg("keys")}); res.Status != "sent" {
		t.Fatalf("protocol traffic from a timed-out member: %+v", res)
	}
	kat.mustAppend(m.ch, map[string]any{"op": "timeout", "member": ravi.id, "until": time.Now().Unix()})
	if res := ravi.say(m, 1, "back"); res.Status != "sent" {
		t.Fatalf("after the timeout ended: %+v", res)
	}
	// Stored messages, by number.
	var msgs struct {
		Items []struct {
			Seq      uint64   `json:"seq"`
			Delivery wire.Raw `json:"delivery"`
			Deleted  uint64   `json:"deleted"`
		} `json:"items"`
		Next string `json:"next"`
	}
	if c := e.call("GET", "channels/1/messages?from=2&limit=2", kat.tok, nil, &msgs); c != 200 || len(msgs.Items) != 2 || msgs.Items[0].Seq != 2 || msgs.Next != "3" {
		t.Fatalf("channel messages: %d %+v", c, msgs)
	}
	// Deleting: the author, with its own later delete.
	del := ravi.say(m, 1, "delete seq 1")
	if c, _ := e.errOf("POST", "messages/delete", kat.tok, map[string]any{"channel": 1, "seq": 1, "by": del.Seq}); c != 403 {
		t.Fatalf("someone else's delete as by: %d", c)
	}
	if c := e.call("POST", "messages/delete", ravi.tok, map[string]any{"channel": 1, "seq": 1, "by": del.Seq}, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	msgs.Items = nil
	if c := e.call("GET", "channels/1/messages", kat.tok, nil, &msgs); c != 200 || msgs.Items[0].Deleted != del.Seq || msgs.Items[0].Delivery != nil {
		t.Fatalf("deleted message: %+v", msgs.Items[0])
	}
	// Kat (owner, outranks ravi) deletes ravi's message with her own delete.
	kd := kat.say(m, 1, "mod delete")
	if c := e.call("POST", "messages/delete", kat.tok, map[string]any{"channel": 1, "seq": 2, "by": kd.Seq}, nil); c != 204 {
		t.Fatalf("moderator's delete: %d", c)
	}
	// Ravi can't delete kat's.
	rd := ravi.say(m, 1, "try")
	if c, _ := e.errOf("POST", "messages/delete", ravi.tok, map[string]any{"channel": 1, "seq": 5, "by": rd.Seq}); c != 403 {
		t.Fatalf("deleting the owner's message: %d", c)
	}
}

// History segments (SPEC §16.5): one per start, no overlaps, retries, and replace only after
// a delete inside the segment.
func TestCommunityHistory(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat := e.user("kat")
	m := kat.create("chat.test", false)
	kat.mustAppend(m.ch, textChannel(1, []uint64{0}, []uint64{0}, 0),
		map[string]any{"op": "add-channel", "id": 2, "name": sealed(), "see": []uint64{0}, "write": []uint64{0}, "kind": "text", "history": false, "slow": 0})
	for range 6 {
		kat.say(m, 1, "m")
	}
	ct := randB(100)
	put := func(start, end uint64, ct []byte, replace bool) (int, string) {
		b := map[string]any{"channel": 1, "start": start, "end": end, "ct": ct}
		if replace {
			b["replace"] = true
		}
		return e.errOf("POST", "history/put", kat.tok, b)
	}
	if c, _ := put(1, 3, ct, false); c != 204 {
		t.Fatalf("put: %d", c)
	}
	if c, _ := put(1, 3, ct, false); c != 204 {
		t.Fatalf("retry: %d", c)
	}
	if c, code := put(1, 3, randB(100), false); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("duplicate start: %d %s", c, code)
	}
	if c, code := put(3, 5, ct, false); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("overlap: %d %s", c, code)
	}
	if c, _ := put(4, 9, ct, false); c != 400 {
		t.Fatalf("end past the newest message: %d", c)
	}
	if c, _ := put(5, 4, ct, false); c != 400 {
		t.Fatalf("start after end: %d", c)
	}
	if c, _ := e.errOf("POST", "history/put", kat.tok, map[string]any{"channel": 2, "start": 1, "end": 1, "ct": ct}); c != 403 {
		t.Fatalf("history off: %d", c)
	}
	// replace needs a delete inside the segment since it was stored.
	if c, _ := put(1, 3, randB(100), true); c != 409 {
		t.Fatalf("replace without a delete: %d", c)
	}
	del := kat.say(m, 1, "delete 2")
	if c := e.call("POST", "messages/delete", kat.tok, map[string]any{"channel": 1, "seq": 2, "by": del.Seq}, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	ct2 := randB(90)
	if c, _ := put(1, 3, ct2, true); c != 204 {
		t.Fatalf("replace after a delete: %d", c)
	}
	var list struct {
		Items []struct {
			Start uint64 `json:"start"`
			End   uint64 `json:"end"`
			Size  int64  `json:"size"`
		} `json:"items"`
	}
	if c := e.call("GET", "history/list?channel=1", kat.tok, nil, &list); c != 200 || len(list.Items) != 1 || list.Items[0].Size != 90 {
		t.Fatalf("list: %+v", list)
	}
	var seg struct {
		Start uint64     `json:"start"`
		End   uint64     `json:"end"`
		CT    wire.Bytes `json:"ct"`
	}
	if c := e.call("GET", "history/get?channel=1&start=1", kat.tok, nil, &seg); c != 200 || !bytes.Equal(seg.CT, ct2) {
		t.Fatalf("get: %d", c)
	}
	if c, _ := e.errOf("GET", "history/get?channel=1&start=4", kat.tok, nil); c != 404 {
		t.Fatalf("get a missing segment: %d", c)
	}
	// Removing the channel deletes its segments.
	kat.mustAppend(m.ch, map[string]any{"op": "remove-channel", "id": 1})
	if s, err := e.st.Communities().Segments(t.Context(), "chat.test", 1, 0, 10); err != nil || len(s) != 0 {
		t.Fatalf("segments after remove-channel: %v %d", err, len(s))
	}
}

// spec/vectors/v2/code.json's join proof passes the checks POST join makes: a join-proof
// signed with the code's composite key, carried whole in k, over the commit's hash.
func TestVectorJoinProof(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/v2/code.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		CodeKey struct {
			PublicHex string `json:"public_hex"`
		} `json:"code_key"`
		Commit struct {
			SHA256Hex string `json:"sha256_hex"`
		} `json:"commit"`
		JoinProof struct {
			Signed string `json:"signed"`
		} `json:"join_proof"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	proof, err := wire.DecodeSignedV2([]byte(v.JoinProof.Signed))
	if err != nil || proof.T != "join-proof" {
		t.Fatalf("decode: %v", err)
	}
	pub, _ := hex.DecodeString(v.CodeKey.PublicHex)
	if !bytes.Equal(proof.K, pub) {
		t.Fatal("k isn't the code's composite key")
	}
	if _, err := proof.VerifyCompositeSelf("join-proof"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var pb struct {
		Commit wire.Bytes `json:"commit"`
		ID     string     `json:"id"`
		Epoch  uint64     `json:"epoch"`
	}
	sum, _ := hex.DecodeString(v.Commit.SHA256Hex)
	if err := proof.OpenClosed(&pb); err != nil || !bytes.Equal(pb.Commit, sum) || !wire.ValidIdentityID(pb.ID) {
		t.Fatalf("body: %v %+v", err, pb)
	}
	// One byte off, and it fails.
	bad := proof
	bad.B = strings.Replace(bad.B, `"epoch":`, `"epoch": `, 1)
	if _, err := bad.VerifyCompositeSelf("join-proof"); err == nil {
		t.Fatal("a changed body verified")
	}
}
