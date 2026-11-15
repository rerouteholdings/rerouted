package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// joined makes a community with kat as owner and the others joined by code.
func joined(t *testing.T, e *cmEnv, others ...*cmUser) (*cmUser, *made) {
	t.Helper()
	kat := e.user("kat")
	m := kat.create("chat.test", false)
	code := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code, 100))
	for _, u := range others {
		if c, cd := u.codeJoin(m, code, nil); c != 200 {
			t.Fatalf("%s joins: %d %s", u.handle, c, cd)
		}
	}
	return kat, m
}

// openStream signs a device's stream in, and reads up to "ready".
func (u *cmUser) openStream() *ws.Client {
	u.t.Helper()
	url := "ws" + strings.TrimPrefix(u.e.ts.URL, "http") + cmBase + "stream"
	cl, _, err := ws.Dial(url, "tieroute.v2")
	if err != nil {
		u.t.Fatal(err)
	}
	u.t.Cleanup(cl.Close)
	b, _ := wire.Marshal(map[string]any{"t": "auth", "token": u.tok})
	cl.SendText(b)
	for {
		f := readFrame(u.t, cl)
		if f["t"] == "ready" {
			return cl
		}
	}
}

func readFrame(t *testing.T, cl *ws.Client) map[string]any {
	t.Helper()
	b, err := cl.Next(5 * time.Second)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	var f map[string]any
	if err := wire.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// waitFrame reads frames until one of type typ.
func waitFrame(t *testing.T, cl *ws.Client, typ string) map[string]any {
	t.Helper()
	for range 50 {
		if f := readFrame(t, cl); f["t"] == typ {
			return f
		}
	}
	t.Fatalf("no %s frame", typ)
	return nil
}

// Bans and kicks (SPEC §16.7): the server removes the member, tells them, closes their
// stream with 4403, and refuses them from then on. Rank applies.
func TestCommunityBanKick(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi, mia, lee := e.user("ravi"), e.user("mia"), e.user("lee")
	kat, m := joined(t, e, ravi, mia, lee)
	kat.mustAppend(m.ch, map[string]any{"op": "add-role", "id": 1, "rank": 10, "perms": []string{"moderate"}, "name": sealed()},
		map[string]any{"op": "assign-roles", "member": mia.id, "roles": []uint64{1}})
	// Mia kicks lee; she can't kick kat, or ravi kick anyone.
	if c, _ := e.errOf("POST", "members/kick", mia.tok, map[string]any{"id": kat.id}); c != 403 {
		t.Fatalf("kicking the owner: %d", c)
	}
	if c, _ := e.errOf("POST", "members/kick", ravi.tok, map[string]any{"id": lee.id}); c != 403 {
		t.Fatalf("kick without moderate: %d", c)
	}
	cl := lee.openStream()
	if c := e.call("POST", "members/kick", mia.tok, map[string]any{"id": lee.id}, nil); c != 204 {
		t.Fatalf("kick: %d", c)
	}
	for {
		f := waitFrame(t, cl, "item")
		if bytes.Contains(must(wire.Marshal(f)), []byte(`"removed"`)) {
			break
		}
	}
	if _, err := cl.Next(3 * time.Second); err == nil {
		t.Fatal("the stream stayed open after a kick")
	} else if ce, ok := err.(*ws.CloseError); !ok || ce.Code != closeNotAllowed {
		t.Fatalf("closed with %v, want 4403", err)
	}
	if c, _ := e.errOf("POST", "send", lee.tok, map[string]any{"deliveries": []any{map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "app", "data": privMsg("x")}}}); c != 403 {
		t.Fatalf("a kicked member sent: %d", c)
	}
	if c, _ := e.errOf("GET", "chain", lee.tok, nil); c != 403 {
		t.Fatalf("a kicked member read the chain: %d", c)
	}
	if c, _ := e.errOf("POST", "members/kick", mia.tok, map[string]any{"id": lee.id}); c != 404 {
		t.Fatalf("kicking a non-member: %d", c)
	}
	// A ban: ravi is removed by the append, and can't sign in or join again.
	kat.mustAppend(m.ch, map[string]any{"op": "ban", "member": ravi.id})
	if ok, _ := e.srv.comm.byName["chat.test"].isMember(t.Context(), ravi.id); ok {
		t.Fatal("a banned identity is still a member")
	}
	if c, _ := e.errOf("GET", "inbox", ravi.tok, nil); c != 403 {
		t.Fatalf("a banned identity's session still works: %d", c)
	}
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	e.call("POST", "auth/challenge", "", map[string]any{"id": ravi.id, "key": edOf(ravi.dev), "home": "chat.test"}, &ch)
	auth := signed2(t, "auth", map[string]any{"id": ravi.id, "nonce": ch.Nonce, "server": "chat.test", "ts": time.Now().Unix()}, ravi.dev)
	if c, _ := e.errOf("POST", "auth/session", "", map[string]any{"auth": auth}); c != 403 {
		t.Fatalf("a banned identity signed in: %d", c)
	}
	// A domain ban covers chat.test's users, but never the owner.
	kat.mustAppend(m.ch, map[string]any{"op": "ban", "domain": "chat.test"})
	if ok, _ := e.srv.comm.byName["chat.test"].isMember(t.Context(), mia.id); ok {
		t.Fatal("a domain ban left a covered member")
	}
	if ok, _ := e.srv.comm.byName["chat.test"].isMember(t.Context(), kat.id); !ok {
		t.Fatal("a domain ban removed the owner")
	}
	// Leaving: the owner can't.
	if c, _ := e.errOf("POST", "leave", kat.tok, map[string]any{}); c != 403 {
		t.Fatalf("the owner left: %d", c)
	}
}

func must(b []byte, err error) []byte { return b }

// Restricted channels' groups (SPEC §16.5): registered for their see list only, and delivery
// stops when a member loses the role.
func TestCommunityRestrictedGroups(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi, mia := e.user("ravi"), e.user("mia")
	kat, m := joined(t, e, ravi, mia)
	kat.mustAppend(m.ch, map[string]any{"op": "add-role", "id": 1, "rank": 10, "perms": []string{"talk"}, "name": sealed()},
		map[string]any{"op": "assign-roles", "member": kat.id, "roles": []uint64{1}},
		map[string]any{"op": "assign-roles", "member": ravi.id, "roles": []uint64{1}},
		textChannel(1, []uint64{1}, []uint64{1}, 0))
	staff := &made{group: randB(32), ekey: newComposite(t), ch: m.ch}
	reg := map[string]any{"group": staff.group, "epoch": 0, "epoch-key": staff.ekey.Public().Bytes(), "info": []byte("i"), "tree": kat.uploadTree("staff-0")}
	reg["see"] = []uint64{2}
	if c, _ := e.errOf("POST", "groups/create", kat.tok, reg); c != 400 {
		t.Fatalf("a see list no channel has: %d", c)
	}
	reg["see"] = []uint64{1}
	if c, _ := e.errOf("POST", "groups/create", ravi.tok, reg); c != 403 {
		t.Fatalf("groups/create without administrate: %d", c)
	}
	if c := e.call("POST", "groups/create", kat.tok, reg, nil); c != 204 {
		t.Fatalf("groups/create: %d", c)
	}
	reg["group"] = randB(32)
	if c, code := e.errOf("POST", "groups/create", kat.tok, reg); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("a second group for the same see list: %d %s", c, code)
	}
	reg["group"] = staff.group
	reg["see"] = nil
	// Registration follows the see list.
	if c, _ := e.errOf("POST", "groups/register", mia.tok, map[string]any{"group": staff.group}); c != 403 {
		t.Fatalf("mia registered for staff: %d", c)
	}
	if c := e.call("POST", "groups/register", ravi.tok, map[string]any{"group": staff.group}, nil); c != 204 {
		t.Fatalf("ravi registers: %d", c)
	}
	// Channel 1 travels in the staff group, not the members group.
	if res := kat.say(m, 1, "x"); res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("a restricted channel's message in the members group: %+v", res)
	}
	if res := kat.say(staff, 1, "staff only"); res.Status != "sent" || res.Seq != 1 {
		t.Fatalf("staff message: %+v", res)
	}
	if res := mia.say(staff, 1, "x"); res.Error != wire.ErrCodeNotAllowed {
		t.Fatalf("mia in the staff group: %+v", res)
	}
	got := 0
	for _, d := range deliveries(t, ravi.inbox()) {
		if d.Channel == 1 {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("ravi got %d staff messages", got)
	}
	// Ravi loses the role: no more staff traffic.
	kat.mustAppend(m.ch, map[string]any{"op": "assign-roles", "member": ravi.id, "roles": []uint64{}})
	kat.say(staff, 1, "after")
	for _, d := range deliveries(t, ravi.inbox()) {
		if d.Channel == 1 {
			t.Fatal("ravi still gets the staff group")
		}
	}
	// Key packages: members claim each other's, 50 a day per claimant and target.
	if c := e.call("POST", "keypackages/upload", ravi.tok, map[string]any{"packages": []any{ravi.kp(ravi.dev, "r1")}}, nil); c != 200 {
		t.Fatalf("upload: %d", c)
	}
	var cl claimed
	if c := e.call("POST", "keypackages/claim", kat.tok, map[string]any{"id": ravi.id}, &cl); c != 200 || len(cl.Packages) != 1 || cl.Packages[0].LastResort {
		t.Fatalf("claim: %d %+v", c, cl)
	}
	stranger := e.user("lee")
	if c, _ := e.errOf("POST", "keypackages/claim", kat.tok, map[string]any{"id": stranger.id}); c != 403 {
		t.Fatalf("claiming a non-member's packages: %d", c)
	}
	if c, _ := e.errOf("POST", "keypackages/claim", stranger.tok, map[string]any{"id": ravi.id}); c != 403 {
		t.Fatalf("a non-member claimed: %d", c)
	}
	var count struct {
		Count int `json:"count"`
	}
	if c := e.call("GET", "keypackages/count", ravi.tok, nil, &count); c != 200 || count.Count != 0 {
		t.Fatalf("count: %d %d", c, count.Count)
	}
}

// The hub: the reg fallback, missed commits with proofs, trees by epoch, and stale commits.
func TestCommunityHub(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi := e.user("ravi")
	kat, m := joined(t, e, ravi)
	g := base64.RawURLEncoding.EncodeToString(m.group)
	var commits struct {
		Items []struct {
			Epoch uint64   `json:"epoch"`
			Proof wire.Raw `json:"proof"`
		} `json:"items"`
	}
	if c := e.call("GET", "groups/"+g+"/commits?after=-1", ravi.tok, nil, &commits); c != 200 || len(commits.Items) != 1 || commits.Items[0].Proof == nil {
		t.Fatalf("commits: %d %+v", c, commits)
	}
	// A commit to the members group needs its tree and GroupInfo.
	data := privMsg("no tree")
	sum := sha256Of(data)
	creq := signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": m.epoch, "hash": sum, "next": newComposite(t).Public().Bytes()}, m.ekey)
	if res := kat.send(map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "commit", "data": data, "commit": creq}); res.Error != wire.ErrCodeBadRequest {
		t.Fatalf("members-group commit without a tree: %+v", res)
	}
	// Signed with the wrong epoch key.
	wrong := &made{group: m.group, epoch: m.epoch, ekey: newComposite(t), ch: m.ch}
	if _, res := kat.commit(wrong, nil, nil); res.Error != wire.ErrCodeBadSignature {
		t.Fatalf("commit with the wrong epoch key: %+v", res)
	}
	// The reg fallback: the hub awaits the epoch's key.
	data = privMsg("reg commit")
	sum = sha256Of(data)
	reg := newComposite(t)
	creq = signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": m.epoch, "hash": sum, "reg": reg.Public().Bytes()}, m.ekey)
	tree := kat.uploadTree("reg-tree")
	if res := kat.send(map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "commit", "data": data, "commit": creq, "info": []byte("i"), "tree": tree}); res.Status != "sent" {
		t.Fatalf("reg commit: %+v", res)
	}
	m.epoch++
	if _, res := ravi.commit(m, nil, nil); res.Error != wire.ErrCodeAwaitingKey {
		t.Fatalf("commit while awaiting: %+v", res)
	}
	next := newComposite(t)
	ek := signedFull2(t, "epoch-key", map[string]any{"group": m.group, "epoch": m.epoch, "next": next.Public().Bytes()}, reg)
	if c := e.call("POST", "groups/epoch-key", kat.tok, map[string]any{"key": ek}, nil); c != 204 {
		t.Fatalf("epoch-key: %d", c)
	}
	if c := e.call("POST", "groups/epoch-key", kat.tok, map[string]any{"key": ek}, nil); c != 204 {
		t.Fatalf("epoch-key retried: %d", c)
	}
	m.ekey = next
	if _, res := ravi.commit(m, nil, nil); res.Status != "sent" {
		t.Fatalf("commit after the key: %+v", res)
	}
	// The tree of each epoch, for registered devices.
	resp := e.raw("GET", "groups/"+g+"/tree?epoch=2", ravi.tok)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "reg-tree" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("tree at epoch 2: %d %q", resp.StatusCode, b)
	}
	var info struct {
		Epoch uint64     `json:"epoch"`
		Tree  wire.Bytes `json:"tree"`
	}
	if c := e.call("GET", "groups/"+g+"/info", ravi.tok, nil, &info); c != 200 || info.Epoch != m.epoch {
		t.Fatalf("info: %d %+v", c, info)
	}
	if c, _ := e.errOf("GET", "groups/"+g+"/info", e.user("lee").tok, nil); c != 403 {
		t.Fatalf("GroupInfo for a stranger: %d", c)
	}
	// A known group ID can't be registered again.
	if c, code := e.errOf("POST", "groups/create", kat.tok, map[string]any{"group": m.group, "epoch": 0, "epoch-key": newComposite(t).Public().Bytes(), "info": []byte("i"), "tree": tree, "see": []uint64{1}}); c != 409 && c != 400 {
		t.Fatalf("re-registering a group: %d %s", c, code)
	}
	// Trees are octet-stream, at most 32 MiB.
	if c, _ := e.do("POST", "tree/upload", kat.tok, wire.MediaType, []byte("{}"), nil); c != 415 {
		t.Fatalf("tree as JSON: %d", c)
	}
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func (e *cmEnv) raw(method, path, token string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+cmBase+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// Files: members with talk upload; deletes with their message answer 410 removed.
func TestCommunityMedia(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) { c.CommunityFileQuota = 1000 })
	ravi := e.user("ravi")
	kat, m := joined(t, e, ravi)
	kat.mustAppend(m.ch, textChannel(1, []uint64{0}, []uint64{0}, 0))
	var up struct {
		ID     wire.Bytes `json:"id"`
		SHA256 wire.Bytes `json:"sha256"`
		Size   int64      `json:"size"`
	}
	if c, b := e.do("POST", "media/upload", ravi.tok, "application/octet-stream", []byte("encrypted file"), &up); c != 200 || up.Size != 14 {
		t.Fatalf("upload: %d %s", c, b)
	}
	resp := e.raw("GET", "media/"+base64.RawURLEncoding.EncodeToString(up.ID), kat.tok)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "encrypted file" {
		t.Fatalf("download: %d %q", resp.StatusCode, b)
	}
	if c, _ := e.errOf("GET", "media/"+base64.RawURLEncoding.EncodeToString(up.ID), e.user("lee").tok, nil); c != 403 {
		t.Fatalf("a non-member downloaded: %d", c)
	}
	if c, code := e.errOf("POST", "media/upload", ravi.tok, map[string]any{}); c != 415 || code != wire.ErrCodeBadContentType {
		t.Fatalf("JSON upload: %d %s", c, code)
	}
	// The community's quota.
	if c, b := e.do("POST", "media/upload", ravi.tok, "application/octet-stream", make([]byte, 2000), nil); c != 413 || !bytes.Contains(b, []byte(wire.ErrCodeOverQuota)) {
		t.Fatalf("over quota: %d %s", c, b)
	}
	// Deleted with its message.
	msg := ravi.say(m, 1, "with a file")
	del := ravi.say(m, 1, "delete it")
	if c := e.call("POST", "messages/delete", ravi.tok, map[string]any{"channel": 1, "seq": msg.Seq, "by": del.Seq, "media": [][]byte{up.ID}}, nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if c, code := e.errOf("GET", "media/"+base64.RawURLEncoding.EncodeToString(up.ID), kat.tok, nil); c != 410 || code != wire.ErrCodeRemoved {
		t.Fatalf("a deleted message's file: %d %s", c, code)
	}
}

// Reports go to the community's moderators, readable.
func TestCommunityReports(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi := e.user("ravi")
	kat, _ := joined(t, e, ravi)
	rep := map[string]any{"reporter": ravi.id, "reported": kat.id, "reason": "spam"}
	if c, _ := e.errOf("POST", "report", ravi.tok, map[string]any{"report": map[string]any{"reporter": kat.id, "reported": ravi.id, "reason": "x"}}); c != 403 {
		t.Fatalf("a report in someone else's name: %d", c)
	}
	var res struct {
		ID wire.Bytes `json:"id"`
	}
	if c := e.call("POST", "report", ravi.tok, map[string]any{"report": rep, "at": []any{map[string]any{"channel": 1, "seq": 3}}}, &res); c != 200 || len(res.ID) != 16 {
		t.Fatalf("report: %d", c)
	}
	if c, _ := e.errOf("GET", "reports", ravi.tok, nil); c != 403 {
		t.Fatalf("a member without moderate read reports: %d", c)
	}
	var list struct {
		Items []struct {
			ID     wire.Bytes `json:"id"`
			Report struct {
				Reason string `json:"reason"`
			} `json:"report"`
			At []struct {
				Seq uint64 `json:"seq"`
			} `json:"at"`
		} `json:"items"`
	}
	if c := e.call("GET", "reports", kat.tok, nil, &list); c != 200 || len(list.Items) != 1 || list.Items[0].Report.Reason != "spam" || list.Items[0].At[0].Seq != 3 {
		t.Fatalf("reports: %d %+v", c, list)
	}
	if c := e.call("POST", "reports/close", kat.tok, map[string]any{"id": res.ID}, nil); c != 204 {
		t.Fatalf("close: %d", c)
	}
	if c, _ := e.errOf("POST", "reports/close", kat.tok, map[string]any{"id": res.ID}); c != 404 {
		t.Fatalf("close twice: %d", c)
	}
}

// Moving a community (SPEC §16.2.3 set-home, §16.6): the owner asks the new server for a
// reservation, without which the old one records no set-home; the new server takes the whole
// chain; the old one refuses messages and appends with wrong-home, and answers 410 to all
// but the chain and commits.
func TestCommunityMove(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = append(c.Communities, config.Community{Name: "new.test", URL: "https://new.test"})
	})
	ravi := e.user("ravi")
	kat, m := joined(t, e, ravi)
	kat.mustAppend(m.ch, textChannel(1, []uint64{0}, []uint64{0}, 0))
	// Only the owner moves it.
	if c, _ := ravi.appendOps(m.ch, map[string]any{"op": "set-home", "server": "new.test"}); c != 403 {
		t.Fatalf("set-home by a member: %d", c)
	}
	for i := 1; i <= 2; i++ {
		if res := ravi.say(m, 1, "before the move"); res.Seq != uint64(i) {
			t.Fatalf("message %d before the move: %+v", i, res)
		}
	}
	var chain struct {
		Entries []wire.Raw `json:"entries"`
	}
	if c := e.call("GET", "chain", kat.tok, nil, &chain); c != 200 {
		t.Fatalf("the old server's chain: %d", c)
	}
	setHome := kat.sign(kat.next(m.ch, map[string]any{"op": "set-home", "server": "new.test"}))
	chain.Entries = append(chain.Entries, setHome)
	// Without a reservation from new.test, the old server records nothing, and the community
	// goes on there (SPEC §16.6).
	if c, code := e.errOf("POST", "chain/append", kat.tok, map[string]any{"entry": setHome}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("set-home without a reservation: %d %s", c, code)
	}
	if res := ravi.say(m, 1, "still here"); res.Seq != 3 {
		t.Fatalf("a message after a refused set-home: %+v", res)
	}
	// The owner asks new.test first: everything a move-in checks, then a reservation.
	e.host = "new.test"
	kn, rn := e.signIn(kat.v2User), e.signIn(ravi.v2User)
	lee := e.signIn(newV2User(t, e.ts, "lee", "chat.test"))
	list := func(by *cmUser, ids ...string) wire.Raw {
		return signed2(t, "community-members", map[string]any{"community": m.ch.id, "members": ids, "ts": time.Now().Unix()}, by.dev)
	}
	check := func(tok string, body map[string]any) (int, string, wire.Raw) {
		var res struct {
			Reservation wire.Raw `json:"reservation"`
			wire.Error
		}
		body["check"] = true
		c := e.call("POST", "create", tok, body, &res)
		return c, res.Code, res.Reservation
	}
	if c, code, _ := check(kn.tok, map[string]any{"chain": chain.Entries, "code": "not-the-code", "members": list(kn, ravi.id)}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a check without the creation code: %d %s", c, code)
	}
	if c, _, _ := check(rn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(rn, ravi.id)}); c != 403 {
		t.Fatalf("a check by a member: %d", c)
	}
	if c, _, _ := check(kn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(kn, ravi.id), "seqs": []channelSeq{{1, 3}}}); c != 400 {
		t.Fatalf("a check with seqs: %d", c)
	}
	c, _, resv := check(kn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(kn, ravi.id)})
	if c != 200 || resv == nil {
		t.Fatalf("the check: %d", c)
	}
	// It stored no community, and holds the name for this one: another can't be created.
	if c, _ := e.errOf("GET", "preview", "", nil); c != 404 {
		t.Fatalf("preview after a check: %d", c)
	}
	other := lee.sign(map[string]any{"seq": 0, "ts": time.Now().Unix(), "by": lee.id, "ops": []any{createOp("new.test", true, false)}})
	reg := map[string]any{"group": randB(32), "epoch": 0, "epoch-key": newComposite(t).Public().Bytes(), "info": []byte("i"), "tree": lee.uploadTree("held")}
	if c, code := e.errOf("POST", "create", lee.tok, map[string]any{"entry": other, "group": reg, "code": testCreateCode}); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("a create on a name held for a move: %d %s", c, code)
	}
	// Back on the old server: a reservation that isn't new.test's, or is for another entry,
	// records nothing.
	e.host = ""
	forged := signed2(t, "community-move-reservation", map[string]any{"community": m.ch.id, "server": "new.test", "entry": randB(32), "exp": time.Now().Unix() + 600}, kat.dev)
	if c, code := e.errOf("POST", "chain/append", kat.tok, map[string]any{"entry": setHome, "reservation": forged}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a reservation signed with a device key: %d %s", c, code)
	}
	otherHome := kat.sign(map[string]any{"community": m.ch.id, "seq": m.ch.seq + 1, "prev": m.ch.head, "ts": time.Now().Unix() + 1, "by": kat.id, "ops": []any{map[string]any{"op": "set-home", "server": "new.test"}}})
	if c, code := e.errOf("POST", "chain/append", kat.tok, map[string]any{"entry": otherHome, "reservation": resv}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a reservation for another entry: %d %s", c, code)
	}
	// The set-home with its reservation: the answer gives each text channel's last number,
	// for the new server.
	var moved struct {
		Seq  uint64       `json:"seq"`
		Head wire.Bytes   `json:"head"`
		Seqs []channelSeq `json:"seqs"`
	}
	if c := e.call("POST", "chain/append", kat.tok, map[string]any{"entry": setHome, "reservation": resv}, &moved); c != 200 || len(moved.Seqs) != 1 || moved.Seqs[0] != (channelSeq{1, 3}) {
		t.Fatalf("set-home: %d %+v", c, moved)
	}
	// A retry after a lost answer gets the same answer.
	var again struct {
		Seqs []channelSeq `json:"seqs"`
	}
	if c := e.call("POST", "chain/append", kat.tok, map[string]any{"entry": setHome, "reservation": resv}, &again); c != 200 || len(again.Seqs) != 1 || again.Seqs[0] != moved.Seqs[0] {
		t.Fatalf("set-home again: %d %+v", c, again)
	}
	m.ch.seq, m.ch.head = moved.Seq, moved.Head
	if c, code := e.errOf("GET", "preview", "", nil); c != 410 || code != wire.ErrCodeExpired {
		t.Fatalf("old preview: %d %s", c, code)
	}
	if c, code := kat.appendOps(m.ch, map[string]any{"op": "set-name", "name": "x"}); c != 409 || code != wire.ErrCodeWrongHome {
		t.Fatalf("append after set-home: %d %s", c, code)
	}
	if res := ravi.say(m, 1, "x"); res.Error != wire.ErrCodeWrongHome {
		t.Fatalf("message after the move: %+v", res)
	}
	if c, _ := e.errOf("GET", "history/list?channel=1", kat.tok, nil); c != 410 {
		t.Fatalf("other endpoints after the move: %d", c)
	}
	// Commits still go through, for the hub handoff.
	if _, res := kat.commit(m, nil, nil); res.Status != "sent" {
		t.Fatalf("a commit after the move: %+v", res)
	}
	// The new server takes the chain from the owner.
	e.host = "new.test"
	if c, _ := e.errOf("POST", "create", rn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(rn, ravi.id)}); c != 403 {
		t.Fatalf("a move-in by a member: %d", c)
	}
	if c, _ := e.errOf("POST", "create", kn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode}); c != 400 {
		t.Fatalf("a move-in without its member list: %d", c)
	}
	if c, _ := e.errOf("POST", "create", kn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(rn, ravi.id)}); c != 403 {
		t.Fatalf("a member list signed by someone other than the owner: %d", c)
	}
	if c, code := e.errOf("POST", "create", kn.tok, map[string]any{"chain": chain.Entries[:len(chain.Entries)-1], "code": testCreateCode, "members": list(kn, ravi.id)}); c != 400 || code != wire.ErrCodeInvalidChain {
		t.Fatalf("a chain that doesn't end in set-home here: %d %s", c, code)
	}
	var res struct {
		ID wire.Bytes `json:"id"`
	}
	if c, _ := e.errOf("POST", "create", kn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(kn, ravi.id), "seqs": []channelSeq{{9, 4}}}); c != 400 {
		t.Fatalf("seqs for a channel the chain doesn't have: %d", c)
	}
	if c := e.call("POST", "create", kn.tok, map[string]any{"chain": chain.Entries, "code": testCreateCode, "members": list(kn, ravi.id), "seqs": moved.Seqs}, &res); c != 200 || !bytes.Equal(res.ID, m.ch.id) {
		t.Fatalf("move-in: %d", c)
	}
	var pv struct {
		Name string `json:"name"`
	}
	if c := e.call("GET", "preview", "", nil, &pv); c != 200 || pv.Name != "Night shift" {
		t.Fatalf("new preview: %d", c)
	}
	// The owner hands the members group over; members join the list as they register.
	tree := kn.uploadTree("handoff")
	handed := randB(32)
	if c := e.call("POST", "groups/create", kn.tok, map[string]any{"group": handed, "epoch": 5, "epoch-key": newComposite(t).Public().Bytes(), "info": []byte("i"), "tree": tree}, nil); c != 204 {
		t.Fatalf("hub handoff: %d", c)
	}
	if c, _ := e.errOf("GET", "chain", rn.tok, nil); c != 403 {
		t.Fatalf("ravi read the moved chain before registering: %d", c)
	}
	// A stranger isn't on the list, and can't join by registering.
	if c, code := e.errOf("POST", "groups/register", lee.tok, map[string]any{"group": handed}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("a stranger registered after the move: %d %s", c, code)
	}
	if c, _ := e.errOf("GET", "chain", lee.tok, nil); c != 403 {
		t.Fatalf("a stranger became a member: %d", c)
	}
	if c := e.call("POST", "groups/register", rn.tok, map[string]any{"group": handed}, nil); c != 204 {
		t.Fatalf("ravi registers after the move: %d", c)
	}
	if c := e.call("GET", "chain", rn.tok, nil, nil); c != 200 {
		t.Fatalf("ravi as a member after registering: %d", c)
	}
	// Numbering goes on from the old server's.
	m.group = handed
	if res := rn.say(m, 1, "after the move"); res.Seq != 4 {
		t.Fatalf("the first message after the move: %+v", res)
	}
	// Appends continue on the new server, after the set-home.
	kn.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "Moved"})
}

// Former members' chains stay available (SPEC §16.1): a member catching up late checks a
// join by someone since kicked, banned, or gone. Never an identity that wasn't a member.
func TestCommunityFormerMemberChains(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi, lee, mia := e.user("ravi"), e.user("lee"), e.user("mia")
	kat, m := joined(t, e, ravi, lee, mia)
	sam := e.user("sam")
	if c := e.call("POST", "members/kick", kat.tok, map[string]any{"id": lee.id}, nil); c != 204 {
		t.Fatalf("kick: %d", c)
	}
	if c := e.call("POST", "leave", ravi.tok, map[string]any{}, nil); c != 204 {
		t.Fatalf("leave: %d", c)
	}
	kat.mustAppend(m.ch, map[string]any{"op": "ban", "member": mia.id})
	var mc struct {
		Entries []wire.Raw `json:"entries"`
	}
	for who, u := range map[string]*cmUser{"kicked": lee, "left": ravi, "banned": mia} {
		if c := e.call("GET", "members/"+u.id+"/chain", kat.tok, nil, &mc); c != 200 || len(mc.Entries) == 0 {
			t.Fatalf("the chain of a member who %s: %d", who, c)
		}
		if st, err := decodeChainFor(wire.V2, [][]byte{mc.Entries[0]}); err != nil || st.ID != u.id {
			t.Fatalf("the chain of a member who %s doesn't check out: %v", who, err)
		}
	}
	if c, code := e.errOf("GET", "members/"+sam.id+"/chain", kat.tok, nil); c != 404 || code != wire.ErrCodeNotFound {
		t.Fatalf("the chain of someone never a member: %d %s", c, code)
	}
	// Still for members only: the kicked identity can't read them.
	if c, _ := e.errOf("GET", "members/"+ravi.id+"/chain", lee.tok, nil); c != 403 {
		t.Fatalf("a kicked identity read a chain: %d", c)
	}
}

// The old server numbers no message after the set-home (SPEC §16.6): messages sent while the
// set-home is appended are either numbered within the seqs it answers with, or refused.
func TestCommunityMoveStopsSequencing(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = append(c.Communities, config.Community{Name: "new.test", URL: "https://new.test"})
	})
	ravi := e.user("ravi")
	kat, m := joined(t, e, ravi)
	kat.mustAppend(m.ch, textChannel(1, []uint64{0}, []uint64{0}, 0))
	var chain struct {
		Entries []wire.Raw `json:"entries"`
	}
	if c := e.call("GET", "chain", kat.tok, nil, &chain); c != 200 {
		t.Fatalf("chain: %d", c)
	}
	setHome := kat.sign(kat.next(m.ch, map[string]any{"op": "set-home", "server": "new.test"}))
	e.host = "new.test"
	kn := e.signIn(kat.v2User)
	members := signed2(t, "community-members", map[string]any{"community": m.ch.id, "members": []string{kat.id, ravi.id}, "ts": time.Now().Unix()}, kat.dev)
	var res struct {
		Reservation wire.Raw `json:"reservation"`
	}
	if c := e.call("POST", "create", kn.tok, map[string]any{"chain": append(chain.Entries, setHome), "code": testCreateCode, "members": members, "check": true}, &res); c != 200 {
		t.Fatalf("check: %d", c)
	}
	e.host = ""
	var mu sync.Mutex
	var numbered []uint64
	refused := 0
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r := ravi.say(m, 1, "racing the move")
				mu.Lock()
				switch {
				case r.Status == "sent":
					numbered = append(numbered, r.Seq)
				case r.Error == wire.ErrCodeWrongHome:
					refused++
				}
				mu.Unlock()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	var moved struct {
		Seqs []channelSeq `json:"seqs"`
	}
	if c := e.call("POST", "chain/append", kat.tok, map[string]any{"entry": setHome, "reservation": res.Reservation}, &moved); c != 200 || len(moved.Seqs) != 1 {
		t.Fatalf("set-home: %d %+v", c, moved)
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	if len(numbered) == 0 || refused == 0 {
		t.Fatalf("the race didn't happen: %d numbered, %d refused", len(numbered), refused)
	}
	for _, n := range numbered {
		if n > moved.Seqs[0].Seq {
			t.Fatalf("message %d numbered after the set-home's last, %d", n, moved.Seqs[0].Seq)
		}
	}
}
