package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Community servers (SPEC §16, spec/api/community.md), driven as a client would, with stand-in
// MLS bytes: the server never reads them.

const (
	cmBase         = "/.well-known/tieroute/v2/community/"
	testCreateCode = "create-a-community"
)

// cmEnv is a server whose own name, chat.test, is also a community server, unless host
// names a community-only name, reached by its Host header.
type cmEnv struct {
	t    *testing.T
	ts   *httptest.Server
	host string
	st   store.Store
	srv  *Server
}

func newCommunityEnv(t *testing.T, change func(*config.Config)) *cmEnv {
	t.Helper()
	dir := t.TempDir()
	st := newStore(t)
	cfg := &config.Config{Name: "chat.test", Handles: "chat.test", Registration: "invite", RegistrationCode: testRegCode, DataDir: dir, Dev: true,
		Peers: map[string]string{}, Communities: []config.Community{{Name: "chat.test", URL: "https://chat.test"}}, CommunityCode: testCreateCode, CommunityFileDays: 30}
	change(cfg)
	testSFU(t, cfg)
	key := testKey(t, dir, cfg)
	s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		if s.comm.sfu != nil {
			s.comm.sfu.Close()
		}
	})
	for _, cm := range cfg.Communities {
		cfg.Peers[cm.Name] = ts.URL
	}
	cfg.Peers["chat.test"] = ts.URL
	return &cmEnv{t: t, ts: ts, st: st, srv: s}
}

func (e *cmEnv) do(method, path, token, ctype string, body []byte, out any) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.ts.URL+cmBase+path, rd)
	if e.host != "" {
		req.Host = e.host
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && len(b) > 0 && resp.Header.Get("Content-Type") == wire.MediaType {
		if err := wire.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: decode: %v (%s)", method, path, err, b)
		}
	}
	return resp.StatusCode, b
}

// call sends a JSON body (or none) and decodes the answer into out.
func (e *cmEnv) call(method, path, token string, body any, out any) int {
	e.t.Helper()
	var b []byte
	ctype := ""
	if body != nil {
		var err error
		if b, err = wire.Marshal(body); err != nil {
			e.t.Fatal(err)
		}
		ctype = wire.MediaType
	}
	c, _ := e.do(method, path, token, ctype, b, out)
	return c
}

// errOf calls and returns the status and error code.
func (e *cmEnv) errOf(method, path, token string, body any) (int, string) {
	e.t.Helper()
	var res wire.Error
	c := e.call(method, path, token, body, &res)
	return c, res.Code
}

// cmUser is a wire version 2 identity on chat.test, signed in to the community.
type cmUser struct {
	*v2User
	e    *cmEnv
	tok  string
	tree []byte // the tree its joins name, uploaded once: non-members may upload 5 an hour
}

func (u *cmUser) joinTree() []byte {
	if u.tree == nil {
		u.tree = u.uploadTree("tree-join-" + u.id)
	}
	return u.tree
}

func (e *cmEnv) user(name string) *cmUser {
	e.t.Helper()
	u := newV2User(e.t, e.ts, name, "chat.test")
	return e.signIn(u)
}

func (e *cmEnv) signIn(u *v2User) *cmUser {
	e.t.Helper()
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	if c := e.call("POST", "auth/challenge", "", map[string]any{"id": u.id, "key": edOf(u.dev), "home": "chat.test"}, &ch); c != 200 {
		e.t.Fatalf("community challenge: %d", c)
	}
	server := "chat.test"
	if e.host != "" {
		server = e.host
	}
	auth := signed2(e.t, "auth", map[string]any{"id": u.id, "nonce": ch.Nonce, "server": server, "ts": time.Now().Unix()}, u.dev)
	var sess struct {
		Token  string `json:"token"`
		Member bool   `json:"member"`
	}
	if c := e.call("POST", "auth/session", "", map[string]any{"auth": auth}, &sess); c != 200 {
		e.t.Fatalf("community session: %d", c)
	}
	return &cmUser{v2User: u, e: e, tok: sess.Token}
}

// cmChain tracks the community chain's head, as a client does.
type cmChain struct {
	id   []byte
	seq  uint64
	head []byte
}

func randB(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func sealed() map[string]any { return map[string]any{"key": randB(32), "ct": randB(40)} }

// sign signs a community entry with the user's device key.
func (u *cmUser) sign(body map[string]any) wire.Raw {
	return signed2(u.t, "community-entry", body, u.dev)
}

// next is the body of the entry after ch's head.
func (u *cmUser) next(ch *cmChain, ops ...any) map[string]any {
	return map[string]any{"community": ch.id, "seq": ch.seq + 1, "prev": ch.head, "ts": time.Now().Unix(), "by": u.id, "ops": ops}
}

// appendOps appends an entry, moving ch's head on success.
func (u *cmUser) appendOps(ch *cmChain, ops ...any) (int, string) {
	u.t.Helper()
	return u.appendRaw(ch, u.sign(u.next(ch, ops...)))
}

func (u *cmUser) appendRaw(ch *cmChain, raw wire.Raw) (int, string) {
	u.t.Helper()
	var res struct {
		Seq  uint64     `json:"seq"`
		Head wire.Bytes `json:"head"`
		wire.Error
	}
	c := u.e.call("POST", "chain/append", u.tok, map[string]any{"entry": raw}, &res)
	if c == 200 {
		ch.seq, ch.head = res.Seq, res.Head
	}
	return c, res.Code
}

func (u *cmUser) mustAppend(ch *cmChain, ops ...any) {
	u.t.Helper()
	if c, code := u.appendOps(ch, ops...); c != 200 {
		u.t.Fatalf("append %v: %d %s", ops, c, code)
	}
}

// uploadTree uploads a stand-in ratchet tree and returns its hash.
func (u *cmUser) uploadTree(data string) []byte {
	u.t.Helper()
	var res struct {
		Hash wire.Bytes `json:"hash"`
		Size int64      `json:"size"`
	}
	c, b := u.e.do("POST", "tree/upload", u.tok, "application/octet-stream", []byte(data), &res)
	if c != 200 {
		u.t.Fatalf("tree/upload: %d %s", c, b)
	}
	sum := sha256.Sum256([]byte(data))
	if !bytes.Equal(res.Hash, sum[:]) || res.Size != int64(len(data)) {
		u.t.Fatalf("tree/upload answered %x, %d", res.Hash, res.Size)
	}
	return res.Hash
}

// made is what a test's owner made: the chain, the members group, its epoch key.
type made struct {
	ch    *cmChain
	group []byte
	epoch uint64
	ekey  *wire.CompositePrivateKey // the members group's current epoch key
}

func createOp(server string, public, approval bool) map[string]any {
	return map[string]any{"op": "create", "server": server, "name": "Night shift", "desc": "A place", "public": public, "approval": approval, "everyone": []string{"talk", "invite"}}
}

// create makes the community, with its members group at epoch 0.
func (u *cmUser) create(server string, approval bool) *made {
	u.t.Helper()
	tree := u.uploadTree("tree-epoch-0")
	m := &made{group: randB(32), ekey: newComposite(u.t)}
	entry := u.sign(map[string]any{"seq": 0, "ts": time.Now().Unix(), "by": u.id, "ops": []any{createOp(server, true, approval)}})
	var res struct {
		ID wire.Bytes `json:"id"`
	}
	reg := map[string]any{"group": m.group, "epoch": 0, "epoch-key": m.ekey.Public().Bytes(), "info": []byte("info-0"), "tree": tree}
	if c := u.e.call("POST", "create", u.tok, map[string]any{"entry": entry, "group": reg, "code": testCreateCode}, &res); c != 200 {
		u.t.Fatalf("create: %d", c)
	}
	sum := sha256.Sum256(entry)
	if !bytes.Equal(res.ID, sum[:]) {
		u.t.Fatal("the community's identifier isn't the hash of its create entry")
	}
	m.ch = &cmChain{id: res.ID, seq: 0, head: res.ID}
	return m
}

// privMsg is stand-in MLS bytes framed as a PrivateMessage; pubMsg as a PublicMessage.
func privMsg(s string) []byte { return append([]byte{0, 1, 0, 2}, s...) }
func pubMsg(s string) []byte  { return append([]byte{0, 1, 0, 1}, s...) }

// commit sends a commit to group at epoch, signed with ekey; on success it returns the next
// epoch's key.
func (u *cmUser) commit(m *made, welcomes []any, extra map[string]any) (*wire.CompositePrivateKey, cResult) {
	u.t.Helper()
	data := privMsg("commit-" + strconv.FormatUint(m.epoch, 10) + "-" + base64.RawURLEncoding.EncodeToString(randB(4)))
	sum := sha256.Sum256(data)
	next := newComposite(u.t)
	creq := signedFull2(u.t, "commit-request", map[string]any{"group": m.group, "epoch": m.epoch, "hash": sum[:], "next": next.Public().Bytes()}, m.ekey)
	tree := u.uploadTree("tree-" + strconv.FormatUint(m.epoch+1, 10))
	d := map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "commit", "data": data, "commit": creq, "info": []byte("info"), "tree": tree}
	if welcomes != nil {
		d["welcomes"] = welcomes
	}
	for k, v := range extra {
		if v == nil { // drops the field
			delete(d, k)
			continue
		}
		d[k] = v
	}
	res := u.send(d)
	if res.Status == "sent" {
		m.epoch++
		m.ekey = next
	}
	return next, res
}

func (u *cmUser) send(d map[string]any) cResult {
	u.t.Helper()
	var res struct {
		Results []cResult `json:"results"`
	}
	if c := u.e.call("POST", "send", u.tok, map[string]any{"deliveries": []any{d}}, &res); c != 200 {
		u.t.Fatalf("send: %d", c)
	}
	return res.Results[0]
}

// say sends an application message to a channel in the members group.
func (u *cmUser) say(m *made, channel uint64, text string) cResult {
	u.t.Helper()
	return u.send(map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": m.epoch, "mls": "app", "channel": channel, "data": privMsg(text)})
}

type cmItem struct {
	Cursor   string   `json:"cursor"`
	TS       int64    `json:"ts"`
	Delivery wire.Raw `json:"delivery"`
	Notice   wire.Raw `json:"notice"`
}

func (u *cmUser) inbox() []cmItem {
	u.t.Helper()
	var res struct {
		Items []cmItem `json:"items"`
	}
	if c := u.e.call("GET", "inbox", u.tok, nil, &res); c != 200 {
		u.t.Fatalf("inbox: %d", c)
	}
	return res.Items
}

// deliveries decodes the deliveries in an inbox.
func deliveries(t *testing.T, items []cmItem) []cDelivery {
	t.Helper()
	var out []cDelivery
	for _, it := range items {
		if it.Delivery == nil {
			continue
		}
		var d cDelivery
		if err := wire.Unmarshal(it.Delivery, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// codeJoin joins with a code key: GroupInfo and tree by code access, the external commit
// with its join proof and code-signed commit-request.
func (u *cmUser) codeJoin(m *made, code *wire.CompositePrivateKey, mutate func(proof map[string]any, d map[string]any)) (int, string) {
	u.t.Helper()
	q := "?code=" + base64.RawURLEncoding.EncodeToString(code.Public().Hash())
	var info struct {
		Epoch uint64 `json:"epoch"`
	}
	if c := u.e.call("GET", "groups/"+base64.RawURLEncoding.EncodeToString(m.group)+"/info"+q, u.tok, nil, &info); c != 200 {
		return c, "info"
	}
	data := pubMsg("external-commit-" + u.id)
	sum := sha256.Sum256(data)
	proof := map[string]any{"commit": sum[:], "id": u.id, "epoch": info.Epoch}
	next := newComposite(u.t)
	d := map[string]any{"group": m.group, "epoch": info.Epoch, "data": data, "info": []byte("info-join"), "tree": u.joinTree()}
	if mutate != nil {
		mutate(proof, d)
	}
	d["proof"] = signedFull2(u.t, "join-proof", proof, code)
	if _, ok := d["commit"]; !ok {
		d["commit"] = signedFull2(u.t, "commit-request", map[string]any{"group": m.group, "epoch": info.Epoch, "hash": sum[:], "next": next.Public().Bytes()}, code)
	}
	var res struct {
		Receipt wire.Raw `json:"receipt"`
		wire.Error
	}
	c := u.e.call("POST", "join"+q, u.tok, d, &res)
	if c == 200 {
		m.epoch = info.Epoch + 1
		m.ekey = next
	}
	return c, res.Code
}

func addCodeOp(k *wire.CompositePrivateKey, uses int) map[string]any {
	return map[string]any{"op": "add-code", "key": k.Public().Bytes(), "exp": time.Now().Unix() + 3600, "uses": uses}
}

func textChannel(id uint64, see, write []uint64, slow int) map[string]any {
	return map[string]any{"op": "add-channel", "id": id, "name": sealed(), "see": see, "write": write, "kind": "text", "history": true, "slow": slow}
}

func voiceChannel(id uint64, max, cast int) map[string]any {
	return map[string]any{"op": "add-channel", "id": id, "name": sealed(), "see": []uint64{0}, "write": []uint64{0}, "kind": "voice", "max": max, "cast": cast}
}

// ---- tests ----

// The server document of a name that's both a homeserver and a community server lists both
// roles; a community-only name answers as its own server, with its own key, and 501 on S2S.
func TestCommunityServerDocs(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = append(c.Communities, config.Community{Name: "games.test", URL: "https://games.test"})
	})
	var doc serverDoc
	resp, err := http.Get(e.ts.URL + "/.well-known/tieroute/server")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := wire.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Roles) != 2 || doc.Roles[1] != "community" || doc.APIs[1].Community != "https://chat.test/.well-known/tieroute/v2/community/" {
		t.Fatalf("dual doc: %+v", doc)
	}
	req, _ := http.NewRequest("GET", e.ts.URL+"/.well-known/tieroute/server", nil)
	req.Host = "games.test"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var g serverDoc
	if err := wire.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if g.Name != "games.test" || len(g.Roles) != 1 || g.Roles[0] != "community" || len(g.APIs) != 1 || g.APIs[0].V != 2 ||
		g.APIs[0].Community != "https://games.test/.well-known/tieroute/v2/community/" || g.APIs[0].S2S == "" || g.APIs[0].Client != "" ||
		len(g.Keys) != 1 || bytes.Equal(g.Keys[0].Pub, doc.Keys[1].Pub) {
		t.Fatalf("community-only doc: %s", b)
	}
	req, _ = http.NewRequest("POST", e.ts.URL+"/.well-known/tieroute/v2/s2s/identity/fetch", bytes.NewReader([]byte("{}")))
	req.Host = "games.test"
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("S2S on a community-only name: %d", resp.StatusCode)
	}
	// The homeserver's client API isn't on the community-only name.
	req, _ = http.NewRequest("GET", e.ts.URL+"/.well-known/tieroute/v2/client/contacts", nil)
	req.Host = "games.test"
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("client API on a community-only name: %d", resp.StatusCode)
	}
}

// A community-only name signs in an identity whose chain lives on another name, fetched with
// S2S identity/fetch signed with the community's own key, and hosts its own community.
func TestCommunityOnlyName(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = []config.Community{{Name: "games.test", URL: "https://games.test"}}
	})
	kat := newV2User(t, e.ts, "kat", "chat.test")
	e.host = "games.test"
	k := e.signIn(kat)
	if c, _ := e.errOf("GET", "preview", "", nil); c != 404 {
		t.Fatalf("preview before create: %d", c)
	}
	m := k.create("games.test", false)
	var pv struct {
		ID   wire.Bytes `json:"id"`
		Name string     `json:"name"`
	}
	if c := e.call("GET", "preview", "", nil, &pv); c != 200 || pv.Name != "Night shift" || !bytes.Equal(pv.ID, m.ch.id) {
		t.Fatalf("preview: %d %+v", c, pv)
	}
	// The server's copy of a member's chain, fetched from chat.test at sign-in.
	var mc struct {
		Entries []wire.Raw `json:"entries"`
		Head    int        `json:"head"`
	}
	if c := e.call("GET", "members/"+kat.id+"/chain", k.tok, nil, &mc); c != 200 || len(mc.Entries) != 1 || mc.Head != 0 {
		t.Fatalf("members/{id}/chain: %d %+v", c, mc)
	}
	if st, err := decodeChainFor(wire.V2, [][]byte{mc.Entries[0]}); err != nil || st.ID != kat.id {
		t.Fatalf("the member's chain doesn't check out: %v", err)
	}
	ravi := e.signIn(newV2User(t, e.ts, "ravi", "chat.test"))
	if c, _ := e.errOf("GET", "members/"+kat.id+"/chain", ravi.tok, nil); c != 403 {
		t.Fatalf("a non-member read a member's chain: %d", c)
	}
	if c, _ := e.errOf("GET", "members/"+ravi.id+"/chain", k.tok, nil); c != 404 {
		t.Fatalf("a non-member's chain: %d", c)
	}
	code := newComposite(t)
	k.mustAppend(m.ch, addCodeOp(code, 3))
	if c := e.call("GET", "members/"+kat.id+"/chain?code="+base64.RawURLEncoding.EncodeToString(code.Public().Hash()), ravi.tok, nil, &mc); c != 200 {
		t.Fatalf("members/{id}/chain with code access: %d", c)
	}
	// chat.test hosts no community.
	e.host = ""
	if c, _ := e.errOf("GET", "preview", "", nil); c != 404 {
		t.Fatalf("the homeserver's name answered for games.test's community: %d", c)
	}
}

func TestCommunityCreate(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi := e.user("kat"), e.user("ravi")
	entry := kat.sign(map[string]any{"seq": 0, "ts": time.Now().Unix(), "by": kat.id, "ops": []any{createOp("chat.test", true, false)}})
	// The operator's creation code.
	if c, code := e.errOf("POST", "create", kat.tok, map[string]any{"entry": entry}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("create without the code: %d %s", c, code)
	}
	if c, code := e.errOf("POST", "create", kat.tok, map[string]any{"entry": entry, "code": "wrong-code-here"}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("create with a wrong code: %d %s", c, code)
	}
	// Another server's name.
	other := kat.sign(map[string]any{"seq": 0, "ts": time.Now().Unix(), "by": kat.id, "ops": []any{createOp("elsewhere.test", true, false)}})
	if c, code := e.errOf("POST", "create", kat.tok, map[string]any{"entry": other, "code": testCreateCode}); c != 400 || code != wire.ErrCodeInvalidChain {
		t.Fatalf("create naming another server: %d %s", c, code)
	}
	// Signed by kat, sent by ravi: the owner must be the caller.
	if c, code := e.errOf("POST", "create", ravi.tok, map[string]any{"entry": entry, "code": testCreateCode}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("create of someone else's entry: %d %s", c, code)
	}
	// Clock.
	old := kat.sign(map[string]any{"seq": 0, "ts": time.Now().Unix() - 3600, "by": kat.id, "ops": []any{createOp("chat.test", true, false)}})
	if c, code := e.errOf("POST", "create", kat.tok, map[string]any{"entry": old, "code": testCreateCode}); c != 400 || code != wire.ErrCodeClockSkew {
		t.Fatalf("create an hour old: %d %s", c, code)
	}
	var res struct {
		ID wire.Bytes `json:"id"`
	}
	if c := e.call("POST", "create", kat.tok, map[string]any{"entry": entry, "code": testCreateCode}, &res); c != 200 {
		t.Fatalf("create: %d", c)
	}
	// A retry gets the same answer; another create is refused (SPEC §16.1).
	var again struct {
		ID wire.Bytes `json:"id"`
	}
	if c := e.call("POST", "create", kat.tok, map[string]any{"entry": entry, "code": testCreateCode}, &again); c != 200 || !bytes.Equal(again.ID, res.ID) {
		t.Fatalf("retried create: %d", c)
	}
	second := ravi.sign(map[string]any{"seq": 0, "ts": time.Now().Unix(), "by": ravi.id, "ops": []any{createOp("chat.test", true, false)}})
	if c, code := e.errOf("POST", "create", ravi.tok, map[string]any{"entry": second, "code": testCreateCode}); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("a second community: %d %s", c, code)
	}
	// No members group yet: the owner registers one; nobody else can.
	tree := kat.uploadTree("t0")
	reg := map[string]any{"group": randB(32), "epoch": 0, "epoch-key": newComposite(t).Public().Bytes(), "info": []byte("i"), "tree": tree}
	if c, _ := e.errOf("POST", "groups/create", ravi.tok, reg); c != 403 {
		t.Fatalf("a stranger registered the members group: %d", c)
	}
	if c := e.call("POST", "groups/create", kat.tok, reg, nil); c != 204 {
		t.Fatalf("owner registers the members group: %d", c)
	}
	reg["group"] = randB(32)
	if c, code := e.errOf("POST", "groups/create", kat.tok, reg); c != 409 || code != wire.ErrCodeAlreadyExists {
		t.Fatalf("a second members group: %d %s", c, code)
	}
}

// The chain: sequenced appends, the server's checks, and who can read it.
func TestCommunityChainAppend(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi, mia := e.user("kat"), e.user("ravi"), e.user("mia")
	m := kat.create("chat.test", false)
	kat.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "Night shift 2"})
	// Idempotent: the head again gets the same answer.
	head := kat.sign(kat.next(&cmChain{id: m.ch.id, seq: m.ch.seq, head: m.ch.head}, map[string]any{"op": "set-name", "name": "Three"}))
	if c, _ := kat.appendRaw(m.ch, head); c != 200 {
		t.Fatal("append")
	}
	seq := m.ch.seq
	if c, _ := kat.appendRaw(m.ch, head); c != 200 || m.ch.seq != seq {
		t.Fatalf("re-append of the head: %d, seq %d", c, m.ch.seq)
	}
	// A stale prev.
	stale := &cmChain{id: m.ch.id, seq: m.ch.seq - 1, head: randB(32)}
	if c, code := kat.appendOps(stale, map[string]any{"op": "set-name", "name": "x"}); c != 409 || code != wire.ErrCodeStaleHead {
		t.Fatalf("stale head: %d %s", c, code)
	}
	// A non-member can't append, or read the chain.
	if c, code := ravi.appendOps(m.ch, map[string]any{"op": "set-name", "name": "mine now"}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("non-member append: %d %s", c, code)
	}
	if c, _ := e.errOf("GET", "chain", ravi.tok, nil); c != 403 {
		t.Fatalf("non-member read the chain: %d", c)
	}
	if c, _ := e.errOf("GET", "chain", "", nil); c != 401 {
		t.Fatalf("anonymous read the chain: %d", c)
	}
	// Code access reads the chain, with a session.
	code := newComposite(t)
	kat.mustAppend(m.ch, addCodeOp(code, 5))
	q := "?code=" + base64.RawURLEncoding.EncodeToString(code.Public().Hash())
	var chain struct {
		Entries []wire.Raw `json:"entries"`
		Head    uint64     `json:"head"`
	}
	if c := e.call("GET", "chain"+q, ravi.tok, nil, &chain); c != 200 || uint64(len(chain.Entries)) != m.ch.seq+1 || chain.Head != m.ch.seq {
		t.Fatalf("chain with code access: %d, %d entries", c, len(chain.Entries))
	}
	if c, _ := e.errOf("GET", "chain?code="+base64.RawURLEncoding.EncodeToString(randB(32)), ravi.tok, nil); c != 403 {
		t.Fatalf("chain with an unknown code: %d", c)
	}
	if c := e.call("GET", "chain?after=1"+"&code="+q[6:], ravi.tok, nil, &chain); c != 200 || uint64(len(chain.Entries)) != m.ch.seq-1 {
		t.Fatalf("chain after 1: %d, %d entries", c, len(chain.Entries))
	}
	// Ravi joins; he's a member without administrate.
	if c, code := ravi.codeJoin(m, code, nil); c != 200 {
		t.Fatalf("join: %d %s", c, code)
	}
	if c, code := ravi.appendOps(m.ch, map[string]any{"op": "set-name", "name": "mine now"}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("append without permission: %d %s", c, code)
	}
	if c, code := ravi.appendOps(m.ch, map[string]any{"op": "add-role", "id": 1, "rank": 5, "perms": []string{"administrate"}, "name": sealed()}); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("self-made admin role: %d %s", c, code)
	}
	// An entry signed by kat, appended with ravi's session.
	if c, code := ravi.appendRaw(m.ch, kat.sign(kat.next(m.ch, map[string]any{"op": "set-name", "name": "x"}))); c != 403 || code != wire.ErrCodeNotAllowed {
		t.Fatalf("someone else's entry: %d %s", c, code)
	}
	// Clock skew, both ways.
	body := kat.next(m.ch, map[string]any{"op": "set-name", "name": "x"})
	body["ts"] = time.Now().Unix() + 3600
	if c, code := kat.appendRaw(m.ch, kat.sign(body)); c != 400 || code != wire.ErrCodeClockSkew {
		t.Fatalf("future entry: %d %s", c, code)
	}
	// A bad signature: mia's key in kat's name.
	if c, _ := kat.appendRaw(m.ch, signed2(t, "community-entry", kat.next(m.ch, map[string]any{"op": "set-name", "name": "x"}), mia.dev)); c != 403 && c != 400 {
		t.Fatalf("forged entry: %d", c)
	}
	// Unknown op.
	if c, code := kat.appendOps(m.ch, map[string]any{"op": "make-me-king"}); c != 400 || code != wire.ErrCodeUnknownKind {
		t.Fatalf("unknown op: %d %s", c, code)
	}
	// Every member hears of each append.
	found := false
	for _, it := range ravi.inbox() {
		if bytes.Contains(it.Notice, []byte(`"community-chain"`)) {
			found = true
		}
	}
	if !found {
		t.Fatal("no community-chain notice")
	}
}

// Every endpoint in spec/api/community.md is routed, on the homeserver's name and on a
// community-only one.
func TestCommunityEveryEndpointRouted(t *testing.T) {
	e := newCommunityEnv(t, func(c *config.Config) {
		c.Communities = append(c.Communities, config.Community{Name: "games.test", URL: "https://games.test"})
	})
	endpoints := []string{"GET preview", "POST auth/challenge", "POST auth/session", "POST auth/logout", "POST create", "POST join",
		"POST join/request", "GET join/requests", "POST join/approve", "POST join/decline", "POST leave", "GET chain", "POST chain/append",
		"POST keypackages/upload", "GET keypackages/count", "POST keypackages/claim", "POST groups/create", "POST groups/epoch-key",
		"POST groups/register", "POST groups/unregister", "GET groups/AAAA/commits", "GET groups/AAAA/info", "GET groups/AAAA/tree",
		"POST tree/upload", "POST send", "GET inbox", "POST inbox/ack", "GET channels/1/messages", "POST history/put", "GET history/list",
		"GET history/get", "GET members/tr:aaaaaaaaaaaaaaaaaaaaaaaa/chain", "POST media/upload", "GET media/AAAA", "POST voice/move", "POST messages/delete", "POST members/kick",
		"POST report", "GET reports", "POST reports/close", "GET icon/AAAA", "POST icon/upload", "POST read", "GET read"}
	for _, host := range []string{"", "games.test"} {
		e.host = host
		for _, ep := range endpoints {
			method, path, _ := strings.Cut(ep, " ")
			var body []byte
			if method == "POST" {
				body = []byte("{}")
			}
			_, b := e.do(method, path, "", wire.MediaType, body, nil)
			if strings.Contains(string(b), "no such endpoint") {
				t.Errorf("%s (host %q) isn't routed", ep, host)
			}
		}
	}
}
