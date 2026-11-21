package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// Wire version 2, served beside version 1 (SPEC §5.1, §6.8): the same endpoints under
// the version 2 base, with version 2 identities, composite signatures, and kp-bindings.

const v2Client = "/.well-known/tieroute/v2/client/"

// v2User is a minimal wire version 2 client: one composite device key, and the first two
// keys of its recovery code.
type v2User struct {
	t      *testing.T
	ts     *httptest.Server
	server string
	dev    *wire.CompositePrivateKey
	rec    []*wire.CompositePrivateKey
	id     string
	token  string
	handle string
	seq    uint64
	head   []byte
}

func call2(t *testing.T, ts *httptest.Server, method, path, token string, body any, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := wire.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+v2Client+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", wire.MediaType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && len(b) > 0 {
		if err := wire.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: decode: %v (%s)", method, path, err, b)
		}
	}
	return resp.StatusCode
}

// signed2 signs as a device: k is the composite key's Ed25519 component.
func signed2(t *testing.T, typ string, body any, k *wire.CompositePrivateKey) wire.Raw {
	t.Helper()
	s, err := wire.SignComposite(typ, body, k)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := s.Encode()
	return enc
}

// signedFull2 signs with the whole composite key in k: recovery keys and link proofs.
func signedFull2(t *testing.T, typ string, body any, k *wire.CompositePrivateKey) wire.Raw {
	t.Helper()
	s, err := wire.SignCompositeFull(typ, body, k)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := s.Encode()
	return enc
}

func newComposite(t *testing.T) *wire.CompositePrivateKey {
	t.Helper()
	k, err := wire.GenerateCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func edOf(k *wire.CompositePrivateKey) []byte { return k.Public().Ed25519() }

func addDevice(k *wire.CompositePrivateKey, name string) map[string]any {
	return map[string]any{"op": "add-device", "key": edOf(k), "pub": k.Public().Bytes(), "name": name}
}

func newV2User(t *testing.T, ts *httptest.Server, name, server string) *v2User {
	t.Helper()
	u := &v2User{t: t, ts: ts, server: server, dev: newComposite(t), rec: []*wire.CompositePrivateKey{newComposite(t), newComposite(t)}, handle: name + "." + server}
	genesis := signed2(t, "chain-entry", map[string]any{
		"seq": 0, "ts": time.Now().Unix(),
		"ops": []any{
			addDevice(u.dev, name+"'s laptop"),
			map[string]any{"op": "set-home", "home": server},
			map[string]any{"op": "set-handle", "handle": u.handle},
			map[string]any{"op": "set-recovery", "next": u.rec[0].Public().Hash()},
		},
	}, u.dev)
	var reg struct {
		ID string `json:"id"`
	}
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": genesis, "invite": testRegCode}, &reg); c != 200 {
		t.Fatalf("register %s: %d", name, c)
	}
	u.id = reg.ID
	sum := sha256.Sum256(genesis)
	u.head = sum[:]
	u.token = u.signIn(u.dev)
	u.uploadKPs(u.dev, u.token, "kp-"+name)
	return u
}

// signIn starts a session for device k (SPEC §8.2).
func (u *v2User) signIn(k *wire.CompositePrivateKey) string {
	u.t.Helper()
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	if c := call2(u.t, u.ts, "POST", "auth/challenge", "", map[string]any{"id": u.id, "key": edOf(k)}, &ch); c != 200 {
		u.t.Fatalf("challenge: %d", c)
	}
	auth := signed2(u.t, "auth", map[string]any{"id": u.id, "nonce": ch.Nonce, "server": u.server, "ts": time.Now().Unix()}, k)
	var sess struct {
		Token string `json:"token"`
	}
	if c := call2(u.t, u.ts, "POST", "auth/session", "", map[string]any{"auth": auth}, &sess); c != 200 {
		u.t.Fatalf("session: %d", c)
	}
	return sess.Token
}

// kp returns a key package with its kp-binding by device k (SPEC §3.2.2).
func (u *v2User) kp(k *wire.CompositePrivateKey, data string) map[string]any {
	sum := sha256.Sum256([]byte(data))
	return map[string]any{"kp": []byte(data), "binding": signed2(u.t, "kp-binding", map[string]any{"id": u.id, "kp": sum[:]}, k)}
}

func (u *v2User) uploadKPs(k *wire.CompositePrivateKey, token string, data string) {
	u.t.Helper()
	if c := call2(u.t, u.ts, "POST", "keypackages/upload", token, map[string]any{"packages": []any{u.kp(k, data)}, "last-resort": u.kp(k, data+"-lr")}, nil); c != 200 {
		u.t.Fatalf("kp upload: %d", c)
	}
}

// entry builds the next chain entry.
func (u *v2User) entry(ops ...any) map[string]any {
	return map[string]any{"id": u.id, "seq": u.seq + 1, "prev": u.head, "ts": time.Now().Unix(), "ops": ops}
}

// appendSigned appends a signed entry through chain/append, and on success moves the head.
func (u *v2User) appendSigned(entry wire.Raw) (int, wire.Error) {
	u.t.Helper()
	var res struct {
		Seq  uint64     `json:"seq"`
		Head wire.Bytes `json:"head"`
		wire.Error
	}
	c := call2(u.t, u.ts, "POST", "chain/append", u.token, map[string]any{"entry": entry}, &res)
	if c == 200 {
		u.seq, u.head = res.Seq, res.Head
	}
	return c, res.Error
}

func (u *v2User) inbox() []inboxItem {
	var res struct {
		Items []inboxItem `json:"items"`
	}
	if c := call2(u.t, u.ts, "GET", "inbox", u.token, nil, &res); c != 200 {
		u.t.Fatalf("inbox: %d", c)
	}
	if n := len(res.Items); n > 0 {
		call2(u.t, u.ts, "POST", "inbox/ack", u.token, map[string]any{"upto": res.Items[n-1].Cursor}, nil)
	}
	return res.Items
}

func (u *v2User) eventually(n int) []inboxItem {
	u.t.Helper()
	var got []inboxItem
	for range 100 {
		got = append(got, u.inbox()...)
		if len(got) >= n {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	u.t.Fatalf("%s: wanted %d inbox items, got %d", u.handle, n, len(got))
	return nil
}

func (u *v2User) invite() string {
	u.t.Helper()
	var res struct {
		Code string `json:"code"`
	}
	if c := call2(u.t, u.ts, "POST", "invites/create", u.token, map[string]any{}, &res); c != 200 {
		u.t.Fatalf("invites/create: %d", c)
	}
	return res.Code
}

func (u *v2User) request(to *v2User, invite string) int {
	u.t.Helper()
	req := signed2(u.t, "contact-request", map[string]any{"from": u.id, "to": to.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": invite}, u.dev)
	return call2(u.t, u.ts, "POST", "contacts/request", u.token, map[string]any{"request": req}, nil)
}

type claimed struct {
	Packages []struct {
		Dev        wire.Bytes `json:"dev"`
		KP         wire.Bytes `json:"kp"`
		Binding    wire.Raw   `json:"binding"`
		LastResort bool       `json:"last-resort"`
	} `json:"packages"`
}

// checkBinding checks a claimed package's kp-binding as a claimant does (SPEC §3.2.2).
func checkBinding(t *testing.T, id string, dev *wire.CompositePrivateKey, kp, binding []byte) {
	t.Helper()
	sig, err := wire.DecodeSignedV2(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyKPBinding(sig, id, dev.Public(), kp); err != nil {
		t.Fatalf("claimed binding: %v", err)
	}
}

// The core flow on one server: sign up, sign in, find each other, become contacts with
// an invite, claim key packages with their bindings, and deliver.
func TestV2Flow(t *testing.T) {
	ts := testServer(t)
	kat, ravi, eve := newV2User(t, ts, "kat", "chat.test"), newV2User(t, ts, "ravi", "chat.test"), newV2User(t, ts, "eve", "chat.test")

	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call2(t, ts, "GET", "resolve/ravi.chat.test", kat.token, nil, &res); c != 200 || res.ID != ravi.id {
		t.Fatalf("resolve: %d %+v", c, res)
	}
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	if c := call2(t, ts, "GET", "chain/"+ravi.id, kat.token, nil, &ch); c != 200 || len(ch.Entries) != 1 {
		t.Fatalf("chain: %d", c)
	}
	if st, err := decodeChainFor(wire.V2, [][]byte{ch.Entries[0]}); err != nil || st.ID != ravi.id || st.V != wire.V2 {
		t.Fatalf("fetched chain: %v", err)
	}

	if c := kat.request(ravi, ravi.invite()); c != 202 {
		t.Fatalf("request: %d", c)
	}
	if items := ravi.inbox(); len(items) != 1 || items[0].Notice == nil {
		t.Fatalf("ravi's inbox: %+v", items)
	}
	if c := call2(t, ts, "POST", "contacts/accept", ravi.token, map[string]any{"id": kat.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}
	var cl claimed
	if c := call2(t, ts, "POST", "keypackages/claim", ravi.token, map[string]any{"id": kat.id}, &cl); c != 200 || len(cl.Packages) != 1 || string(cl.Packages[0].KP) != "kp-kat" {
		t.Fatalf("claim: %d %+v", c, cl)
	}
	checkBinding(t, kat.id, kat.dev, cl.Packages[0].KP, cl.Packages[0].Binding)
	// The one-time package is gone; the last-resort one comes next, with its own binding.
	if call2(t, ts, "POST", "keypackages/claim", ravi.token, map[string]any{"id": kat.id}, &cl); !cl.Packages[0].LastResort {
		t.Fatalf("second claim: %+v", cl)
	}
	checkBinding(t, kat.id, kat.dev, cl.Packages[0].KP, cl.Packages[0].Binding)
	if c := call2(t, ts, "POST", "keypackages/claim", eve.token, map[string]any{"id": kat.id}, nil); c != 403 {
		t.Fatalf("eve's claim: %d", c)
	}

	// Deliveries: a Welcome from a contact allowlists its group, then messages arrive.
	// A commit for a group the hub doesn't know is refused (groups_v2_test.go has the hub).
	group := randBytes(32)
	var sr struct {
		Results []sendResult `json:"results"`
	}
	welcome := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 1, "mls": "welcome", "data": []byte("welcome")}
	app := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id, eve.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("ciphertext")}
	commit := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 1, "mls": "commit", "data": []byte("c")}
	if c := call2(t, ts, "POST", "send", ravi.token, map[string]any{"deliveries": []any{welcome, app, commit}}, &sr); c != 200 ||
		sr.Results[0].Status != "sent" || sr.Results[1].Status != "sent" || sr.Results[2].Error != wire.ErrCodeBadRequest {
		t.Fatalf("send: %d %+v", c, sr)
	}
	items := kat.inbox()
	if len(items) != 2 || items[0].Delivery.MLS != "welcome" || string(items[1].Delivery.Data) != "ciphertext" || items[1].Delivery.From != ravi.id {
		t.Fatalf("kat's inbox: %+v", items)
	}
	if items := eve.inbox(); len(items) != 0 {
		t.Fatalf("eve got %d", len(items))
	}
	if c := call2(t, ts, "POST", "groups/create", ravi.token, map[string]any{"group": group, "kind": "direct", "epoch-key": randBytes(32)}, nil); c != 400 {
		t.Fatalf("groups/create with a version 1 epoch key: %d", c)
	}

	// The stream speaks tieroute.v2, and pushes what arrives.
	c, _, err := ws.Dial(ts.URL+v2Client+"stream", "tieroute.v2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	b, _ := wire.Marshal(map[string]any{"t": "auth", "token": kat.token})
	c.SendText(b)
	frameOf(t, c, "ready")
	app["id"], app["data"] = randBytes(16), []byte("live")
	call2(t, ts, "POST", "send", ravi.token, map[string]any{"deliveries": []any{app}}, &sr)
	if f := frameOf(t, c, "item"); !strings.Contains(string(f["item"]), wire.B64([]byte("live"))) {
		t.Fatalf("stream item: %s", f["item"])
	}
	if _, _, err := ws.Dial(ts.URL+v2Client+"stream", "tieroute.v1"); err == nil {
		t.Fatal("the version 2 stream took tieroute.v1")
	}
}

// The two versions never mix: tokens, identities, and signatures of one aren't accepted
// on the other's API (SPEC §5.1). Handles are one namespace.
func TestV2Isolation(t *testing.T) {
	ts := testServer(t)
	v1 := newUser(t, ts, "kat")
	v2 := newV2User(t, ts, "ravi", "chat.test")

	if c := call2(t, ts, "GET", "inbox", v1.token, nil, nil); c != 401 {
		t.Fatalf("a version 1 token on version 2: %d", c)
	}
	if c := call(t, ts, "GET", "inbox", v2.token, nil, nil); c != 401 {
		t.Fatalf("a version 2 token on version 1: %d", c)
	}
	if c := call(t, ts, "GET", "chain/"+v2.id, v1.token, nil, nil); c != 404 {
		t.Fatalf("a version 2 chain on version 1: %d", c)
	}
	if c := call2(t, ts, "GET", "chain/"+v1.id, v2.token, nil, nil); c != 404 {
		t.Fatalf("a version 1 chain on version 2: %d", c)
	}
	if c := call(t, ts, "GET", "resolve/ravi.chat.test", v1.token, nil, nil); c != 404 {
		t.Fatalf("version 1 resolved a version 2 handle: %d", c)
	}
	// A version 2 identity can't take a handle a version 1 identity holds.
	g := signed2(t, "chain-entry", map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		addDevice(v2.dev, ""), map[string]any{"op": "set-home", "home": "chat.test"},
		map[string]any{"op": "set-handle", "handle": "kat.chat.test"},
		map[string]any{"op": "set-recovery", "next": v2.rec[0].Public().Hash()},
	}}, v2.dev)
	var e wire.Error
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": g, "invite": testRegCode}, &e); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("handle taken across versions: %d %+v", c, e)
	}
	// Either version's genesis on the other's API is refused.
	if c := call(t, ts, "POST", "register", "", map[string]any{"genesis": g, "invite": testRegCode}, nil); c != 400 {
		t.Fatalf("a version 2 genesis on version 1: %d", c)
	}
	var v1g struct {
		Entries []wire.Raw `json:"entries"`
	}
	call(t, ts, "GET", "chain/"+v1.id, v1.token, nil, &v1g)
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": v1g.Entries[0], "invite": testRegCode}, nil); c != 400 {
		t.Fatalf("a version 1 genesis on version 2: %d", c)
	}
	// A version 1 signature (context tieroute/v1, Ed25519) doesn't sign in on version 2,
	// even from a key that is a version 2 device's Ed25519 component.
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	call2(t, ts, "POST", "auth/challenge", "", map[string]any{"id": v2.id, "key": edOf(v2.dev)}, &ch)
	auth := signed(t, "auth", map[string]any{"id": v2.id, "nonce": ch.Nonce, "server": "chat.test", "ts": time.Now().Unix()}, v1.dev)
	if c := call2(t, ts, "POST", "auth/session", "", map[string]any{"auth": auth}, nil); c != 400 {
		t.Fatalf("a version 1 auth on version 2: %d", c)
	}
	// A device's composite key in k, rather than its Ed25519 component, isn't a device signature.
	full := signedFull2(t, "auth", map[string]any{"id": v2.id, "nonce": ch.Nonce, "server": "chat.test", "ts": time.Now().Unix()}, v2.dev)
	if c := call2(t, ts, "POST", "auth/session", "", map[string]any{"auth": full}, nil); c != 400 {
		t.Fatalf("auth with a whole key in k: %d", c)
	}
	// Another device's composite key under this device's name doesn't verify.
	forged, _ := wire.SignComposite("auth", map[string]any{"id": v2.id, "nonce": ch.Nonce, "server": "chat.test", "ts": time.Now().Unix()}, newComposite(t))
	forged.K = edOf(v2.dev)
	fenc, _ := forged.Encode()
	if c := call2(t, ts, "POST", "auth/session", "", map[string]any{"auth": wire.Raw(fenc)}, nil); c != 400 {
		t.Fatalf("a forged auth: %d", c)
	}
	// Contacts can't be made across versions: a version 1 request names a stranger.
	req := signed(t, "contact-request", map[string]any{"from": v1.id, "to": v2.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": v2.invite()}, v1.dev)
	call(t, ts, "POST", "contacts/request", v1.token, map[string]any{"request": req}, nil)
	if items := v2.inbox(); len(items) != 0 {
		t.Fatalf("a version 1 request reached a version 2 identity: %+v", items)
	}
}

// Every client and S2S endpoint is routed under the version 2 base too, and implemented:
// none answers 501, but GET turn on a server with no call relay.
func TestV2EveryEndpointRouted(t *testing.T) {
	ts := testServer(t)
	u := newV2User(t, ts, "kat", "chat.test")
	for _, e := range clientEndpoints {
		method, path, _ := strings.Cut(e, " ")
		path = strings.NewReplacer("{id}", "tr:aaaaaaaaaaaaaaaaaaaaaaaa", "{handle}", "x.chat.test", "{device}", "AAAA", "{server}", "chat.test", "{name}", "chat.test", "{group}", "AAAA").Replace(path)
		var body any
		if method == "POST" {
			body = map[string]any{}
		}
		var res wire.Error
		out := any(&res)
		if path == "stream" {
			out = nil // not a WebSocket handshake: answers with plain text
		}
		c := call2(t, ts, method, path, u.token, body, out)
		if res.Msg == "no such endpoint" {
			t.Errorf("%s isn't routed", e)
		}
		if c == 501 && e != "GET turn" {
			t.Errorf("%s: %d", e, c)
		}
	}
	for _, p := range []string{"identity/fetch", "identity/push", "keypackages/claim", "contacts/request", "contacts/decline", "deliver",
		"commit", "commit/fetch", "group/epoch-key", "group/register", "presence", "profile/fetch", "media/fetch", "report"} {
		resp, err := http.Post(ts.URL+"/.well-known/tieroute/v2/s2s/"+p, wire.MediaType, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 501 || resp.StatusCode == 404 {
			t.Errorf("s2s %s: %d", p, resp.StatusCode)
		}
	}
}

// Key packages need a kp-binding by the uploading device, for its identity and that
// package (SPEC §3.2.2).
func TestV2KeyPackageBindings(t *testing.T) {
	ts := testServer(t)
	kat, ravi := newV2User(t, ts, "kat", "chat.test"), newV2User(t, ts, "ravi", "chat.test")
	up := func(p any) (int, string) {
		var e wire.Error
		c := call2(t, ts, "POST", "keypackages/upload", kat.token, map[string]any{"packages": []any{p}}, &e)
		return c, e.Code
	}
	sum := sha256.Sum256([]byte("kp"))
	for name, p := range map[string]any{
		"no binding":           map[string]any{"kp": []byte("kp")},
		"a bare package":       wire.Bytes("kp"),
		"another package":      map[string]any{"kp": []byte("other"), "binding": kat.kp(kat.dev, "kp")["binding"]},
		"another identity":     map[string]any{"kp": []byte("kp"), "binding": signed2(t, "kp-binding", map[string]any{"id": ravi.id, "kp": sum[:]}, kat.dev)},
		"another type":         map[string]any{"kp": []byte("kp"), "binding": signed2(t, "msg-key", map[string]any{"id": kat.id, "kp": sum[:]}, kat.dev)},
		"a version 1 binding":  map[string]any{"kp": []byte("kp"), "binding": signed(t, "kp-binding", map[string]any{"id": kat.id, "kp": sum[:]}, newUser(t, ts, "x").dev)},
		"extra member":         map[string]any{"kp": []byte("kp"), "binding": signed2(t, "kp-binding", map[string]any{"id": kat.id, "kp": sum[:], "x": 1}, kat.dev)},
		"another device's key": map[string]any{"kp": []byte("kp"), "binding": ravi.kp(ravi.dev, "kp")["binding"]},
	} {
		if c, code := up(p); c != 400 {
			t.Errorf("%s: %d %s", name, c, code)
		}
	}
	if c, code := up(kat.kp(kat.dev, "kp")); c != 200 {
		t.Fatalf("a good binding: %d %s", c, code)
	}
}

// Chains on version 2: a linked device, the device ceiling, a removal, and a recovery
// fork, all through the API.
func TestV2Chain(t *testing.T) {
	ts := testServer(t)
	kat := newV2User(t, ts, "kat", "chat.test")

	// A new device parks its link proof, carrying its whole composite key (SPEC §7.2).
	phone := newComposite(t)
	proof := signedFull2(t, "link-proof", map[string]any{"id": kat.id, "code": "ABCD1234", "ts": time.Now().Unix()}, phone)
	if c := call2(t, ts, "POST", "link/proof", "", map[string]any{"proof": proof}, nil); c != 202 {
		t.Fatalf("link proof: %d", c)
	}
	// Signed by the device key alone (its component in k), it can't be checked: refused.
	bad := signed2(t, "link-proof", map[string]any{"id": kat.id, "code": "ABCD1234", "ts": time.Now().Unix()}, newComposite(t))
	if c := call2(t, ts, "POST", "link/proof", "", map[string]any{"proof": bad}, nil); c != 400 {
		t.Fatalf("a link proof without its key: %d", c)
	}
	var got struct {
		Proof wire.Raw `json:"proof"`
	}
	if c := call2(t, ts, "GET", "link/proof/"+wire.B64(edOf(phone)), kat.token, nil, &got); c != 200 {
		t.Fatalf("fetching the proof: %d", c)
	}
	ps, _ := wire.DecodeSignedV2(got.Proof)
	pub, err := ps.VerifyCompositeSelf("link-proof")
	if err != nil || !pub.Equal(phone.Public()) {
		t.Fatalf("the proof: %v", err)
	}
	// An approving device that showed an approval code lists the waiting proofs instead,
	// since it doesn't know the new device's key (SPEC §7.2). Only its own identity's.
	var list struct {
		Proofs []wire.Raw `json:"proofs"`
	}
	if c := call2(t, ts, "GET", "link/proofs", kat.token, nil, &list); c != 200 || len(list.Proofs) != 1 || string(list.Proofs[0]) != string(got.Proof) {
		t.Fatalf("listing the proofs: %d %d", c, len(list.Proofs))
	}
	ravi := newV2User(t, ts, "ravi", "chat.test")
	if c := call2(t, ts, "GET", "link/proofs", ravi.token, nil, &list); c != 200 || len(list.Proofs) != 0 {
		t.Fatalf("another identity's proofs: %d %d", c, len(list.Proofs))
	}
	if c := call2(t, ts, "GET", "link/proofs", "", nil, nil); c != 401 {
		t.Fatalf("listing without a session: %d", c)
	}
	// The laptop adds it, with the composite key from the proof.
	if c, e := kat.appendSigned(signed2(t, "chain-entry", kat.entry(addDevice(phone, "phone")), kat.dev)); c != 200 {
		t.Fatalf("add-device: %d %+v", c, e)
	}
	phoneToken := kat.signIn(phone)
	kat.uploadKPs(phone, phoneToken, "kp-phone")
	if items := kat.inbox(); len(items) == 0 || !strings.Contains(string(items[len(items)-1].Notice), `"notice"`) {
		t.Fatalf("no new-device notice: %+v", items)
	}
	// An add-device whose key isn't its pub's component is invalid.
	other := newComposite(t)
	mismatched := addDevice(other, "")
	mismatched["key"] = edOf(phone)
	if c, e := kat.appendSigned(signed2(t, "chain-entry", kat.entry(mismatched), kat.dev)); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("mismatched add-device: %d %+v", c, e)
	}
	// Up to 10 devices, and not one more (SPEC §6.4 rule 4).
	var extra []*wire.CompositePrivateKey
	for len(extra) < chain.MaxDevices-2 {
		extra = append(extra, newComposite(t))
	}
	var ops []any
	for _, k := range extra {
		ops = append(ops, addDevice(k, ""))
	}
	if c, e := kat.appendSigned(signed2(t, "chain-entry", kat.entry(ops...), kat.dev)); c != 200 {
		t.Fatalf("ten devices: %d %+v", c, e)
	}
	if c, e := kat.appendSigned(signed2(t, "chain-entry", kat.entry(addDevice(newComposite(t), "")), kat.dev)); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("an eleventh device: %d %+v", c, e)
	}
	// The phone removes the laptop: its session ends at once.
	if c, e := kat.appendSigned(signed2(t, "chain-entry", kat.entry(map[string]any{"op": "remove-device", "key": edOf(kat.dev)}), phone)); c != 200 {
		t.Fatalf("remove-device: %d %+v", c, e)
	}
	if c := call2(t, ts, "GET", "inbox", kat.token, nil, nil); c != 401 {
		t.Fatalf("removed device's session: %d", c)
	}
	kat.token = phoneToken
	// The recovery code undoes the removal with a fork at that entry: k is recovery key 1's
	// whole composite key, which the genesis committed to (SPEC §6.3, §6.4.1).
	fork := map[string]any{"id": kat.id, "seq": kat.seq, "prev": prevOf(t, ts, kat), "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "remove-device", "key": edOf(phone)},
		map[string]any{"op": "set-recovery", "next": kat.rec[1].Public().Hash()},
	}}
	var rr struct {
		Seq uint64 `json:"seq"`
		wire.Error
	}
	if c := call2(t, ts, "POST", "recover", "", map[string]any{"entry": signedFull2(t, "chain-entry", fork, kat.rec[0])}, &rr); c != 200 || rr.Seq != kat.seq {
		t.Fatalf("recovery fork: %d %+v", c, rr)
	}
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	call2(t, ts, "GET", "chain/"+kat.id, "", nil, &ch)
	raw := make([][]byte, len(ch.Entries))
	for i, e := range ch.Entries {
		raw[i] = e
	}
	st, err := decodeChainFor(wire.V2, raw)
	if err != nil || !st.HasDevice(edOf(kat.dev)) || st.HasDevice(edOf(phone)) {
		t.Fatalf("after the fork: %v", err)
	}
	if c := call2(t, ts, "GET", "inbox", phoneToken, nil, nil); c != 401 {
		t.Fatalf("the phone, dropped by the fork, still has a session: %d", c)
	}
	// A recovery entry signed by the spent key 1 is refused now.
	again := map[string]any{"id": kat.id, "seq": st.Seq + 1, "prev": st.Head, "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "set-recovery", "next": kat.rec[1].Public().Hash()},
	}}
	if c := call2(t, ts, "POST", "recover", "", map[string]any{"entry": signedFull2(t, "chain-entry", again, kat.rec[0])}, nil); c != 400 {
		t.Fatalf("spent recovery key: %d", c)
	}
}

// prevOf is the hash of the entry before u's head, from the server's copy.
func prevOf(t *testing.T, ts *httptest.Server, u *v2User) []byte {
	t.Helper()
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	call2(t, ts, "GET", "chain/"+u.id, "", nil, &ch)
	s, err := wire.DecodeSignedV2(ch.Entries[len(ch.Entries)-2])
	if err != nil {
		t.Fatal(err)
	}
	h, _ := s.Hash()
	return h
}

// A cached version 2 chain gives way to a recovery fork however old the device entries
// it overrides are (SPEC §6.4.1, §6.5), and the overridden branch never comes back.
// Version 1 would keep a device branch more than 72 hours older than the recovery entry.
func TestV2CachedRecoveryForkAnyAge(t *testing.T) {
	_, _, _, sb := twoServers(t)
	s := sb.V2()
	ctx := context.Background()
	dev, thief, rec1, rec2 := newComposite(t), newComposite(t), newComposite(t), newComposite(t)
	old := time.Now().Unix() - 2*365*24*3600
	enc := func(b wire.Raw) []byte { return b }
	g := signed2(t, "chain-entry", map[string]any{"seq": 0, "ts": old, "ops": []any{
		addDevice(dev, ""), map[string]any{"op": "set-home", "home": "a.test"},
		map[string]any{"op": "set-handle", "handle": "kat.a.test"},
		map[string]any{"op": "set-recovery", "next": rec1.Public().Hash()},
	}}, dev)
	id := wire.IdentityID(g)
	gh := sha256.Sum256(g)
	add := signed2(t, "chain-entry", map[string]any{"id": id, "seq": 1, "prev": gh[:], "ts": old + 60, "ops": []any{addDevice(thief, "")}}, dev)
	ah := sha256.Sum256(add)
	theft := signed2(t, "chain-entry", map[string]any{"id": id, "seq": 2, "prev": ah[:], "ts": old + 120, "ops": []any{map[string]any{"op": "remove-device", "key": edOf(dev)}}}, thief)
	recovery := signedFull2(t, "chain-entry", map[string]any{"id": id, "seq": 2, "prev": ah[:], "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "remove-device", "key": edOf(thief)},
		map[string]any{"op": "set-recovery", "next": rec2.Public().Hash()},
	}}, rec1)
	devBranch := [][]byte{enc(g), enc(add), enc(theft)}
	recBranch := [][]byte{enc(g), enc(add), enc(recovery)}
	if err := s.st.Remote().Put(ctx, id, "a.test", devBranch); err != nil {
		t.Fatal(err)
	}
	st, kept, changed, err := s.acceptChain(ctx, id, recBranch, "a.test")
	if err != nil || !changed || len(kept) != 3 || st.HasDevice(edOf(thief)) || !st.HasDevice(edOf(dev)) {
		t.Fatalf("recovery fork two years on: %v %v", changed, err)
	}
	if _, _, _, err := s.acceptChain(ctx, id, devBranch, "a.test"); err == nil {
		t.Fatal("the overridden branch came back")
	}
	// The version 1 Server doesn't see the version 2 cache at all.
	if _, _, err := sb.st.Remote().Get(ctx, id); err == nil {
		t.Fatal("version 1 sees a version 2 cached chain")
	}
}

// Two servers, each serving both versions: version 2 users on each become contacts
// through the version 2 S2S API, claim each other's packages with bindings, and deliver,
// while version 1 users on the same servers carry on as before.
func TestV2Federation(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, b, "ravi", "b.test")
	kat1, ravi1 := newUserOn(t, a, "kat1", "a.test"), newUserOn(t, b, "ravi1", "b.test")

	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call2(t, a, "GET", "resolve/ravi.b.test", kat.token, nil, &res); c != 200 || res.ID != ravi.id || res.Home != "b.test" {
		t.Fatalf("resolve across servers: %d %+v", c, res)
	}
	if c := kat.request(ravi, ravi.invite()); c != 202 {
		t.Fatalf("request: %d", c)
	}
	items := ravi.eventually(1)
	if items[0].Notice == nil || !strings.Contains(string(items[0].Notice), kat.id) {
		t.Fatalf("ravi's notice: %s", items[0].Notice)
	}
	if c := call2(t, b, "POST", "contacts/accept", ravi.token, map[string]any{"id": kat.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}
	var cl claimed
	if c := call2(t, b, "POST", "keypackages/claim", ravi.token, map[string]any{"id": kat.id}, &cl); c != 200 || len(cl.Packages) != 1 {
		t.Fatalf("claim across servers: %d %+v", c, cl)
	}
	checkBinding(t, kat.id, kat.dev, cl.Packages[0].KP, cl.Packages[0].Binding)

	group := randBytes(32)
	welcome := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 1, "mls": "welcome", "data": []byte("welcome")}
	app := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("hello across")}
	var sr struct {
		Results []sendResult `json:"results"`
	}
	if c := call2(t, b, "POST", "send", ravi.token, map[string]any{"deliveries": []any{welcome, app}}, &sr); c != 200 || sr.Results[1].Status != "sent" {
		t.Fatalf("send: %d %+v", c, sr)
	}
	got := kat.eventually(2) // the Welcome and the message
	if !slices.ContainsFunc(got, func(it inboxItem) bool { return it.Delivery != nil && string(it.Delivery.Data) == "hello across" }) {
		t.Fatalf("kat's inbox: %+v", got)
	}

	// Version 1, between the same servers, is untouched.
	if c := call(t, a, "GET", "resolve/ravi1.b.test", kat1.token, nil, &res); c != 200 || res.ID != ravi1.id {
		t.Fatalf("version 1 resolve: %d", c)
	}
	req := signed(t, "contact-request", map[string]any{"from": kat1.id, "to": ravi1.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": ravi1.invite(false)}, kat1.dev)
	if c := call(t, a, "POST", "contacts/request", kat1.token, map[string]any{"request": req}, nil); c != 202 {
		t.Fatalf("version 1 request: %d", c)
	}
	if items := ravi1.eventually(1); items[0].Notice == nil {
		t.Fatalf("version 1 notice: %+v", items)
	}
	// And version 2's people are strangers to it.
	if c := call(t, a, "GET", "chain/"+ravi.id+"?home=b.test", kat1.token, nil, nil); c != 404 {
		t.Fatalf("version 1 fetched a version 2 chain: %d", c)
	}
}

// A version 2 S2S endpoint refuses a request signed with the sender's version 1 key, and
// the version 1 endpoint one signed with its version 2 key (SPEC §5.1, §8.3).
func TestV2S2SSignatures(t *testing.T) {
	_, b, sa, _ := twoServers(t)
	ravi := newV2User(t, b, "ravi", "b.test")
	body, _ := wire.Marshal(map[string]any{"id": ravi.id})
	ctx := context.Background()
	// The version 2 Fed of a.test, calling b.test's version 2 API: accepted.
	if _, err := sa.V2().fed.Call(ctx, "b.test", "identity/fetch", body); err != nil {
		t.Fatalf("version 2 to version 2: %v", err)
	}
	// a.test's version 1 key on b.test's version 2 API, and the reverse.
	sign := func(v int) []byte {
		req := map[string]any{"from": "a.test", "to": "b.test", "path": "identity/fetch", "ts": time.Now().Unix(), "nonce": randBytes(16), "body": json.RawMessage(body)}
		var s wire.Signed
		var err error
		if v == wire.V2 {
			s, err = wire.SignCompositeKID("s2s", req, sa.key().V2.Priv, sa.key().V2.KID)
		} else {
			s, err = wire.SignKID("s2s", req, sa.key().Priv, sa.key().KID)
		}
		if err != nil {
			t.Fatal(err)
		}
		enc, _ := s.Encode()
		return enc
	}
	post := func(base string, v int) int {
		resp, err := http.Post(b.URL+base+"s2s/identity/fetch", wire.MediaType, bytes.NewReader(sign(v)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("/.well-known/tieroute/v2/", wire.V2); c != 200 {
		t.Fatalf("version 2 request on version 2: %d", c)
	}
	if c := post("/.well-known/tieroute/v2/", wire.V1); c != 401 {
		t.Fatalf("version 1 request on version 2: %d", c)
	}
	if c := post("/.well-known/tieroute/v1/", wire.V2); c != 401 {
		t.Fatalf("version 2 request on version 1: %d", c)
	}
}

// spec/vectors/v2/link.json, as rerouted sees it: both proofs verify with the composite
// key in k, which names the device by its Ed25519 component, and the parked proof's HPKE
// key hashes to the link code's hash. The code itself is made and read by clients.
func TestVectorLinkV2(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/v2/link.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Device struct {
			Ed string `json:"ed25519_public"`
		} `json:"device"`
		Full struct {
			HPKEHash string `json:"hpke_sha256_hex"`
		} `json:"full"`
		ID     string                  `json:"identity_id"`
		Parked struct{ Signed string } `json:"parked_proof"`
		Proof  struct{ Signed string } `json:"proof"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	s := &Server{wv: wire.V2}
	for name, text := range map[string]string{"parked": v.Parked.Signed, "proof": v.Proof.Signed} {
		sig, err := s.decodeSigned([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		key, err := s.selfSigned(sig, "link-proof")
		if err != nil || hex.EncodeToString(key) != v.Device.Ed {
			t.Fatalf("%s: %x %v", name, key, err)
		}
		var body struct {
			ID   string     `json:"id"`
			Code string     `json:"code"`
			HPKE wire.Bytes `json:"hpke"`
		}
		if err := sig.Open(&body); err != nil || body.ID != v.ID {
			t.Fatalf("%s body: %v", name, err)
		}
		if name == "parked" {
			if sum := sha256.Sum256(body.HPKE); len(body.HPKE) != hpkeKeySize || hex.EncodeToString(sum[:]) != v.Full.HPKEHash {
				t.Fatal("parked HPKE key doesn't match the code's hash")
			}
		}
		// Version 1's rules refuse it.
		if _, err := (&Server{wv: wire.V1}).decodeSigned([]byte(text)); err == nil {
			t.Fatalf("%s: version 1 decoded it", name)
		}
	}
}

// A version 2 move (SPEC §6.6): the new home checks it and reserves it with its composite
// server key, the old home appends it only with that reservation, and the new home takes
// the chain with a move signed by a current device. A reservation signed with the new
// home's version 1 key isn't one.
func TestV2Move(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, b, "ravi", "b.test")
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	call2(t, a, "GET", "chain/"+kat.id, "", nil, &ch)
	entry := signed2(t, "chain-entry", kat.entry(map[string]any{"op": "set-home", "home": "b.test"}, map[string]any{"op": "set-handle", "handle": "kat.b.test"}), kat.dev)
	head := sha256.Sum256(entry)
	move := func(h []byte) wire.Raw {
		return signed2(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": h, "ts": time.Now().Unix(), "contacts": []string{ravi.id}, "groups": []wire.Bytes{}}, kat.dev)
	}
	var check struct {
		Reservation wire.Raw `json:"reservation"`
	}
	if c := call2(t, b, "POST", "register", "", map[string]any{"chain": append(ch.Entries, entry), "move": move(head[:]), "invite": testRegCode, "check": true}, &check); c != 200 || check.Reservation == nil {
		t.Fatalf("check: %d", c)
	}
	res, err := wire.DecodeSignedV2(check.Reservation)
	if err != nil || len(res.S) != wire.CompositeSignatureSize || res.KID != sb.key().V2.KID {
		t.Fatalf("the reservation isn't signed with the composite key: %v", err)
	}
	// A reservation with the same body, signed with b.test's version 1 key: refused, and
	// nothing appended.
	var body map[string]any
	res.Open(&body)
	v1res, _ := wire.SignKID("move-reservation", body, sb.key().Priv, sb.key().KID)
	v1enc, _ := v1res.Encode()
	var e wire.Error
	if c := call2(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry, "reservation": wire.Raw(v1enc)}, &e); c/100 != 4 {
		t.Fatalf("a version 1 reservation: %d %+v", c, e)
	}
	if c := call2(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, &e); c != 403 {
		t.Fatalf("no reservation: %d %+v", c, e)
	}
	if c := call2(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry, "reservation": check.Reservation}, &e); c != 200 {
		t.Fatalf("append the move: %d %+v", c, e)
	}
	call2(t, a, "GET", "chain/"+kat.id, "", nil, &ch)
	if c := call2(t, b, "POST", "register", "", map[string]any{"chain": ch.Entries, "move": move(head[:]), "invite": testRegCode}, &e); c != 200 {
		t.Fatalf("register at b.test: %d %+v", c, e)
	}
	kat.ts, kat.server = b, "b.test"
	kat.token = kat.signIn(kat.dev)
	var r struct {
		ID string `json:"id"`
	}
	if c := call2(t, b, "GET", "resolve/kat.b.test", ravi.token, nil, &r); c != 200 || r.ID != kat.id {
		t.Fatalf("resolve after the move: %d %+v", c, r)
	}
	// Ravi came along as a contact.
	var cs struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if c := call2(t, b, "GET", "contacts", kat.token, nil, &cs); c != 200 || len(cs.Items) != 1 || cs.Items[0].ID != ravi.id {
		t.Fatalf("contacts after the move: %d %+v", c, cs)
	}
}
