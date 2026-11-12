package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// testUser is a minimal client. MLS bytes are opaque to the server,
// so this test uses placeholder bytes where a real client sends MLS messages.
type testUser struct {
	t      *testing.T
	ts     *httptest.Server
	dev    ed25519.PrivateKey
	rec    ed25519.PrivateKey // recovery key 1
	id     string
	token  string
	handle string
}

func call(t *testing.T, ts *httptest.Server, method, path, token string, body any, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := wire.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, ts.URL+"/.well-known/tieroute/v1/client/"+path, rd)
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
			t.Fatalf("%s %s: decode: %v (%x)", method, path, err, b)
		}
	}
	return resp.StatusCode
}

func signed(t *testing.T, typ string, body any, k ed25519.PrivateKey) wire.Raw {
	t.Helper()
	s, err := wire.Sign(typ, body, k)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := s.Encode()
	return enc
}

func newUser(t *testing.T, ts *httptest.Server, name string) *testUser {
	return newUserOn(t, ts, name, "chat.test")
}

func newUserOn(t *testing.T, ts *httptest.Server, name, server string) *testUser {
	t.Helper()
	return newUserDated(t, ts, name, server, time.Now().Unix())
}

// newUserDated is newUserOn with the genesis entry dated `when`.
func newUserDated(t *testing.T, ts *httptest.Server, name, server string, when int64) *testUser {
	t.Helper()
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, rec, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub) // pre-rotation commitment to recovery key 1
	u := &testUser{t: t, ts: ts, dev: dev, rec: rec, handle: name + "." + server}
	genesis := signed(t, "chain-entry", map[string]any{
		"seq": 0, "ts": when,
		"ops": []any{
			map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey)), "name": name + "'s laptop"},
			map[string]any{"op": "set-home", "home": server},
			map[string]any{"op": "set-handle", "handle": u.handle},
			map[string]any{"op": "set-recovery", "next": commit[:]},
		},
	}, dev)
	var reg struct {
		ID string `json:"id"`
	}
	if c := call(t, ts, "POST", "register", "", map[string]any{"genesis": genesis, "invite": testRegCode}, &reg); c != 200 {
		t.Fatalf("register %s: %d", name, c)
	}
	u.id = reg.ID

	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	pub := []byte(dev.Public().(ed25519.PublicKey))
	if c := call(t, ts, "POST", "auth/challenge", "", map[string]any{"id": u.id, "key": pub}, &ch); c != 200 {
		t.Fatalf("challenge: %d", c)
	}
	auth := signed(t, "auth", map[string]any{"id": u.id, "nonce": ch.Nonce, "server": server, "ts": time.Now().Unix()}, dev)
	var sess struct {
		Token string `json:"token"`
	}
	if c := call(t, ts, "POST", "auth/session", "", map[string]any{"auth": auth}, &sess); c != 200 {
		t.Fatalf("session: %d", c)
	}
	u.token = sess.Token
	if c := call(t, ts, "POST", "keypackages/upload", u.token, map[string]any{"packages": [][]byte{[]byte("kp-" + name)}}, nil); c != 200 {
		t.Fatalf("kp upload: %d", c)
	}
	return u
}

// testRegCode is the registration invite every test server uses (SPEC §8.2).
const testRegCode = "test-registration-code"

// invite creates a contact invite code for u (SPEC §9.1).
func (u *testUser) invite(public bool) string {
	u.t.Helper()
	var res struct {
		Code string `json:"code"`
	}
	if c := call(u.t, u.ts, "POST", "invites/create", u.token, map[string]any{"public": public}, &res); c != 200 || len(res.Code) != 10 {
		u.t.Fatalf("invites/create: %d %q", c, res.Code)
	}
	return res.Code
}

type inboxItem struct {
	Cursor   string    `json:"cursor"`
	Delivery *delivery `json:"delivery"`
	Notice   wire.Raw  `json:"notice"`
}

func (u *testUser) inbox() []inboxItem {
	var res struct {
		Items []inboxItem `json:"items"`
	}
	if c := call(u.t, u.ts, "GET", "inbox", u.token, nil, &res); c != 200 {
		u.t.Fatalf("inbox: %d", c)
	}
	if n := len(res.Items); n > 0 {
		call(u.t, u.ts, "POST", "inbox/ack", u.token, map[string]any{"upto": res.Items[n-1].Cursor}, nil)
	}
	return res.Items
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func TestBasicFlow(t *testing.T) {
	basicFlow(t, testServerWith(t, newStore(t)))
}

func basicFlow(t *testing.T, ts *httptest.Server) {
	kat, bob, eve := newUser(t, ts, "kat"), newUser(t, ts, "bob"), newUser(t, ts, "eve")

	// Kat finds Bob by handle and sends a contact request.
	var res struct {
		ID string `json:"id"`
	}
	if c := call(t, ts, "GET", "resolve/bob.chat.test", kat.token, nil, &res); c != 200 || res.ID != bob.id {
		t.Fatalf("resolve: %d %s", c, res.ID)
	}
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	if c := call(t, ts, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil); c != 202 {
		t.Fatalf("request: %d", c)
	}

	// Bob gets the notice, accepts, and claims Kat's key package.
	items := bob.inbox()
	if len(items) != 1 || items[0].Notice == nil {
		t.Fatalf("bob's inbox: %+v", items)
	}
	if c := call(t, ts, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}
	var claim struct {
		Packages []struct {
			KP wire.Bytes `json:"kp"`
		} `json:"packages"`
	}
	if c := call(t, ts, "POST", "keypackages/claim", bob.token, map[string]any{"id": kat.id}, &claim); c != 200 || len(claim.Packages) != 1 || string(claim.Packages[0].KP) != "kp-kat" {
		t.Fatalf("claim: %d %+v", c, claim)
	}
	// Eve isn't Kat's contact and can't drain her key packages.
	if c := call(t, ts, "POST", "keypackages/claim", eve.token, map[string]any{"id": kat.id}, nil); c != 403 {
		t.Fatalf("eve's claim: %d, want 403", c)
	}

	// Bob creates the direct group with epoch key 0 and commits the Add.
	group := randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, ek1, _ := ed25519.GenerateKey(rand.Reader)
	if c := call(t, ts, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "direct", "epoch-key": []byte(ek0Pub)}, nil); c != 204 {
		t.Fatalf("groups/create: %d", c)
	}
	commitData := []byte("mls-commit-add-kat")
	sum := sha256.Sum256(commitData)
	commitReq := signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "next": []byte(ek1Pub)}, ek0)
	var sendRes struct {
		Results []sendResult `json:"results"`
	}
	out := map[string]any{
		"id": randBytes(16), "kind": "mls", "to": []string{bob.id}, "group": group, "epoch": 0, "mls": "commit",
		"data": commitData, "commit": commitReq,
		"welcomes": []any{map[string]any{"id": randBytes(16), "to": []string{kat.id}, "data": []byte("mls-welcome")}},
	}
	if c := call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &sendRes); c != 200 || sendRes.Results[0].Status != "sent" || sendRes.Results[0].Receipt == nil {
		t.Fatalf("commit: %d %+v", c, sendRes)
	}
	// The receipt is signed by the hub's server key and names it by key ID (SPEC §11.6).
	receipt, err := wire.DecodeSigned(sendRes.Results[0].Receipt)
	if kid, ok := receipt.KeyID(); err != nil || !ok || kid == "" || receipt.T != "commit-receipt" {
		t.Fatalf("receipt: %v %+v", err, receipt)
	}

	// The same request again (its reply was lost) gets the same receipt, so its fan-out and
	// Welcomes still go out (SPEC §11.6).
	first := sendRes.Results[0].Receipt
	out["id"] = randBytes(16)
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &sendRes)
	if sendRes.Results[0].Status != "sent" || !bytes.Equal(sendRes.Results[0].Receipt, first) {
		t.Fatalf("an exact retry: %+v; want the first receipt", sendRes.Results[0])
	}
	// A different commit for epoch 0 loses (stale-epoch), and a commit signed with the wrong epoch key fails.
	other := []byte("mls-commit-something-else")
	otherSum := sha256.Sum256(other)
	out["id"], out["welcomes"], out["data"] = randBytes(16), nil, other
	out["commit"] = signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": otherSum[:], "next": []byte(ek1Pub)}, ek0)
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &sendRes)
	if sendRes.Results[0].Error != "stale-epoch" {
		t.Fatalf("second commit: %+v", sendRes.Results[0])
	}
	out["data"] = commitData
	bad := signed(t, "commit-request", map[string]any{"group": group, "epoch": 1, "hash": sum[:], "next": []byte(ek1Pub)}, ek0)
	out["id"], out["epoch"], out["commit"] = randBytes(16), 1, bad
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &sendRes)
	if sendRes.Results[0].Error != "bad-signature" {
		t.Fatalf("wrong epoch key: %+v", sendRes.Results[0])
	}
	_ = ek1

	// Kat gets the Welcome (she asked Bob, so it's allowed) and joins the group.
	items = kat.inbox()
	if len(items) != 1 || items[0].Delivery == nil || items[0].Delivery.MLS != "welcome" || items[0].Delivery.From != bob.id {
		t.Fatalf("kat's inbox: %+v", items)
	}
	// Bob sends an application message right away; Kat receives it even though her device
	// hasn't registered the group yet: accepting the Welcome allowlisted it (SPEC §10.3).
	// Eve, not in the group, is dropped silently.
	msg := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{bob.id, kat.id, eve.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("ciphertext")}
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{msg}}, &sendRes)
	if sendRes.Results[0].Status != "sent" {
		t.Fatalf("app: %+v", sendRes.Results[0])
	}
	items = kat.inbox()
	if len(items) != 1 || string(items[0].Delivery.Data) != "ciphertext" {
		t.Fatalf("kat's app message: %+v", items)
	}
	if items := eve.inbox(); len(items) != 0 {
		t.Fatalf("eve got %d items", len(items))
	}
	// Devices still register the group after processing the Welcome; it's already there.
	if c := call(t, ts, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil); c != 204 {
		t.Fatalf("groups/register: %d", c)
	}

	// Retrying the same send is idempotent: Kat doesn't get it twice.
	call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{msg}}, &sendRes)
	if items := kat.inbox(); len(items) != 0 {
		t.Fatalf("duplicate delivered: %d", len(items))
	}

	// Missed commits can be fetched from the hub.
	var commits struct {
		Items []struct {
			Epoch uint64 `json:"epoch"`
		} `json:"items"`
	}
	b64 := base64.RawURLEncoding.EncodeToString(group)
	if c := call(t, ts, "GET", "groups/"+b64+"/commits", kat.token, nil, &commits); c != 200 || len(commits.Items) != 1 || commits.Items[0].Epoch != 0 {
		t.Fatalf("commits: %d %+v", c, commits)
	}
}

func TestBadTokenRejected(t *testing.T) {
	ts := testServer(t)
	if c := call(t, ts, "GET", "inbox", "nope", nil, nil); c != 401 {
		t.Fatalf("status %d", c)
	}
}

func TestInboxClearedAfterAck(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	call(t, ts, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil)
	if items := bob.inbox(); len(items) != 1 { // inbox() acks what it read
		t.Fatalf("got %d items", len(items))
	}
	// Bob has one device, and it acked: the item is gone from storage, not just skipped.
	left, _, _, err := st.Inbox().List(context.Background(), bob.id, []byte("another device"), "", 100)
	if err != nil || len(left) != 0 {
		t.Fatalf("%d items still stored after every device acked", len(left))
	}
}

func TestKeyPackageReplace(t *testing.T) {
	ts := testServerWith(t, newStore(t))
	kat := newUser(t, ts, "kat") // uploaded "kp-kat"
	var res struct {
		Count int `json:"count"`
	}
	call(t, ts, "POST", "keypackages/upload", kat.token, map[string]any{"packages": [][]byte{[]byte("new-1"), []byte("new-2")}, "replace": true}, &res)
	if res.Count != 2 {
		t.Fatalf("count after replace = %d, want 2", res.Count)
	}
	var claim struct {
		Packages []struct {
			KP wire.Bytes `json:"kp"`
		} `json:"packages"`
	}
	call(t, ts, "POST", "keypackages/claim", kat.token, map[string]any{"id": kat.id}, &claim)
	if len(claim.Packages) != 1 || string(claim.Packages[0].KP) != "new-1" {
		t.Fatalf("claimed %+v; the old package should be gone", claim.Packages)
	}
}

// Contact requests need an invite code (SPEC §9.1). Without one, or with a wrong,
// used-up, or revoked one, the request is dropped silently: the sender still gets 202.
func TestContactRequestsNeedInvites(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	send := func(invite string) {
		t.Helper()
		body := map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16)}
		if invite != "" {
			body["invite"] = invite
		}
		if c := call(t, ts, "POST", "contacts/request", kat.token, map[string]any{"request": signed(t, "contact-request", body, kat.dev)}, nil); c != 202 {
			t.Fatalf("contacts/request: %d, want a silent 202", c)
		}
	}
	requests := func() int {
		n := 0
		for _, it := range bob.inbox() {
			if it.Notice != nil {
				n++
			}
		}
		return n
	}

	send("")
	send("AAAAAAAAAA")
	if n := requests(); n != 0 {
		t.Fatalf("requests without a valid code reached bob: %d", n)
	}

	// A one-use private code works once.
	var res struct {
		Code string     `json:"code"`
		Hash wire.Bytes `json:"hash"`
	}
	call(t, ts, "POST", "invites/create", bob.token, map[string]any{"uses": 1}, &res)
	send(res.Code)
	if n := requests(); n != 1 {
		t.Fatalf("a valid code: %d requests, want 1", n)
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	call(t, ts, "GET", "invites", bob.token, nil, &list)
	if len(list.Items) != 0 {
		t.Fatalf("a used-up code is still listed: %v", list.Items)
	}

	// A revoked code stops working.
	code := bob.invite(false)
	if c := call(t, ts, "POST", "invites/revoke", bob.token, map[string]any{"code": code}, nil); c != 204 {
		t.Fatalf("revoke: %d", c)
	}
	send(code)
	if n := requests(); n != 0 {
		t.Fatalf("a revoked code got through: %d", n)
	}
}

// Public codes are held to the per-sender limits: one request per pair per 7 days (SPEC §9.5).
func TestPublicInviteRateLimit(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	code := bob.invite(true)
	for range 3 {
		body := map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": code}
		call(t, ts, "POST", "contacts/request", kat.token, map[string]any{"request": signed(t, "contact-request", body, kat.dev)}, nil)
	}
	if n := len(bob.inbox()); n != 1 {
		t.Fatalf("bob got %d requests from one sender on a public code, want 1", n)
	}
}

func TestRegistrationNeedsInvite(t *testing.T) {
	ts := testServer(t)
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub)
	genesis := signed(t, "chain-entry", map[string]any{
		"seq": 0, "ts": time.Now().Unix(),
		"ops": []any{
			map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey))},
			map[string]any{"op": "set-home", "home": "chat.test"},
			map[string]any{"op": "set-handle", "handle": "eve.chat.test"},
			map[string]any{"op": "set-recovery", "next": commit[:]},
		},
	}, dev)
	var e wire.Error
	if c := call(t, ts, "POST", "register", "", map[string]any{"genesis": genesis, "invite": "wrong"}, &e); c != 403 || e.Code != wire.ErrCodeBadInvite {
		t.Fatalf("register with a wrong code: %d %q", c, e.Code)
	}
}

func TestReservedHandles(t *testing.T) {
	ts := testServer(t)
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub)
	genesis := signed(t, "chain-entry", map[string]any{
		"seq": 0, "ts": time.Now().Unix(),
		"ops": []any{
			map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey))},
			map[string]any{"op": "set-home", "home": "chat.test"},
			map[string]any{"op": "set-handle", "handle": "reroute.chat.test"},
			map[string]any{"op": "set-recovery", "next": commit[:]},
		},
	}, dev)
	var e wire.Error
	if c := call(t, ts, "POST", "register", "", map[string]any{"genesis": genesis, "invite": testRegCode}, &e); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("registering a reserved name: %d %q", c, e.Code)
	}
}

// SPEC §9.3: a pending request stops letting the other side claim key packages after 30 days.
func TestPendingRequestsExpire(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	call(t, ts, "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil)
	st.Contacts().Put(context.Background(), kat.id, store.Contact{ID: bob.id, State: store.StatePendingOut, Since: time.Now().Unix() - 31*24*3600})
	if c := call(t, ts, "POST", "keypackages/claim", bob.token, map[string]any{"id": kat.id}, nil); c != 403 {
		t.Fatalf("claim on a 31-day-old request: %d, want 403", c)
	}
}

// SPEC §11.6, the `reg` fallback: a committer whose MLS library can't export the next epoch
// key before merging commits with a one-time key and registers the epoch key after.
func TestRegFallback(t *testing.T) {
	ts := testServer(t)
	bob := newUser(t, ts, "bob")
	group := randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, ek1, _ := ed25519.GenerateKey(rand.Reader)
	regPub, reg, _ := ed25519.GenerateKey(rand.Reader)
	call(t, ts, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "group", "epoch-key": []byte(ek0Pub)}, nil)
	commit := func(epoch int, key ed25519.PrivateKey, extra map[string]any) map[string]any {
		data := randBytes(40)
		sum := sha256.Sum256(data)
		body := map[string]any{"group": group, "epoch": epoch, "hash": sum[:]}
		for k, v := range extra {
			body[k] = v
		}
		var res struct {
			Results []map[string]any `json:"results"`
		}
		call(t, ts, "POST", "send", bob.token, map[string]any{"deliveries": []any{map[string]any{
			"id": randBytes(16), "kind": "mls", "to": []string{bob.id}, "group": group, "epoch": epoch, "mls": "commit",
			"data": data, "commit": signed(t, "commit-request", body, key)}}}, &res)
		return res.Results[0]
	}
	if r := commit(0, ek0, map[string]any{"reg": []byte(regPub)}); r["status"] != "sent" {
		t.Fatalf("commit with reg: %v", r)
	}
	// Until the key is registered, nothing else commits.
	if r := commit(1, ek1, map[string]any{"next": randBytes(32)}); r["error"] != wire.ErrCodeAwaitingKey {
		t.Fatalf("commit while awaiting: %v", r)
	}
	register := func(key ed25519.PrivateKey) int {
		k := signed(t, "epoch-key", map[string]any{"group": group, "epoch": 1, "next": []byte(ek1Pub)}, key)
		return call(t, ts, "POST", "groups/epoch-key", bob.token, map[string]any{"key": k}, nil)
	}
	// The epoch-0 key, which a member removed by that commit would know, can't register it.
	if c := register(ek0); c != 409 {
		t.Fatalf("registration signed with the old epoch key: %d", c)
	}
	if c := register(reg); c != 204 {
		t.Fatalf("registration with reg: %d", c)
	}
	// The same registration again (its reply was lost) succeeds without changing anything;
	// the same reg key naming a different key doesn't.
	if c := register(reg); c != 204 {
		t.Fatalf("an exact retry of the registration: %d", c)
	}
	other := signed(t, "epoch-key", map[string]any{"group": group, "epoch": 1, "next": randBytes(32)}, reg)
	if c := call(t, ts, "POST", "groups/epoch-key", bob.token, map[string]any{"key": other}, nil); c != 409 {
		t.Fatalf("a second registration naming another key: %d", c)
	}
	if r := commit(1, ek1, map[string]any{"next": randBytes(32)}); r["status"] != "sent" {
		t.Fatalf("commit after registration: %v", r)
	}
}
