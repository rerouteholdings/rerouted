package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// Wire version 2 has every endpoint version 1 has (SPEC Appendix A), with version 2's
// objects: account keys and data, backups, files, profiles, presence, call relays, reports,
// and moves, on one server and across servers.

// raw2 sends raw bytes to a version 2 client endpoint, and returns the status, content type,
// and body.
func raw2(t *testing.T, ts *httptest.Server, method, path, token, ctype string, data []byte) (int, string, []byte) {
	t.Helper()
	var rd io.Reader
	if data != nil {
		rd = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, ts.URL+v2Client+path, rd)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

// v2Contacts makes u and v mutual contacts: u asks with v's invite, v accepts, and v's
// Welcome to u, in a group it returns, tells u's server.
func v2Contacts(t *testing.T, u, v *v2User) []byte {
	t.Helper()
	call2(t, u.ts, "GET", "resolve/"+v.handle, u.token, nil, nil)
	if c := u.request(v, v.invite()); c != 202 {
		t.Fatalf("request: %d", c)
	}
	v.eventually(1)
	if c := call2(t, v.ts, "POST", "contacts/accept", v.token, map[string]any{"id": u.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}
	group := randBytes(32)
	welcome := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{u.id}, "group": group, "epoch": 1, "mls": "welcome", "data": []byte("welcome")}
	if c := call2(t, v.ts, "POST", "send", v.token, map[string]any{"deliveries": []any{welcome}}, nil); c != 200 {
		t.Fatalf("welcome: %d", c)
	}
	u.eventually(1)
	return group
}

// waitFor polls u's inbox until a delivery from `from` carries `data`.
func (u *v2User) waitFor(from, data string) {
	u.t.Helper()
	for range 100 {
		for _, it := range u.inbox() {
			if it.Delivery != nil && it.Delivery.From == from && string(it.Delivery.Data) == data {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	u.t.Fatalf("%s never got %q from %s", u.handle, data, from)
}

// openStream opens u's version 2 stream, after "ready".
func (u *v2User) openStream() *ws.Client {
	u.t.Helper()
	c, _, err := ws.Dial(u.ts.URL+v2Client+"stream", "tieroute.v2")
	if err != nil {
		u.t.Fatal(err)
	}
	u.t.Cleanup(c.Close)
	b, _ := wire.Marshal(map[string]any{"t": "auth", "token": u.token})
	c.SendText(b)
	frameOf(u.t, c, "ready")
	return c
}

// recoveryEntry is a recovery-signed entry on u's head: signed by recovery key `by`, whose
// whole composite key goes in k (SPEC §3.2.2), committing to `next`.
func (u *v2User) recoveryEntry(by *wire.CompositePrivateKey, next []byte, ops ...any) wire.Raw {
	return signedFull2(u.t, "chain-entry", u.entry(append(ops, map[string]any{"op": "set-recovery", "next": next})...), by)
}

func setWrap2(t *testing.T, u *v2User, via string, commit []byte, ct string) (int, wire.Error) {
	t.Helper()
	w := map[string]any{"via": via, "ct": []byte(ct)}
	if commit != nil {
		w["commit"] = commit
	}
	var e wire.Error
	c := call2(t, u.ts, "POST", "account/keys", u.token, map[string]any{"set": w}, &e)
	return c, e
}

func listWraps2(t *testing.T, u *v2User) []listedWrap {
	t.Helper()
	var res struct {
		Items []listedWrap `json:"items"`
	}
	if c := call2(t, u.ts, "GET", "account/keys", u.token, nil, &res); c != 200 {
		t.Fatalf("account/keys: %d", c)
	}
	return res.Items
}

// SPEC §7.4, §6.3: account data, and recovery wraps decided against a version 2 chain,
// whose set-recovery ops commit to composite recovery keys. A rotation stages the new
// code's wrap, appends the recovery-signed entry, and promotes it.
func TestV2AccountKeysAndData(t *testing.T) {
	ts := testServer(t)
	kat := newV2User(t, ts, "kat", "chat.test")
	ravi := newV2User(t, ts, "ravi", "chat.test")

	// Account data: versioned, and a stale write is refused.
	var put struct {
		Version int64 `json:"version"`
	}
	if c := call2(t, ts, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, &put); c != 200 || put.Version != 1 {
		t.Fatalf("account data: %d %+v", c, put)
	}
	var e wire.Error
	if c := call2(t, ts, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, &e); c != 409 || e.Code != wire.ErrCodeStaleVersion {
		t.Fatalf("a stale write: %d %+v", c, e)
	}
	var got struct {
		Version int64      `json:"version"`
		CT      wire.Bytes `json:"ct"`
	}
	if c := call2(t, ts, "GET", "account/data", kat.token, nil, &got); c != 200 || got.Version != 1 || len(got.CT) != 64 {
		t.Fatalf("read back: %d %+v", c, got)
	}
	if c := call2(t, ts, "GET", "account/data", ravi.token, nil, &got); c != 200 || got.Version != 0 {
		t.Fatalf("someone else's account data: %d %+v", c, got)
	}

	// The passphrase wrap.
	pw := map[string]any{"via": "passphrase", "ct": randBytes(32), "argon2": map[string]any{"salt": randBytes(16), "m": 65536, "t": 3, "p": 1}}
	if c := call2(t, ts, "POST", "account/keys", kat.token, map[string]any{"set": pw}, nil); c != 204 {
		t.Fatalf("passphrase wrap: %d", c)
	}

	// Recovery wraps name the commitment to their code's key 1: the SHA-256 of its composite
	// public key, which the genesis committed to.
	code1 := kat.rec[0].Public().Hash()
	if c, e := setWrap2(t, kat, "recovery", code1, "code 1"); c != 204 {
		t.Fatalf("the first recovery wrap: %d %+v", c, e)
	}
	// A rotation to a new code: stage, append, promote.
	code2 := newComposite(t)
	if c, e := setWrap2(t, kat, "recovery", code2.Public().Hash(), "code 2, early"); c != 409 || e.Code != wire.ErrCodeStaleVersion {
		t.Fatalf("promoting a code the chain doesn't commit to: %d %+v", c, e)
	}
	if c, e := setWrap2(t, kat, "recovery-next", code2.Public().Hash(), "code 2"); c != 204 {
		t.Fatalf("staging: %d %+v", c, e)
	}
	if c, e := kat.appendSigned(kat.recoveryEntry(kat.rec[0], code2.Public().Hash())); c != 200 {
		t.Fatalf("the rotation: %d %+v", c, e)
	}
	if c, e := setWrap2(t, kat, "recovery", code2.Public().Hash(), "code 2"); c != 204 {
		t.Fatalf("promoting: %d %+v", c, e)
	}
	if c := call2(t, ts, "POST", "account/keys", kat.token, map[string]any{"remove": "recovery-next", "commit": code2.Public().Hash()}, nil); c != 204 {
		t.Fatalf("cleanup: %d", c)
	}
	// Listed: the current wrap and the passphrase; the replaced one is retained, unlisted.
	var vias []string
	for _, w := range listWraps2(t, kat) {
		vias = append(vias, w.Via)
		if w.Via == "recovery" && (string(w.CT) != "code 2" || !bytes.Equal(w.Commit, code2.Public().Hash())) {
			t.Fatalf("the current wrap: %q", w.CT)
		}
	}
	slices.Sort(vias)
	if !slices.Equal(vias, []string{"passphrase", "recovery"}) {
		t.Fatalf("listed wraps: %v", vias)
	}
	// The old code's wrap can't come back, and forgetting it waits 72 hours.
	if c, e := setWrap2(t, kat, "recovery", code1, "code 1 again"); c != 409 || e.Code != wire.ErrCodeStaleVersion {
		t.Fatalf("a stale promotion: %d %+v", c, e)
	}
	if c, e := func() (int, wire.Error) {
		var e wire.Error
		return call2(t, ts, "POST", "account/keys", kat.token, map[string]any{"remove": "retained"}, &e), e
	}(); c != 429 || e.Retry == 0 {
		t.Fatalf("forgetting within 72 hours: %d %+v", c, e)
	}
	if c := call2(t, ts, "POST", "account/keys", kat.token, map[string]any{"remove": "passphrase"}, nil); c != 204 {
		t.Fatalf("removing the passphrase wrap: %d", c)
	}
}

// SPEC §7.5: backups on the version 2 API.
func TestV2Backups(t *testing.T) {
	ts := testServerCfg(t, newStore(t), func(c *config.Config) { c.BackupQuota = 1000 })
	kat := newV2User(t, ts, "kat", "chat.test")
	put := func(seq int, ct []byte, snapshot bool) int {
		body := map[string]any{"seq": seq, "ct": ct}
		if snapshot {
			body["snapshot"] = true
		}
		return call2(t, ts, "POST", "backup/put", kat.token, body, nil)
	}
	if c := put(0, randBytes(300), true); c != 204 {
		t.Fatalf("segment 0: %d", c)
	}
	s1 := randBytes(300)
	if c := put(1, s1, false); c != 204 {
		t.Fatalf("segment 1: %d", c)
	}
	if c := put(1, randBytes(300), false); c != 409 {
		t.Fatalf("other bytes for segment 1: %d", c)
	}
	if c := put(2, randBytes(500), false); c != 413 {
		t.Fatalf("over quota: %d", c)
	}
	var list struct {
		Segments []struct {
			Seq int64 `json:"seq"`
		} `json:"segments"`
	}
	if c := call2(t, ts, "GET", "backup/list", kat.token, nil, &list); c != 200 || len(list.Segments) != 2 {
		t.Fatalf("list: %d %+v", c, list)
	}
	var got struct {
		CT wire.Bytes `json:"ct"`
	}
	if c := call2(t, ts, "GET", "backup/get?seq=1", kat.token, nil, &got); c != 200 || !bytes.Equal(got.CT, s1) {
		t.Fatalf("get: %d", c)
	}
}

// SPEC §13.1, §14: a profile signed with a device's composite key, its picture, and files,
// fetched across servers through version 2 S2S profile/fetch and media/fetch.
func TestV2ProfilesAndFiles(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, b, "ravi", "b.test")
	call2(t, a, "GET", "resolve/ravi.b.test", kat.token, nil, nil)

	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	c, _, body := raw2(t, b, "POST", "media/upload-public", ravi.token, "image/png", png)
	if c != 200 {
		t.Fatalf("upload a picture: %d %s", c, body)
	}
	var pic struct {
		Media map[string]any `json:"media"`
	}
	wire.Unmarshal(body, &pic)
	profile := func(v int, by *wire.CompositePrivateKey, extra map[string]any) map[string]any {
		p := map[string]any{"id": ravi.id, "v": v, "ts": time.Now().Unix(), "name": "Ravi"}
		for k, x := range extra {
			p[k] = x
		}
		return p
	}
	post := func(p wire.Raw) (int, wire.Error) {
		var e wire.Error
		return call2(t, b, "POST", "profile", ravi.token, map[string]any{"profile": p}, &e), e
	}
	if c, e := post(signed2(t, "profile", profile(1, ravi.dev, map[string]any{"avatar": pic.Media}), ravi.dev)); c != 204 {
		t.Fatalf("publish: %d %+v", c, e)
	}
	// Signed with Ed25519 alone, even by his device's own component: not a device signature.
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if c, e := post(signed(t, "profile", profile(2, nil, nil), ed)); c != 400 || e.Code != wire.ErrCodeBadSignature {
		t.Fatalf("an Ed25519 profile: %d %+v", c, e)
	}
	forged, _ := wire.SignComposite("profile", profile(2, nil, nil), newComposite(t))
	forged.K = edOf(ravi.dev)
	fenc, _ := forged.Encode()
	if c, _ := post(fenc); c != 403 {
		t.Fatalf("another key under his device's name: %d", c)
	}
	if c, _ := post(signed2(t, "profile", profile(1, nil, nil), ravi.dev)); c != 409 {
		t.Fatalf("the same version again: %d", c)
	}

	// Kat fetches it through a.test, and checks it against his chain.
	var got struct {
		Profile wire.Raw `json:"profile"`
	}
	if c := call2(t, a, "GET", "profile/"+ravi.id, kat.token, nil, &got); c != 200 {
		t.Fatalf("profile across servers: %d", c)
	}
	sig, err := wire.DecodeSignedV2(got.Profile)
	if err != nil || sig.VerifyComposite("profile", ravi.dev.Public()) != nil || !strings.Contains(sig.B, `"v":1`) {
		t.Fatalf("the fetched profile doesn't verify: %v", err)
	}
	// His picture and a file, through a.test.
	if c, ctype, b := raw2(t, a, "GET", "media/b.test/"+pic.Media["id"].(string), kat.token, "", nil); c != 200 || ctype != "image/png" || !bytes.Equal(b, png) {
		t.Fatalf("the picture across servers: %d %s", c, ctype)
	}
	data := []byte("pretend this is AES-GCM ciphertext")
	_, _, body = raw2(t, b, "POST", "media/upload", ravi.token, "application/octet-stream", data)
	var file struct {
		ID     string     `json:"id"`
		SHA256 wire.Bytes `json:"sha256"`
	}
	wire.Unmarshal(body, &file)
	if sum := sha256.Sum256(data); !bytes.Equal(file.SHA256, sum[:]) {
		t.Fatalf("upload: %s", body)
	}
	if c, _, b := raw2(t, a, "GET", "media/b.test/"+file.ID, kat.token, "", nil); c != 200 || !bytes.Equal(b, data) {
		t.Fatalf("a file across servers: %d", c)
	}
	id, _ := base64.RawURLEncoding.DecodeString(file.ID)
	sb.st.Media().Remove(context.Background(), id)
	if c, _, b := raw2(t, a, "GET", "media/b.test/"+file.ID, kat.token, "", nil); c != 410 || !strings.Contains(string(b), "removed") {
		t.Fatalf("a removed file: %d %s", c, b)
	}
	// The version 1 API serves the same files: IDs are one namespace, unguessable.
	ravi1 := newUserOn(t, b, "ravi1", "b.test")
	if code, _, b := download(t, b, ravi1.token, "media/b.test/"+pic.Media["id"].(string)); code != 200 || !bytes.Equal(b, png) {
		t.Fatalf("the picture on version 1: %d", code)
	}
}

// SPEC §13.2: presence between version 2 contacts on two servers, with the profile version.
func TestV2Presence(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, b, "ravi", "b.test")
	stranger := newV2User(t, a, "stranger", "a.test")
	v2Contacts(t, ravi, kat)
	c := kat.openStream()
	sc := stranger.openStream()
	if code := call2(t, b, "POST", "profile", ravi.token, map[string]any{"profile": signed2(t, "profile", map[string]any{"id": ravi.id, "v": 3, "ts": time.Now().Unix()}, ravi.dev)}, nil); code != 204 {
		t.Fatalf("profile: %d", code)
	}
	if code := call2(t, b, "POST", "presence", ravi.token, map[string]any{"state": "busy", "status": "in a meeting"}, nil); code != 204 {
		t.Fatalf("presence: %d", code)
	}
	f := frameOf(t, c, "presence")
	if string(f["id"]) != `"`+ravi.id+`"` || string(f["state"]) != `"busy"` || string(f["status"]) != `"in a meeting"` || string(f["pv"]) != "3" {
		t.Fatalf("kat saw: %v", f)
	}
	if m, err := sc.Next(500 * time.Millisecond); err == nil && strings.Contains(string(m), `"presence"`) {
		t.Fatalf("a stranger got ravi's presence: %s", m)
	}
	if code := call2(t, b, "POST", "presence", ravi.token, map[string]any{"state": "sleepy"}, nil); code != 400 {
		t.Fatalf("an unknown state: %d", code)
	}
}

// SPEC §15.1: relay credentials on the version 2 API.
func TestV2Turn(t *testing.T) {
	secret := "a shared secret for coturn"
	ts := testServerCfg(t, newStore(t), func(c *config.Config) {
		c.TurnURLs, c.TurnSecret = []string{"turn:turn.chat.test:3478"}, secret
	})
	kat := newV2User(t, ts, "kat", "chat.test")
	var res struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
		TTL        int64    `json:"ttl"`
	}
	if c := call2(t, ts, "GET", "turn", kat.token, nil, &res); c != 200 || len(res.URLs) != 1 || res.TTL == 0 {
		t.Fatalf("turn: %d %+v", c, res)
	}
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(res.Username))
	if res.Credential != base64.StdEncoding.EncodeToString(m.Sum(nil)) || !strings.HasSuffix(res.Username, ":"+kat.id) {
		t.Fatalf("credentials don't verify: %+v", res)
	}
}

// SPEC §6.6, §6.5: a version 2 identity moves, end to end, across three servers. Its
// contact's server learns the new home from the old home's S2S identity/push, and
// deliveries go both ways from the new home.
func TestV2MoveEndToEnd(t *testing.T) {
	ts, srv := threeServers(t)
	a, b, c := ts["a.test"], ts["b.test"], ts["c.test"]
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, c, "ravi", "c.test")
	v2Contacts(t, kat, ravi)
	ravi.inbox() // drain

	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	call2(t, a, "GET", "chain/"+kat.id, "", nil, &ch)
	entry := signed2(t, "chain-entry", kat.entry(map[string]any{"op": "set-home", "home": "b.test"}, map[string]any{"op": "set-handle", "handle": "kat.b.test"}), kat.dev)
	head := sha256.Sum256(entry)
	move := signed2(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{ravi.id}, "groups": []wire.Bytes{}}, kat.dev)
	var check struct {
		Reservation wire.Raw `json:"reservation"`
	}
	if code := call2(t, b, "POST", "register", "", map[string]any{"chain": append(ch.Entries, entry), "move": move, "invite": testRegCode, "check": true}, &check); code != 200 || check.Reservation == nil {
		t.Fatalf("check: %d", code)
	}
	if code := call2(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": entry, "reservation": check.Reservation}, nil); code != 200 {
		t.Fatalf("append the move: %d", code)
	}
	// a.test pushes the move to c.test, which tells ravi.
	var pushed bool
	for range 100 {
		for _, it := range ravi.inbox() {
			pushed = pushed || (it.Notice != nil && strings.Contains(string(it.Notice), `"chain-update"`) && strings.Contains(string(it.Notice), kat.id))
		}
		if pushed {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !pushed {
		t.Fatal("ravi never heard of the move")
	}
	if st, _, err := srv["c.test"].V2().lookup(context.Background(), kat.id, ""); err != nil || st.Home != "b.test" {
		t.Fatalf("c.test's copy of kat's chain: %v", err)
	}
	call2(t, a, "GET", "chain/"+kat.id, "", nil, &ch)
	if code := call2(t, b, "POST", "register", "", map[string]any{"chain": ch.Entries, "move": move, "invite": testRegCode}, nil); code != 200 {
		t.Fatalf("register at b.test: %d", code)
	}
	kat.ts, kat.server = b, "b.test"
	kat.token = kat.signIn(kat.dev)
	kat.uploadKPs(kat.dev, kat.token, "kp-kat-at-b")
	// Her app fetches her contacts' chains at the new home, with their homes as hints, as
	// it does for anyone it talks to: the new home only routes to identities it has fetched.
	if code := call2(t, b, "GET", "chain/"+ravi.id+"?home=c.test", kat.token, nil, nil); code != 200 {
		t.Fatalf("ravi's chain at the new home: %d", code)
	}

	// Both ways, from the new home.
	g1, g2 := randBytes(32), randBytes(32)
	send := func(u *v2User, to string, group []byte, data string) {
		t.Helper()
		w := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{to}, "group": group, "epoch": 1, "mls": "welcome", "data": []byte("welcome")}
		m := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{to}, "group": group, "epoch": 1, "mls": "app", "data": []byte(data)}
		var sr struct {
			Results []sendResult `json:"results"`
		}
		if code := call2(t, u.ts, "POST", "send", u.token, map[string]any{"deliveries": []any{w, m}}, &sr); code != 200 || sr.Results[1].Status != "sent" {
			t.Fatalf("send: %d %+v", code, sr)
		}
	}
	send(kat, ravi.id, g1, "from my new home")
	ravi.waitFor(kat.id, "from my new home")
	send(ravi, kat.id, g2, "to your new home")
	kat.waitFor(ravi.id, "to your new home")
	var cl claimed
	if code := call2(t, c, "POST", "keypackages/claim", ravi.token, map[string]any{"id": kat.id}, &cl); code != 200 || len(cl.Packages) != 1 {
		t.Fatalf("claiming her packages at the new home: %d %+v", code, cl)
	}
	checkBinding(t, kat.id, kat.dev, cl.Packages[0].KP, cl.Packages[0].Binding)
}

// moveTo moves u from its home to `server` (ts) with a device-signed move, the destination's
// reservation, and a registration there, and signs u in there (SPEC §6.6).
func (u *v2User) moveTo(ts *httptest.Server, server, handle string) {
	u.t.Helper()
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	call2(u.t, u.ts, "GET", "chain/"+u.id, "", nil, &ch)
	entry := signed2(u.t, "chain-entry", u.entry(map[string]any{"op": "set-home", "home": server}, map[string]any{"op": "set-handle", "handle": handle}), u.dev)
	head := sha256.Sum256(entry)
	move := signed2(u.t, "move", map[string]any{"id": u.id, "server": server, "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, u.dev)
	var check struct {
		Reservation wire.Raw `json:"reservation"`
	}
	if c := call2(u.t, ts, "POST", "register", "", map[string]any{"chain": append(ch.Entries, entry), "move": move, "invite": testRegCode, "check": true}, &check); c != 200 {
		u.t.Fatalf("check at %s: %d", server, c)
	}
	if c := call2(u.t, u.ts, "POST", "chain/append", u.token, map[string]any{"entry": entry, "reservation": check.Reservation}, nil); c != 200 {
		u.t.Fatalf("append the move to %s: %d", server, c)
	}
	call2(u.t, u.ts, "GET", "chain/"+u.id, "", nil, &ch)
	if c := call2(u.t, ts, "POST", "register", "", map[string]any{"chain": ch.Entries, "move": move, "invite": testRegCode}, nil); c != 200 {
		u.t.Fatalf("register at %s: %d", server, c)
	}
	u.ts, u.server, u.seq, u.head = ts, server, u.seq+1, head[:]
	u.token = u.signIn(u.dev)
}

// A version 2 identity moves away and comes back with a recovery-signed move (SPEC §6.6):
// that needs no reservation, its old name was held for it at the old home and is its
// again, and the return clears its earlier stay's account data and passphrase wrap but
// keeps its recovery wrap (SPEC §7.4).
func TestV2MoveAndReturnByRecovery(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	code1 := kat.rec[0].Public().Hash()
	if c, e := setWrap2(t, kat, "recovery", code1, "code 1"); c != 204 {
		t.Fatalf("recovery wrap: %d %+v", c, e)
	}
	pw := map[string]any{"via": "passphrase", "ct": randBytes(32), "argon2": map[string]any{"salt": randBytes(16), "m": 65536, "t": 3, "p": 1}}
	call2(t, a, "POST", "account/keys", kat.token, map[string]any{"set": pw}, nil)
	call2(t, a, "POST", "account/data", kat.token, map[string]any{"ct": randBytes(64), "replaces": 0}, nil)

	kat.moveTo(b, "b.test", "kat.b.test")
	if got := resolvesTo(t, b, v2Client, kat.token, "kat.b.test"); got != kat.id {
		t.Fatalf("her name at b.test resolves to %q", got)
	}

	// Back to a.test, recovery-signed: no reservation needed.
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	back := kat.recoveryEntry(kat.rec[0], kat.rec[1].Public().Hash(), map[string]any{"op": "set-home", "home": "a.test"}, map[string]any{"op": "set-handle", "handle": "kat.a.test"})
	if c, e := kat.appendSigned(back); c != 200 {
		t.Fatalf("the recovery-signed move back: %d %+v", c, e)
	}
	call2(t, b, "GET", "chain/"+kat.id, "", nil, &ch)
	h := sha256.Sum256(ch.Entries[len(ch.Entries)-1])
	mv := signed2(t, "move", map[string]any{"id": kat.id, "server": "a.test", "head": h[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call2(t, a, "POST", "register", "", map[string]any{"chain": ch.Entries, "move": mv, "invite": testRegCode}, nil); c != 200 {
		t.Fatalf("register the return: %d", c)
	}
	kat.ts, kat.server = a, "a.test"
	kat.token = kat.signIn(kat.dev)
	if got := resolvesTo(t, a, v2Client, kat.token, "kat.a.test"); got != kat.id {
		t.Fatalf("her old name at a.test resolves to %q", got)
	}
	var data struct {
		Version int64 `json:"version"`
	}
	call2(t, a, "GET", "account/data", kat.token, nil, &data)
	var vias []string
	for _, w := range listWraps2(t, kat) {
		vias = append(vias, w.Via)
	}
	if data.Version != 0 || !slices.Equal(vias, []string{"recovery"}) {
		t.Fatalf("after the return: account data v%d, wraps %v", data.Version, vias)
	}
	// b.test holds kat.b.test for her now.
	other := newComposite(t)
	g := signed2(t, "chain-entry", map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		addDevice(other, ""), map[string]any{"op": "set-home", "home": "b.test"},
		map[string]any{"op": "set-handle", "handle": "kat.b.test"},
		map[string]any{"op": "set-recovery", "next": newComposite(t).Public().Hash()},
	}}, other)
	if c := call2(t, b, "POST", "register", "", map[string]any{"genesis": g, "invite": testRegCode}, nil); c != 409 {
		t.Fatalf("her name at b.test, after she left: %d", c)
	}
}
