package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

func dialStream(t *testing.T, ts *httptest.Server) *ws.Client {
	t.Helper()
	c, _, err := ws.Dial(strings.Replace(ts.URL, "http://", "http://", 1)+"/.well-known/tieroute/v1/client/stream", "tieroute.v1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// openStream connects and authenticates as u, and returns the stream after "ready".
func openStream(t *testing.T, ts *httptest.Server, u *testUser, after string) *ws.Client {
	t.Helper()
	c := dialStream(t, ts)
	auth := map[string]any{"t": "auth", "token": u.token}
	if after != "" {
		auth["after"] = after
	}
	b, _ := wire.Marshal(auth)
	c.SendText(b)
	if f := frameOf(t, c, "ready"); f == nil {
		t.Fatal("no ready")
	}
	return c
}

// frameOf reads frames until one has type typ.
func frameOf(t *testing.T, c *ws.Client, typ string) map[string]json.RawMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m, err := c.Next(time.Until(deadline))
		if err != nil {
			t.Fatalf("waiting for %q: %v", typ, err)
		}
		var f map[string]json.RawMessage
		json.Unmarshal(m, &f)
		if string(f["t"]) == `"`+typ+`"` {
			return f
		}
	}
	t.Fatalf("no %q frame", typ)
	return nil
}

func closeCode(t *testing.T, c *ws.Client) int {
	t.Helper()
	for {
		_, err := c.Next(5 * time.Second)
		var ce *ws.CloseError
		if errors.As(err, &ce) {
			return ce.Code
		}
		if err != nil {
			t.Fatalf("no close frame: %v", err)
		}
	}
}

// spec/api/conventions.md: the first frame authenticates; anything else closes with 4401.
func TestStreamNeedsAuth(t *testing.T) {
	ts := testServer(t)
	c := dialStream(t, ts)
	c.SendText([]byte(`{"t":"ping","n":1}`))
	if code := closeCode(t, c); code != 4401 {
		t.Fatalf("no auth frame: closed %d, want 4401", code)
	}
	c = dialStream(t, ts)
	c.SendText([]byte(`{"t":"auth","token":"nope"}`))
	if code := closeCode(t, c); code != 4401 {
		t.Fatalf("bad token: closed %d, want 4401", code)
	}
	if _, resp, err := ws.Dial(ts.URL+"/.well-known/tieroute/v1/client/stream", "chat"); err == nil || resp.StatusCode != 400 {
		t.Fatal("another subprotocol was accepted")
	}
}

// Stored items replay after ready, new ones arrive live with cursors, pings get pongs, and
// an ack over the stream works like POST inbox/ack.
func TestStreamReplaysThenGoesLive(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	kat.request(bob, bob.invite(false)) // stored before bob connects
	c := openStream(t, ts, bob, "")
	first := frameOf(t, c, "item")
	if !strings.Contains(string(first["item"]), `"contact-request"`) {
		t.Fatalf("replayed: %s", first["item"])
	}
	c.SendText([]byte(`{"t":"ping","n":7}`))
	if f := frameOf(t, c, "pong"); string(f["n"]) != "7" {
		t.Fatalf("pong: %s", f["n"])
	}
	// Something new arrives while connected: a cancel and a fresh request.
	call(t, ts, "POST", "contacts/block", bob.token, map[string]any{"id": "tr:aaaaaaaaaaaaaaaaaaaaaaaa"}, nil)
	kat2 := newUser(t, ts, "kat2")
	kat2.request(bob, bob.invite(false))
	live := frameOf(t, c, "item")
	var it struct {
		Cursor string `json:"cursor"`
	}
	json.Unmarshal(live["item"], &it)
	if it.Cursor == "" {
		t.Fatalf("a live stored item has no cursor: %s", live["item"])
	}
	b, _ := wire.Marshal(map[string]any{"t": "ack", "upto": it.Cursor})
	c.SendText(b)
	time.Sleep(200 * time.Millisecond)
	if items := bob.inboxNoAck(); len(items) != 0 {
		t.Fatalf("after an ack over the stream, the inbox still has %d items", len(items))
	}
}

// SPEC §13.3: ephemeral deliveries reach connected devices, across servers, and are never
// stored.
func TestEphemeralReachesOnlyConnectedDevices(t *testing.T) {
	a, b, _, _, kat, bob, group := federatedGroup(t)
	bob.inbox()
	c := openStream(t, b, bob, "")
	typing := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id, bob.id}, "group": group, "epoch": 1, "mls": "app", "ephemeral": true, "data": []byte("typing")}
	var sent struct {
		Results []sendResult `json:"results"`
	}
	if call(t, a, "POST", "send", kat.token, map[string]any{"deliveries": []any{typing}}, &sent); sent.Results[0].Status != "sent" {
		t.Fatalf("send: %+v", sent.Results[0])
	}
	f := frameOf(t, c, "item")
	if strings.Contains(string(f["item"]), `"cursor"`) || !strings.Contains(string(f["item"]), `"ephemeral":true`) {
		t.Fatalf("ephemeral item: %s", f["item"])
	}
	if items := bob.inbox(); len(items) != 0 {
		t.Fatalf("an ephemeral delivery was stored: %+v", items)
	}
}

// SPEC §13.2: presence reaches mutual contacts, across servers, and nobody else.
func TestPresenceReachesMutualContacts(t *testing.T) {
	a, b, _, _, kat, bob, _ := federatedGroup(t)
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, nil)
	// Make it mutual on kat's side too (her server promoted bob when his Welcome arrived).
	c := openStream(t, b, bob, "")
	stranger := newUserOn(t, b, "stranger", "b.test")
	sc := openStream(t, b, stranger, "")

	if code := call(t, a, "POST", "presence", kat.token, map[string]any{"state": "busy", "status": "in a meeting"}, nil); code != 204 {
		t.Fatalf("presence: %d", code)
	}
	f := frameOf(t, c, "presence")
	if string(f["id"]) != `"`+kat.id+`"` || string(f["state"]) != `"busy"` || string(f["status"]) != `"in a meeting"` {
		t.Fatalf("bob saw: %v", f)
	}
	if m, err := sc.Next(500 * time.Millisecond); err == nil && strings.Contains(string(m), `"presence"`) {
		t.Fatalf("a stranger got kat's presence: %s", m)
	}
	if code := call(t, a, "POST", "presence", kat.token, map[string]any{"state": "sleepy"}, nil); code != 400 {
		t.Fatalf("an unknown state: %d", code)
	}
}

// SPEC §7.6: removing a device ends its stream with 4403.
func TestRemovedDeviceStreamCloses(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	c := openStream(t, ts, kat, "")
	pub2, dev2, _ := ed25519.GenerateKey(rand.Reader)
	seq, prev := head(t, ts, kat.id)
	add := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "add-device", "key": []byte(pub2)}}}, kat.dev)
	if code := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": add}, nil); code != 200 {
		t.Fatalf("add-device: %d", code)
	}
	sum := sha256.Sum256(add)
	rm := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 2, "prev": sum[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "remove-device", "key": []byte(kat.dev.Public().(ed25519.PublicKey))}}}, dev2)
	if code := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": rm}, nil); code != 200 {
		t.Fatalf("remove-device: %d", code)
	}
	if code := closeCode(t, c); code != 4403 {
		t.Fatalf("the removed device's stream closed with %d, want 4403", code)
	}
}

// inboxNoAck reads the inbox without acking.
func (u *testUser) inboxNoAck() []inboxItem {
	var res struct {
		Items []inboxItem `json:"items"`
	}
	call(u.t, u.ts, "GET", "inbox", u.token, nil, &res)
	return res.Items
}

// A server that caches a remote profile drops its copy when presence says there's a newer
// version, so contacts' clients get the new one (spec/api/client-stage5.md).
func TestPresenceRefreshesCachedProfile(t *testing.T) {
	a, b, _, _, kat, bob, _ := federatedGroup(t)
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, nil)
	version := func() string {
		var got struct {
			Profile wire.Raw `json:"profile"`
		}
		if c := call(t, a, "GET", "profile/"+bob.id, kat.token, nil, &got); c != 200 {
			t.Fatalf("kat reads bob's profile: %d", c)
		}
		sig, _ := wire.DecodeSigned(got.Profile)
		var body struct {
			V int64 `json:"v"`
		}
		sig.Open(&body)
		return fmt.Sprint(body.V)
	}
	call(t, b, "POST", "profile", bob.token, map[string]any{"profile": profile(t, bob, 1, bob.dev, nil)}, nil)
	if v := version(); v != "1" {
		t.Fatalf("first fetch: v%s", v)
	}
	call(t, b, "POST", "presence", bob.token, map[string]any{"state": "online"}, nil)
	if c := call(t, b, "POST", "profile", bob.token, map[string]any{"profile": profile(t, bob, 2, bob.dev, nil)}, nil); c != 204 {
		t.Fatalf("publish v2: %d", c)
	}
	for i := 0; i < 40 && version() != "2"; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if v := version(); v != "2" {
		t.Fatalf("after the presence update, kat's server still serves v%s", v)
	}
}
