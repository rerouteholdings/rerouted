package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// request sends a contact request from u to `to`, with code.
func (u *testUser) request(to *testUser, code string) {
	u.t.Helper()
	body := map[string]any{"from": u.id, "to": to.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": code}
	if c := call(u.t, u.ts, "POST", "contacts/request", u.token, map[string]any{"request": signed(u.t, "contact-request", body, u.dev)}, nil); c != 202 {
		u.t.Fatalf("contacts/request: %d", c)
	}
}

func notices(items []inboxItem, t string) []map[string]json.RawMessage {
	var out []map[string]json.RawMessage
	for _, it := range items {
		var n map[string]json.RawMessage
		if it.Notice != nil && json.Unmarshal(it.Notice, &n) == nil && string(n["t"]) == `"`+t+`"` {
			out = append(out, n)
		}
	}
	return out
}

func contactState(t *testing.T, u *testUser, id string) string {
	t.Helper()
	var res struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"items"`
	}
	call(t, u.ts, "GET", "contacts", u.token, nil, &res)
	for _, c := range res.Items {
		if c.ID == id {
			return c.State
		}
	}
	return ""
}

// SPEC §9.3: a decline reaches the requester across servers, clears their request, and
// keeps them from asking again for 30 days, even with a new code.
func TestDeclineAcrossServers(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat, ravi := newUserOn(t, a, "kat", "a.test"), newUserOn(t, b, "ravi", "b.test")
	call(t, a, "GET", "resolve/ravi.b.test", kat.token, nil, nil)
	kat.request(ravi, ravi.invite(false))
	req := notices(ravi.eventually(1), "contact-request")
	if len(req) != 1 {
		t.Fatal("no request")
	}
	sig, err := wire.DecodeSigned(req[0]["request"])
	if err != nil {
		t.Fatal(err)
	}
	h, _ := sig.Hash()

	// A decline that names some other request is refused.
	bogus := signed(t, "contact-decline", map[string]any{"from": ravi.id, "to": kat.id, "request": randBytes(32), "ts": time.Now().Unix()}, ravi.dev)
	if c := call(t, b, "POST", "contacts/decline", ravi.token, map[string]any{"decline": bogus}, nil); c != 404 {
		t.Fatalf("a decline for no such request: %d, want 404", c)
	}
	decline := signed(t, "contact-decline", map[string]any{"from": ravi.id, "to": kat.id, "request": h, "ts": time.Now().Unix()}, ravi.dev)
	if c := call(t, b, "POST", "contacts/decline", ravi.token, map[string]any{"decline": decline}, nil); c != 202 {
		t.Fatalf("decline: %d", c)
	}
	if got := notices(kat.eventually(1), "contact-declined"); len(got) != 1 {
		t.Fatal("kat wasn't told")
	}
	if s := contactState(t, kat, ravi.id); s != "" {
		t.Fatalf("kat's request is still %q", s)
	}
	if s := contactState(t, ravi, kat.id); s != "" {
		t.Fatalf("a declined requester shows in ravi's contacts as %q", s)
	}

	// Kat asks again with a fresh code: dropped for 30 days.
	kat.request(ravi, ravi.invite(false))
	time.Sleep(500 * time.Millisecond)
	if got := notices(ravi.inbox(), "contact-request"); len(got) != 0 {
		t.Fatal("a declined requester got through again")
	}
}

// SPEC §9.6: cancel withdraws an outgoing request; remove takes someone off the list; block
// drops their requests whatever code they carry, and unblock lifts it.
func TestCancelRemoveBlock(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")

	kat.request(bob, bob.invite(false))
	if s := contactState(t, kat, bob.id); s != "pending-out" {
		t.Fatalf("after a request: %q", s)
	}
	if c := call(t, ts, "POST", "contacts/cancel", kat.token, map[string]any{"id": bob.id}, nil); c != 204 {
		t.Fatalf("cancel: %d", c)
	}
	if c := call(t, ts, "POST", "contacts/cancel", kat.token, map[string]any{"id": bob.id}, nil); c != 404 {
		t.Fatalf("cancel again: %d, want 404", c)
	}

	// Bob makes kat a contact, then removes her.
	bob.inbox()
	kat.request(bob, bob.invite(false))
	call(t, ts, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil)
	if c := call(t, ts, "POST", "contacts/remove", bob.token, map[string]any{"id": kat.id}, nil); c != 204 {
		t.Fatalf("remove: %d", c)
	}
	if s := contactState(t, bob, kat.id); s != "" {
		t.Fatalf("after remove: %q", s)
	}

	// Blocked: even a valid code goes nowhere.
	bob.inbox()
	if c := call(t, ts, "POST", "contacts/block", bob.token, map[string]any{"id": kat.id}, nil); c != 204 {
		t.Fatalf("block: %d", c)
	}
	kat.request(bob, bob.invite(false))
	if got := notices(bob.inbox(), "contact-request"); len(got) != 0 {
		t.Fatal("a blocked identity's request arrived")
	}
	if c := call(t, ts, "POST", "contacts/unblock", bob.token, map[string]any{"id": kat.id}, nil); c != 204 {
		t.Fatalf("unblock: %d", c)
	}
	kat.request(bob, bob.invite(false))
	if got := notices(bob.inbox(), "contact-request"); len(got) != 1 {
		t.Fatal("after unblocking, a request with a valid code didn't arrive")
	}
	if c := call(t, ts, "POST", "contacts/block", bob.token, map[string]any{"id": "not-an-id"}, nil); c != 400 {
		t.Fatalf("blocking a non-identifier: %d", c)
	}
}
