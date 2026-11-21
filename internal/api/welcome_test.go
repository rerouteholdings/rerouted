package api

import (
	"testing"
	"time"
)

// A Welcome passes only from the recipient's own identity or a contact, pending outgoing
// included, never by the groups allowlist (SPEC §10.3). Other deliveries for an allowlisted
// group still pass from anyone.
func TestWelcomeNeverByAllowlist(t *testing.T) {
	ts := testServer(t)
	kat, ravi, eve, mia := newV2User(t, ts, "kat", "chat.test"), newV2User(t, ts, "ravi", "chat.test"), newV2User(t, ts, "eve", "chat.test"), newV2User(t, ts, "mia", "chat.test")
	contacts2(t, ravi, kat)
	kat.inbox()
	group := randBytes(32)
	welcome := func(from *v2User, data string) map[string]any {
		return map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 1, "mls": "welcome", "data": []byte(data)}
	}
	// ravi, a contact, adds kat: the Welcome allowlists the group.
	if r := ravi.send2(ts, welcome(ravi, "real")); r.Status != "sent" {
		t.Fatalf("welcome: %+v", r)
	}
	waitDelivery(t, kat, []byte("real"))
	// eve, who isn't a contact, knows the group's ID. Her application message passes by the
	// allowlist, but her Welcome into a group of her own under that ID doesn't.
	app := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("app")}
	if r := eve.send2(ts, app); r.Status != "sent" {
		t.Fatalf("app: %+v", r)
	}
	waitDelivery(t, kat, []byte("app"))
	if r := eve.send2(ts, welcome(eve, "forged")); r.Status != "sent" {
		t.Fatalf("eve's welcome: %+v", r)
	}
	time.Sleep(200 * time.Millisecond)
	for _, it := range kat.inbox() {
		if it.Delivery != nil && string(it.Delivery.Data) == "forged" {
			t.Fatal("a Welcome passed by the groups allowlist")
		}
	}
	// From kat's own identity, and from mia, whom kat has asked to be a contact.
	if r := kat.send2(ts, welcome(kat, "own")); r.Status != "sent" {
		t.Fatalf("own welcome: %+v", r)
	}
	waitDelivery(t, kat, []byte("own"))
	if c := kat.request(mia, mia.invite()); c != 202 {
		t.Fatalf("request: %d", c)
	}
	if r := mia.send2(ts, welcome(mia, "pending")); r.Status != "sent" {
		t.Fatalf("mia's welcome: %+v", r)
	}
	waitDelivery(t, kat, []byte("pending"))
}
