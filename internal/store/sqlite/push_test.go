package sqlite

import (
	"context"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// A device has one token, a token belongs to one device, and tokens go with their device
// or identity.
func TestPushTokens(t *testing.T) {
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	p := st.ForWire(2).Push() // one table for every wire version
	list := func(id string) []store.APNSToken {
		t.Helper()
		ts, err := st.Push().APNS(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	put := func(id, dev, tok string) {
		t.Helper()
		if err := p.PutAPNS(ctx, store.APNSToken{ID: id, Device: []byte(dev), Token: tok, Env: "sandbox", Updated: 1}); err != nil {
			t.Fatal(err)
		}
	}
	put("kat", "phone", "aa")
	put("kat", "phone", "bb") // the phone's new token replaces its old one
	put("kat", "tablet", "cc")
	if ts := list("kat"); len(ts) != 2 || ts[0].Token != "bb" || string(ts[0].Device) != "phone" || ts[1].Token != "cc" {
		t.Fatalf("kat: %+v", ts)
	}
	put("ravi", "laptop", "cc") // the tablet's token moves to Ravi
	if ts := list("kat"); len(ts) != 1 || ts[0].Token != "bb" {
		t.Fatalf("kat after the move: %+v", ts)
	}
	if ts := list("ravi"); len(ts) != 1 || ts[0].Token != "cc" || string(ts[0].Device) != "laptop" {
		t.Fatalf("ravi: %+v", ts)
	}
	p.DeleteAPNS(ctx, "kat", "cc") // not Kat's: nothing happens
	if len(list("ravi")) != 1 {
		t.Fatal("Kat deleted Ravi's token")
	}
	p.DropAPNSDevice(ctx, "kat", []byte("phone"))
	p.DropAPNSToken(ctx, "cc")
	if len(list("kat"))+len(list("ravi")) != 0 {
		t.Fatal("tokens left")
	}
	put("kat", "phone", "aa")
	put("kat", "tablet", "bb")
	p.DropAPNSIdentity(ctx, "kat")
	if len(list("kat")) != 0 {
		t.Fatal("tokens left after the identity left")
	}
}
