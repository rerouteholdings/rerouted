package api

import (
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// pushChain lists contacts before routing. Count that boundary so an accepted
// old registration cannot quietly trigger new pushes on a retry.
type moveRoutingStore struct {
	store.Store
	lists atomic.Int64
}
type moveRoutingContacts struct {
	store.Contacts
	owner *moveRoutingStore
}

func (s *moveRoutingStore) Contacts() store.Contacts {
	return moveRoutingContacts{s.Store.Contacts(), s}
}
func (c moveRoutingContacts) List(ctx context.Context, owner, after string, limit int) ([]store.Contact, string, error) {
	c.owner.lists.Add(1)
	return c.Contacts.List(ctx, owner, after, limit)
}

func TestMoveFreshSignatureAfterReceiptAges(t *testing.T) {
	var stores []*moveRoutingStore
	a, b, _, sb := twoServersWithStore(t, func() store.Store {
		st := newStore(t)
		wrapped := &moveRoutingStore{Store: st}
		stores = append(stores, wrapped)
		return wrapped
	})
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, b, "ravi", "b.test")
	noor := newUserOn(t, b, "noor", "b.test")
	entry := kat.moveEntry(kat.chainOf(a), "b.test", "kat.b.test")
	if c := kat.leave(a, b, entry, "b.test"); c != 200 {
		t.Fatal(c)
	}
	entries := kat.chainOf(a)
	head := sha256.Sum256(entry)
	groups := []wire.Bytes{randBytes(32), randBytes(32)}
	makeMove := func(ts int64, contacts []string, groups []wire.Bytes) wire.Raw {
		return signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": ts, "contacts": contacts, "groups": groups}, kat.dev)
	}
	oldTS := time.Now().Unix() - 599
	old := makeMove(oldTS, []string{ravi.id, noor.id}, groups)
	req := map[string]any{"chain": entries, "move": old, "invite": testRegCode}
	if c := call(t, b, "POST", "register", "", req, nil); c != 200 {
		t.Fatalf("initial registration: %d", c)
	}
	// Simulate a lost reply followed by user edits and the original proof aging out.
	ctx := context.Background()
	if err := sb.st.Contacts().Delete(ctx, kat.id, ravi.id); err != nil {
		t.Fatal(err)
	}
	if err := sb.st.Contacts().DisallowGroup(ctx, kat.id, groups[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	var e wire.Error
	if c := call(t, b, "POST", "register", "", req, &e); c != 400 || e.Code != wire.ErrCodeClockSkew {
		t.Fatalf("expired proof: %d %s", c, e.Code)
	}
	// The completed operation must work without contacting its now-offline old home.
	a.Close()
	lists := stores[1].lists.Load()
	req["move"] = makeMove(time.Now().Unix(), []string{noor.id, ravi.id, ravi.id}, []wire.Bytes{groups[1], groups[0], groups[0]})
	if c := call(t, b, "POST", "register", "", req, nil); c != 200 {
		t.Fatalf("fresh same-intent retry: %d", c)
	}
	if stores[1].lists.Load() != lists {
		t.Fatal("retry entered chain routing")
	}
	if _, err := sb.st.Contacts().Get(ctx, kat.id, ravi.id); err == nil {
		t.Fatal("fresh retry restored removed contact")
	}
	if ok, _ := sb.st.Contacts().GroupAllowed(ctx, kat.id, groups[0]); ok {
		t.Fatal("fresh retry restored removed group")
	}
	req["move"] = makeMove(time.Now().Unix(), []string{noor.id}, groups)
	if c := call(t, b, "POST", "register", "", req, nil); c != 409 {
		t.Fatalf("changed intent at accepted head: %d", c)
	}
	if stores[1].lists.Load() != lists {
		t.Fatal("conflicting retry entered chain routing")
	}
}
