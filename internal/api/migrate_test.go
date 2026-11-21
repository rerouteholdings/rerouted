package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Migrating from wire version 1 to version 2 (SPEC §6.8), server side: the version 1
// migrate and the version 2 registration in one step, closed chains, handles, refused
// deliveries, and contacts carried over once both sides migrate.

// migration is a version 1 user's migration, built but not sent: the version 2 genesis and
// the entry that appends migrate.
type migration struct {
	v2      *v2User
	genesis wire.Raw
	entry   wire.Raw
}

// prepareMigration makes u's version 2 genesis, on server, with handle, and the version 1
// entry that names it.
func (u *testUser) prepareMigration(ts *httptest.Server, server, handle string) migration {
	u.t.Helper()
	t := u.t
	n := &v2User{t: t, ts: ts, server: server, dev: newComposite(t), rec: []*wire.CompositePrivateKey{newComposite(t), newComposite(t)}, handle: handle}
	genesis := signed2(t, "chain-entry", map[string]any{
		"seq": 0, "ts": time.Now().Unix(),
		"ops": []any{
			addDevice(n.dev, "laptop"),
			map[string]any{"op": "set-home", "home": server},
			map[string]any{"op": "set-handle", "handle": handle},
			map[string]any{"op": "set-recovery", "next": n.rec[0].Public().Hash()},
			map[string]any{"op": "migrated-from", "id": u.id},
		},
	}, n.dev)
	gh := sha256.Sum256(genesis)
	n.id, n.head = wire.IdentityIDFromHash(gh[:]), gh[:]
	entries := u.chainOf(u.ts)
	head := sha256.Sum256(entries[len(entries)-1])
	entry := signed(t, "chain-entry", map[string]any{
		"id": u.id, "seq": len(entries), "prev": head[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "migrate", "to": gh[:]}},
	}, u.dev)
	return migration{v2: n, genesis: genesis, entry: entry}
}

// migrate appends m's entry, with its genesis, through version 1 chain/append.
func (u *testUser) migrate(m migration) (int, wire.Error, string) {
	u.t.Helper()
	var res struct {
		ID string `json:"id"`
		wire.Error
	}
	body := map[string]any{"entry": m.entry}
	if m.genesis != nil {
		body["genesis"] = m.genesis
	}
	c := call(u.t, u.ts, "POST", "chain/append", u.token, body, &res)
	return c, res.Error, res.ID
}

// migrateTo migrates u to a version 2 identity on server, keeping its handle, and signs it in.
func (u *testUser) migrateTo(ts *httptest.Server, server string) *v2User {
	u.t.Helper()
	m := u.prepareMigration(ts, server, u.handle)
	if c, e, id := u.migrate(m); c != 200 || id != m.v2.id {
		u.t.Fatalf("migrate %s: %d %+v %s", u.handle, c, e, id)
	}
	m.v2.token = m.v2.signIn(m.v2.dev)
	m.v2.uploadKPs(m.v2.dev, m.v2.token, "kp2-"+u.handle)
	return m.v2
}

// befriend makes a and b full contacts on version 1, on the servers they're on: a request
// each way.
func befriend(t *testing.T, a, b *testUser) {
	t.Helper()
	wait := func(u *testUser, other, state string) {
		for range 100 {
			if contactState(t, u, other) == state {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: %s never became %s", u.handle, other, state)
	}
	for _, p := range [][2]*testUser{{a, b}, {b, a}} {
		from, to := p[0], p[1]
		if c := call(t, from.ts, "GET", "resolve/"+to.handle, from.token, nil, nil); c != 200 {
			t.Fatalf("resolve %s: %d", to.handle, c)
		}
		from.request(to, to.invite(false))
		if from == a {
			wait(b, a.id, store.StatePendingIn)
		}
	}
	wait(a, b.id, store.StateContact)
	wait(b, a.id, store.StateContact)
	a.inbox()
	b.inbox()
}

func contactsOf2(u *v2User) map[string]string {
	u.t.Helper()
	var res struct {
		Items []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"items"`
	}
	if c := call2(u.t, u.ts, "GET", "contacts", u.token, nil, &res); c != 200 {
		u.t.Fatalf("contacts: %d", c)
	}
	out := map[string]string{}
	for _, it := range res.Items {
		out[it.ID] = it.State
	}
	return out
}

type sendResults struct {
	Results []sendResult `json:"results"`
}

func app1(to []string, group []byte, data string) map[string]any {
	return map[string]any{"id": randBytes(16), "kind": "mls", "to": to, "group": group, "epoch": 1, "mls": "app", "data": []byte(data)}
}

func TestMigrateOneServer(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat, ravi, eve := newUser(t, ts, "kat"), newUser(t, ts, "ravi"), newUser(t, ts, "eve")
	befriend(t, kat, ravi)
	befriend(t, kat, eve)
	group := randBytes(32)
	for _, u := range []*testUser{kat, ravi, eve} {
		if c := call(t, ts, "POST", "groups/register", u.token, map[string]any{"group": group}, nil); c != 204 {
			t.Fatalf("groups/register: %d", c)
		}
	}
	m := kat.prepareMigration(ts, "chat.test", kat.handle)

	// The version 2 identity isn't registered on its own, before migrate: anyone can sign a
	// genesis that names someone's version 1 identity.
	var e wire.Error
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": m.genesis}, &e); c != 403 || e.Code != wire.ErrCodeNotAllowed {
		t.Fatalf("version 2 registration before migrate: %d %+v", c, e)
	}
	// migrate needs the genesis, the right one, and a handle that's free.
	if c, e, _ := kat.migrate(migration{entry: m.entry}); c != 400 || e.Code != wire.ErrCodeBadRequest {
		t.Fatalf("migrate without the genesis: %d %+v", c, e)
	}
	other := kat.prepareMigration(ts, "chat.test", kat.handle)
	if c, e, _ := kat.migrate(migration{entry: m.entry, genesis: other.genesis}); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("migrate with a genesis it doesn't name: %d %+v", c, e)
	}
	taken := kat.prepareMigration(ts, "chat.test", eve.handle)
	if c, e, _ := kat.migrate(taken); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("migrate to someone else's handle: %d %+v", c, e)
	}
	elsewhere := kat.prepareMigration(ts, "b.test", "kat.b.test")
	if c, e, _ := kat.migrate(elsewhere); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("migrate to a version 2 identity on another server: %d %+v", c, e)
	}
	if n := len(kat.chainOf(ts)); n != 1 {
		t.Fatalf("a refused migrate changed the chain: %d entries", n)
	}

	// Done: one step registers the version 2 identity, with the handle.
	if c, e, id := kat.migrate(m); c != 200 || id != m.v2.id {
		t.Fatalf("migrate: %d %+v %s", c, e, id)
	}
	if c, _, _ := kat.migrate(m); c != 200 {
		t.Fatalf("a retried migrate: %d", c)
	}
	var reg struct {
		ID string `json:"id"`
	}
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": m.genesis}, &reg); c != 200 || reg.ID != m.v2.id {
		t.Fatalf("version 2 registration after migrate: %d %s", c, reg.ID)
	}
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": other.genesis}, &e); c != 409 || e.Code != wire.ErrCodeAlreadyExists {
		t.Fatalf("another version 2 genesis after migrate: %d %+v", c, e)
	}
	kat2 := m.v2
	kat2.token = kat2.signIn(kat2.dev)
	kat2.uploadKPs(kat2.dev, kat2.token, "kp2-kat")
	if alarms := notices(kat.inbox(), "chain-alert"); len(alarms) != 1 || string(alarms[0]["level"]) != `"alarm"` {
		t.Fatalf("the device-signed migrate's alarm: %v", alarms)
	}

	// The version 1 chain is closed.
	entries := kat.chainOf(ts)
	head := sha256.Sum256(entries[len(entries)-1])
	after := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": len(entries), "prev": head[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-handle", "handle": "kat9.chat.test"}}}, kat.dev)
	if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": after}, &e); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("an entry after migrate: %d %+v", c, e)
	}
	// Nor can a recovery-signed entry follow it. (One that forks from the migrate's position
	// undoes the migration instead: unmigrate_test.go.)
	next := sha256.Sum256(randBytes(32))
	onTop := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": len(entries), "prev": head[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-recovery", "next": next[:]}}}, kat.rec)
	if c := call(t, ts, "POST", "recover", "", map[string]any{"entry": onTop}, &e); c != 400 || e.Code != wire.ErrCodeInvalidChain {
		t.Fatalf("a recovery entry after migrate: %d %+v", c, e)
	}

	// Handles: version 1 no longer resolves it, version 2 resolves the version 2 identity.
	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call(t, ts, "GET", "resolve/kat.chat.test", ravi.token, nil, &e); c != 404 || e.Msg != migratedMsg {
		t.Fatalf("version 1 resolve: %d %+v", c, e)
	}
	if c := call2(t, ts, "GET", "resolve/kat.chat.test", kat2.token, nil, &res); c != 200 || res.ID != kat2.id {
		t.Fatalf("version 2 resolve: %d %+v", c, res)
	}
	if id := handleDocID(t, ts, "kat.chat.test"); id != kat2.id {
		t.Fatalf("handle document: %s", id)
	}
	// Version 2 clients can read the closed version 1 chain, to check the link; no other.
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	if c := call2(t, ts, "GET", "chain/"+kat.id, kat2.token, nil, &ch); c != 200 || len(ch.Entries) != 2 {
		t.Fatalf("the closed chain on version 2: %d %d", c, len(ch.Entries))
	}
	if c := call2(t, ts, "GET", "chain/"+ravi.id, kat2.token, nil, nil); c != 404 {
		t.Fatalf("an open version 1 chain on version 2: %d", c)
	}

	// Deliveries to the version 1 identity are refused out loud: for it alone, the send
	// result says so; with others, they get it, and the sender hears who didn't.
	var sr sendResults
	if c := call(t, ts, "POST", "send", ravi.token, map[string]any{"deliveries": []any{app1([]string{kat.id}, group, "lost?")}}, &sr); c != 200 || sr.Results[0].Error != wire.ErrCodeMigrated {
		t.Fatalf("send to a migrated identity: %d %+v", c, sr)
	}
	if c := call(t, ts, "POST", "send", ravi.token, map[string]any{"deliveries": []any{app1([]string{kat.id, eve.id}, group, "hi both")}}, &sr); c != 200 || sr.Results[0].Status != "sent" {
		t.Fatalf("send to a migrated identity and another: %d %+v", c, sr)
	}
	eve.waitFor(ravi.id, "hi both")
	failed := notices(ravi.inbox(), "delivery-failed")
	if len(failed) != 1 || string(failed[0]["reason"]) != `"migrated"` || string(failed[0]["to"]) != `["`+kat.id+`"]` {
		t.Fatalf("ravi's delivery-failed: %v", failed)
	}
	for _, it := range kat.inbox() {
		if it.Delivery != nil {
			t.Fatalf("the migrated identity got a delivery: %+v", it.Delivery)
		}
	}
	// It can't send, take contact requests, or have its key packages claimed.
	if c := call(t, ts, "POST", "send", kat.token, map[string]any{"deliveries": []any{app1([]string{ravi.id}, group, "from the past")}}, &sr); c != 200 || sr.Results[0].Error != wire.ErrCodeMigrated {
		t.Fatalf("send from a migrated identity: %d %+v", c, sr)
	}
	if c := call(t, ts, "POST", "keypackages/claim", ravi.token, map[string]any{"id": kat.id}, &e); c != 410 || e.Code != wire.ErrCodeMigrated {
		t.Fatalf("claim from a migrated identity: %d %+v", c, e)
	}
	req := signed(t, "contact-request", map[string]any{"from": eve.id, "to": kat.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": "x"}, eve.dev)
	if c := call(t, ts, "POST", "contacts/request", eve.token, map[string]any{"request": req}, &e); c != 410 || e.Code != wire.ErrCodeMigrated {
		t.Fatalf("a request to a migrated identity: %d %+v", c, e)
	}

	// The allowlists came along. Contacts who haven't migrated wait under their version 1
	// identifiers; once Ravi migrates, the two are contacts as version 2 identities.
	if got := contactsOf2(kat2); len(got) != 2 || got[ravi.id] != store.StateContact || got[eve.id] != store.StateContact {
		t.Fatalf("kat2's contacts: %v", got)
	}
	if ok, _ := st.Contacts().GroupAllowed(context.Background(), kat2.id, group); !ok {
		t.Fatal("the groups allowlist didn't come along")
	}
	ravi2 := ravi.migrateTo(ts, "chat.test")
	if got := contactsOf2(kat2); len(got) != 2 || got[ravi2.id] != store.StateContact || got[eve.id] != store.StateContact {
		t.Fatalf("kat2's contacts after ravi migrated: %v", got)
	}
	if got := contactsOf2(ravi2); len(got) != 1 || got[kat2.id] != store.StateContact {
		t.Fatalf("ravi2's contacts: %v", got)
	}
	if updates := notices(kat2.inbox(), "chain-update"); len(updates) != 1 || string(updates[0]["id"]) != `"`+ravi2.id+`"` {
		t.Fatalf("kat2's chain-update: %v", updates)
	}
	// An entry left behind under a version 1 identifier that's known to have migrated is
	// rewritten when the list is read.
	if err := st.Contacts().Put(context.Background(), kat2.id, store.Contact{ID: ravi.id, State: store.StateContact}); err != nil {
		t.Fatal(err)
	}
	if got := contactsOf2(kat2); len(got) != 2 || got[ravi2.id] != store.StateContact {
		t.Fatalf("kat2's contacts, reconciled: %v", got)
	}
	var cl claimed
	if c := call2(t, ts, "POST", "keypackages/claim", ravi2.token, map[string]any{"id": kat2.id}, &cl); c != 200 || len(cl.Packages) != 1 {
		t.Fatalf("ravi2 claims kat2's packages: %d %+v", c, cl)
	}
	if c := call2(t, ts, "POST", "send", ravi2.token, map[string]any{"deliveries": []any{app1([]string{kat2.id}, group, "hello again")}}, &sr); c != 200 || sr.Results[0].Status != "sent" {
		t.Fatalf("version 2 send: %d %+v", c, sr)
	}
	if items := kat2.inbox(); !slices.ContainsFunc(items, func(it inboxItem) bool { return it.Delivery != nil && string(it.Delivery.Data) == "hello again" }) {
		t.Fatalf("kat2's inbox: %+v", items)
	}
	// A version 2 genesis that names a version 1 identity this server doesn't have.
	if c := call2(t, ts, "POST", "register", "", map[string]any{"genesis": newUser(t, testServer(t), "sam").prepareMigration(ts, "chat.test", "sam.chat.test").genesis}, &e); c != 403 {
		t.Fatalf("a migration from another server's identity: %d %+v", c, e)
	}
}

func handleDocID(t *testing.T, ts *httptest.Server, handle string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/.well-known/tieroute/handle", nil)
	req.Host = handle
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var d struct {
		ID string `json:"id"`
	}
	json.Unmarshal(b, &d)
	return d.ID
}

// Across servers, a delivery to a migrated identity from a server that hasn't heard yet
// is refused by its server, and the sender hears.
func TestMigrateDeliveryInFlight(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, b, "ravi", "b.test")
	// Kat has no contacts on b.test, so it doesn't hear about her migration; Ravi only
	// shares a group with her.
	group := randBytes(32)
	call(t, a, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil)
	if c := call(t, b, "GET", "chain/"+kat.id+"?home=a.test", ravi.token, nil, nil); c != 200 {
		t.Fatalf("ravi fetches kat's chain: %d", c)
	}

	kat2 := kat.migrateTo(a, "a.test")

	var sr sendResults
	if c := call(t, b, "POST", "send", ravi.token, map[string]any{"deliveries": []any{app1([]string{kat.id}, group, "too late")}}, &sr); c != 200 || sr.Results[0].Status != "sent" {
		t.Fatalf("send: %d %+v", c, sr)
	}
	var failed []map[string]json.RawMessage
	for range 100 {
		if failed = notices(ravi.inbox(), "delivery-failed"); len(failed) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(failed) != 1 || string(failed[0]["reason"]) != `"migrated"` || string(failed[0]["to"]) != `["`+kat.id+`"]` {
		t.Fatalf("ravi's delivery-failed: %v", failed)
	}
	// b.test fetched the chain again, so the next one is refused right away.
	if c := call(t, b, "POST", "send", ravi.token, map[string]any{"deliveries": []any{app1([]string{kat.id}, group, "again")}}, &sr); c != 200 || sr.Results[0].Error != wire.ErrCodeMigrated {
		t.Fatalf("send after b.test learned: %d %+v", c, sr)
	}
	if kat2.id == "" {
		t.Fatal("no version 2 identity")
	}
}

// Contacts on two servers both migrate, and carry on as version 2 identities: each server
// rewrote its own users' lists, one at the migration and the other when the version 1
// chain was pushed to it.
func TestMigrateFederatedContacts(t *testing.T) {
	for _, katFirst := range []bool{true, false} {
		name := map[bool]string{true: "kat first", false: "sam first"}[katFirst]
		t.Run(name, func(t *testing.T) { federatedContacts(t, katFirst) })
	}
}

func federatedContacts(t *testing.T, katFirst bool) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	sam := newUserOn(t, b, "sam", "b.test")
	befriend(t, kat, sam)
	// Whoever goes first, the other's server hears through the push of the closed chain.
	first, second, firstTS, secondTS, firstName, secondName := kat, sam, a, b, "a.test", "b.test"
	if !katFirst {
		first, second, firstTS, secondTS, firstName, secondName = sam, kat, b, a, "b.test", "a.test"
	}
	first2 := first.migrateTo(firstTS, firstName)
	for range 100 {
		if notices(second.inbox(), "chain-update") != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The first's version 2 chain changes while the second is still on version 1: its server
	// pushes the change to the second's anyway, for the contact carried over there.
	if c, e := first2.appendSigned(signed2(t, "chain-entry", first2.entry(addDevice(newComposite(t), "phone")), first2.dev)); c != 200 {
		t.Fatalf("first2 adds a device: %d %+v", c, e)
	}
	second2 := second.migrateTo(secondTS, secondName)
	var chain struct {
		Entries []wire.Raw `json:"entries"`
	}
	for range 100 {
		if c := call2(t, secondTS, "GET", "chain/"+first2.id, second2.token, nil, &chain); c == 200 && len(chain.Entries) == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(chain.Entries) != 2 {
		t.Fatalf("%s's copy of %s's chain has %d entries, not the pushed 2", secondName, firstName, len(chain.Entries))
	}
	kat2, sam2 := first2, second2
	if !katFirst {
		kat2, sam2 = second2, first2
	}
	var sr sendResults
	if got := contactsOf2(sam2); len(got) != 1 || got[kat2.id] != store.StateContact {
		t.Fatalf("sam2's contacts: %v", got)
	}
	var got map[string]string
	for range 100 {
		if got = contactsOf2(kat2); got[sam2.id] == store.StateContact {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(got) != 1 || got[sam2.id] != store.StateContact {
		t.Fatalf("kat2's contacts: %v", got)
	}
	var cl claimed
	if c := call2(t, b, "POST", "keypackages/claim", sam2.token, map[string]any{"id": kat2.id}, &cl); c != 200 || len(cl.Packages) != 1 {
		t.Fatalf("sam2 claims kat2's packages across servers: %d %+v", c, cl)
	}
	checkBinding(t, kat2.id, kat2.dev, cl.Packages[0].KP, cl.Packages[0].Binding)
	group2 := randBytes(32)
	welcome := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat2.id}, "group": group2, "epoch": 1, "mls": "welcome", "data": []byte("w")}
	if c := call2(t, b, "POST", "send", sam2.token, map[string]any{"deliveries": []any{welcome, app1([]string{kat2.id}, group2, "both on 2")}}, &sr); c != 200 || sr.Results[1].Status != "sent" {
		t.Fatalf("send: %d %+v", c, sr)
	}
	for range 100 {
		if slices.ContainsFunc(kat2.inbox(), func(it inboxItem) bool { return it.Delivery != nil && string(it.Delivery.Data) == "both on 2" }) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("kat2 never got sam2's message")
}

// A contact carried over from wire version 1 who sends a contact request again, as one
// whose app hadn't noticed the other migrated did (SPEC §6.8, §9.3): the requester's own
// entry stays a contact instead of turning into a pending request, the recipient gets the
// notice, and accepting it answers 200, not 404 not-found, since it's accepted already.
func TestMigratedContactAsksAgain(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	sam := newUserOn(t, b, "sam", "b.test")
	befriend(t, kat, sam)
	kat2 := kat.migrateTo(a, "a.test")
	for range 100 {
		if notices(sam.inbox(), "chain-update") != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sam2 := sam.migrateTo(b, "b.test")
	for range 100 {
		if contactsOf2(kat2)[sam2.id] == store.StateContact {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := contactsOf2(kat2); got[sam2.id] != store.StateContact {
		t.Fatalf("kat2's contacts before the request: %v", got)
	}
	// Sam's app resolves Kat first, as any request does, so b.test has her chain.
	if c := call2(t, b, "GET", "chain/"+kat2.id+"?home=a.test", sam2.token, nil, nil); c != 200 {
		t.Fatalf("sam2 fetches kat2's chain: %d", c)
	}
	if c := sam2.request(kat2, kat2.invite()); c != 202 {
		t.Fatalf("sam2's request: %d", c)
	}
	if got := contactsOf2(sam2); got[kat2.id] != store.StateContact {
		t.Fatalf("sam2's entry for kat2 after asking again: %v, want it still a contact", got)
	}
	var got []map[string]json.RawMessage
	for range 100 {
		if got = notices(kat2.inbox(), "contact-request"); got != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got == nil {
		t.Fatal("kat2 never got sam2's request")
	}
	if list := contactsOf2(kat2); list[sam2.id] != store.StateContact {
		t.Fatalf("kat2's contacts after the request: %v", list)
	}
	var e wire.Error
	if c := call2(t, a, "POST", "contacts/accept", kat2.token, map[string]any{"id": sam2.id}, &e); c != 200 {
		t.Fatalf("kat2 accepts a request from a contact: %d %+v, want 200", c, e)
	}
	if c := call2(t, a, "POST", "contacts/accept", kat2.token, map[string]any{"id": wire.IdentityIDFromHash(randBytes(32))}, &e); c != 404 {
		t.Fatalf("accepting someone who never asked: %d, want 404", c)
	}
}

// A handle whose record still names the version 1 identity, as one on the user's own
// domain does until they update it, resolves to the version 2 identity for version 2
// clients (SPEC §5.3 step 3), and not at all for version 1 ones.
func TestMigrateResolveFollows(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	const own = "kat.invalid"
	entries := kat.chainOf(a)
	head := sha256.Sum256(entries[len(entries)-1])
	rename := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": len(entries), "prev": head[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-handle", "handle": own}}}, kat.dev)
	if c := call(t, a, "POST", "chain/append", kat.token, map[string]any{"entry": rename}, nil); c != 200 {
		t.Fatalf("set-handle: %d", c)
	}
	kat.handle = own
	kat2 := kat.migrateTo(a, "a.test")

	txt := func(context.Context, string) ([]string, error) { return []string{"id=" + kat.id + " home=a.test"}, nil }
	sb.fed.LookupTXT, sb.V2().fed.LookupTXT = txt, txt
	ravi2 := newV2User(t, b, "ravi", "b.test")
	ravi1 := newUserOn(t, b, "ravi1", "b.test")
	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call2(t, b, "GET", "resolve/"+own, ravi2.token, nil, &res); c != 200 || res.ID != kat2.id || res.Home != "a.test" {
		t.Fatalf("version 2 resolve: %d %+v", c, res)
	}
	var e wire.Error
	if c := call(t, b, "GET", "resolve/"+own, ravi1.token, nil, &e); c != 404 || e.Msg != migratedMsg {
		t.Fatalf("version 1 resolve: %d %+v", c, e)
	}
}

// A version 2 client checking a migration fetches the version 1 chain through its own
// homeserver's version 2 API, with its session (SPEC §6.8, Appendix A): `fresh` asks the
// identity's home, so a chain that ended in migrate after the server cached it, or that it
// never had, is found; a local one needs no home. An open version 1 chain stays a stranger
// there, and without a session `fresh` for a remote identity is refused.
func TestV1ChainFreshOnV2(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	sam := newUserOn(t, b, "sam", "b.test")
	kat2 := kat.migrateTo(a, "a.test")
	var ch struct {
		Entries []wire.Raw `json:"entries"`
	}
	path := "chain/" + sam.id + "?home=b.test&fresh=1"
	if c := call2(t, a, "GET", path, kat2.token, nil, nil); c != 404 {
		t.Fatalf("sam's open version 1 chain on version 2: %d", c)
	}
	sam.migrateTo(b, "b.test")
	if c := call2(t, a, "GET", path, kat2.token, nil, &ch); c != 200 || len(ch.Entries) != 2 {
		t.Fatalf("sam's closed version 1 chain, fresh from b.test: %d %d", c, len(ch.Entries))
	}
	if c := call2(t, a, "GET", "chain/"+kat.id+"?home=a.test&fresh=1", kat2.token, nil, &ch); c != 200 || len(ch.Entries) != 2 {
		t.Fatalf("kat's own closed version 1 chain, fresh: %d %d", c, len(ch.Entries))
	}
	if c := call2(t, a, "GET", path, "", nil, nil); c != 401 {
		t.Fatalf("fresh without a session: %d", c)
	}
}
