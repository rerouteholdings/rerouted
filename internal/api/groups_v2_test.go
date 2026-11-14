package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Groups and their hub in wire version 2 (SPEC §11.5, §11.6, §11.11): composite epoch keys,
// commit requests signed with them, and receipts signed with the hub's composite server key.

// epochKey is a stand-in for epoch_key_N, which members derive from the MLS exporter: the
// hub only ever sees its public half and signatures by it.
func epochKey(t *testing.T) *wire.CompositePrivateKey { return newComposite(t) }

func pubOf(k *wire.CompositePrivateKey) []byte { return k.Public().Bytes() }

// commitReq builds a commit-request signed with epoch key ek, carrying next or reg.
func commitReq(t *testing.T, group []byte, epoch uint64, data []byte, ek *wire.CompositePrivateKey, member string, key []byte) wire.Raw {
	t.Helper()
	sum := sha256.Sum256(data)
	return signedFull2(t, "commit-request", map[string]any{"group": group, "epoch": epoch, "hash": sum[:], member: key}, ek)
}

// commitOut is an outgoing commit for POST send, with a Welcome for welcomeTo if it isn't empty.
func commitOut(group []byte, epoch uint64, to []string, data []byte, cr wire.Raw, hub string, welcomeTo ...string) map[string]any {
	o := map[string]any{"id": randBytes(16), "kind": "mls", "to": to, "group": group, "epoch": epoch, "mls": "commit", "data": data, "commit": cr}
	if hub != "" {
		o["hub"] = hub
	}
	if len(welcomeTo) > 0 {
		o["welcomes"] = []any{map[string]any{"id": randBytes(16), "to": welcomeTo, "data": []byte("mls-welcome")}}
	}
	return o
}

// send2 sends one delivery and returns its result.
func (u *v2User) send2(ts *httptest.Server, d map[string]any) sendResult {
	u.t.Helper()
	var sr sendResults
	if c := call2(u.t, ts, "POST", "send", u.token, map[string]any{"deliveries": []any{d}}, &sr); c != 200 || len(sr.Results) != 1 {
		u.t.Fatalf("send: %d %+v", c, sr)
	}
	return sr.Results[0]
}

// checkReceipt verifies a version 2 commit receipt as a client does (SPEC §11.6): signed by
// the hub's composite server key, naming the hub, group, epoch, and commit hash.
func checkReceipt(t *testing.T, raw []byte, hub *Server, group []byte, epoch uint64, data []byte) {
	t.Helper()
	sig, err := wire.DecodeSignedV2(raw)
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if sig.KID != hub.key.V2.KID || len(sig.K) != 0 {
		t.Fatalf("receipt names key %q, want the hub's composite key %q", sig.KID, hub.key.V2.KID)
	}
	if err := sig.VerifyComposite("commit-receipt", hub.key.V2.Priv.Public()); err != nil {
		t.Fatalf("receipt signature: %v", err)
	}
	var b struct {
		Hub   string     `json:"hub"`
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
		Hash  wire.Bytes `json:"hash"`
		TS    int64      `json:"ts"`
	}
	if err := sig.OpenClosed(&b); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if b.Hub != hub.cfg.Name || !bytes.Equal(b.Group, group) || b.Epoch != epoch || !bytes.Equal(b.Hash, sum[:]) || b.TS == 0 {
		t.Fatalf("receipt body: %+v", b)
	}
}

// contacts2 makes a and b full contacts on version 2: a requests with b's invite, b accepts.
func contacts2(t *testing.T, a, b *v2User) {
	t.Helper()
	if c := call2(t, a.ts, "GET", "resolve/"+b.handle, a.token, nil, nil); c != 200 {
		t.Fatalf("resolve %s: %d", b.handle, c)
	}
	if c := a.request(b, b.invite()); c != 202 {
		t.Fatalf("request: %d", c)
	}
	b.eventually(1)
	if c := call2(t, b.ts, "POST", "contacts/accept", b.token, map[string]any{"id": a.id}, nil); c != 200 {
		t.Fatalf("accept: %d", c)
	}
}

// One server: creating a group, sequencing commits with next and with reg, the receipt and
// its retry, every refusal of the hub step, and fetching missed commits.
func TestV2HubLocal(t *testing.T) {
	ts, _, s, _ := twoServers(t)
	kat, ravi := newV2User(t, ts, "kat", "a.test"), newV2User(t, ts, "ravi", "a.test")
	contacts2(t, kat, ravi)
	kat.inbox()
	ravi.inbox()

	group := randBytes(32)
	ek0, ek1 := epochKey(t), epochKey(t)
	create := map[string]any{"group": group, "kind": "group", "epoch-key": randBytes(32)}
	if c := call2(t, ts, "POST", "groups/create", ravi.token, create, nil); c != 400 {
		t.Fatalf("a version 1 epoch key: %d, want 400", c)
	}
	bad := pubOf(ek0)
	bad = append(bytes.Clone(bad[:len(bad)-32]), make([]byte, 32)...) // a small-order Ed25519 component
	create["epoch-key"] = bad
	if c := call2(t, ts, "POST", "groups/create", ravi.token, create, nil); c != 400 {
		t.Fatalf("a small-order Ed25519 component: %d, want 400", c)
	}
	create["epoch-key"] = pubOf(ek0)
	if c := call2(t, ts, "POST", "groups/create", ravi.token, create, nil); c != 204 {
		t.Fatalf("groups/create: %d", c)
	}
	var e wire.Error
	if c := call2(t, ts, "POST", "groups/create", kat.token, create, &e); c != 409 || e.Code != wire.ErrCodeAlreadyExists {
		t.Fatalf("the same ID again: %d %+v", c, e)
	}

	members := []string{ravi.id}
	data := []byte("mls-commit-add-kat")
	refused := func(name string, d map[string]any, code string) {
		t.Helper()
		if r := ravi.send2(ts, d); r.Status != "rejected" || r.Error != code {
			t.Fatalf("%s: %+v, want %s", name, r, code)
		}
	}
	// Refusals that leave the group at epoch 0.
	refused("next and reg", commitOut(group, 0, members, data, signedFull2(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sha(data), "next": pubOf(ek1), "reg": pubOf(epochKey(t))}, ek0), ""), wire.ErrCodeBadRequest)
	refused("neither", commitOut(group, 0, members, data, signedFull2(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sha(data)}, ek0), ""), wire.ErrCodeBadRequest)
	refused("a 32-byte next", commitOut(group, 0, members, data, commitReq(t, group, 0, data, ek0, "next", randBytes(32)), ""), wire.ErrCodeBadRequest)
	refused("the wrong hash", commitOut(group, 0, members, []byte("other"), commitReq(t, group, 0, data, ek0, "next", pubOf(ek1)), ""), wire.ErrCodeBadRequest)
	refused("another key", commitOut(group, 0, members, data, commitReq(t, group, 0, data, epochKey(t), "next", pubOf(ek1)), ""), wire.ErrCodeBadSignature)
	// The epoch key's Ed25519 component alone, as version 1 signs, isn't the epoch key.
	v1sig := signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sha(data), "next": pubOf(ek1)}, ed25519.NewKeyFromSeed(randBytes(32)))
	refused("an Ed25519 signature", commitOut(group, 0, members, data, v1sig, ""), wire.ErrCodeBadSignature)
	// The epoch key named by kid, or by its Ed25519 component, isn't either.
	byComponent := signed2(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sha(data), "next": pubOf(ek1)}, ek0)
	refused("k names only the component", commitOut(group, 0, members, data, byComponent, ""), wire.ErrCodeBadSignature)
	refused("an unknown group", commitOut(randBytes(32), 0, members, data, commitReq(t, group, 0, data, ek0, "next", pubOf(ek1)), ""), wire.ErrCodeBadRequest)
	other := randBytes(32)
	refused("a group the hub doesn't know", commitOut(other, 0, members, data, commitReq(t, other, 0, data, ek0, "next", pubOf(ek1)), ""), wire.ErrCodeNotFound)
	// A PublicMessage (version mls10, wire_format public_message) isn't sent at all.
	pm := []byte{0, 1, 0, 1, 9, 9}
	refused("a PublicMessage", commitOut(group, 0, members, pm, commitReq(t, group, 0, pm, ek0, "next", pubOf(ek1)), ""), wire.ErrCodeBadRequest)
	refused("a PublicMessage app message", map[string]any{"id": randBytes(16), "kind": "mls", "to": members, "group": group, "epoch": 0, "mls": "app", "data": pm}, wire.ErrCodeBadRequest)

	// Accepted: the receipt is signed with the server's composite key, and the commit and its
	// Welcome are delivered with it.
	cr := commitReq(t, group, 0, data, ek0, "next", pubOf(ek1))
	add := commitOut(group, 0, members, data, cr, "", kat.id)
	r := ravi.send2(ts, add)
	if r.Status != "sent" {
		t.Fatalf("commit: %+v", r)
	}
	checkReceipt(t, r.Receipt, s.v2, group, 0, data)
	items := kat.eventually(1)
	if items[0].Delivery.MLS != "welcome" || items[0].Delivery.Epoch != 1 {
		t.Fatalf("kat's Welcome: %+v", items[0].Delivery)
	}
	if c := call2(t, ts, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil); c != 204 {
		t.Fatalf("groups/register: %d", c)
	}
	got := ravi.eventually(1)
	if got[0].Delivery.MLS != "commit" || !bytes.Equal(got[0].Delivery.Receipt, r.Receipt) {
		t.Fatalf("ravi's copy of the commit: %+v", got[0].Delivery)
	}

	// The identical request again, as after a lost reply: the same receipt. Anything else
	// for epoch 0 lost the race.
	add["id"] = randBytes(16)
	if again := ravi.send2(ts, add); again.Status != "sent" || !bytes.Equal(again.Receipt, r.Receipt) {
		t.Fatalf("an identical retry: %+v", again)
	}
	refused("another commit for epoch 0", commitOut(group, 0, members, []byte("late"), commitReq(t, group, 0, []byte("late"), ek0, "next", pubOf(epochKey(t))), ""), wire.ErrCodeStaleEpoch)
	refused("epoch 1 signed with epoch 0's key", commitOut(group, 1, members, []byte("c1"), commitReq(t, group, 1, []byte("c1"), ek0, "next", pubOf(epochKey(t))), ""), wire.ErrCodeBadSignature)

	// Epoch 1, with the reg fallback: the hub awaits the key, then takes it from reg only.
	members = []string{ravi.id, kat.id}
	reg, ek2 := epochKey(t), epochKey(t)
	c1 := []byte("mls-commit-1")
	var kr sendResults
	if c := call2(t, ts, "POST", "send", kat.token, map[string]any{"deliveries": []any{commitOut(group, 1, members, c1, commitReq(t, group, 1, c1, ek1, "reg", pubOf(reg)), "")}}, &kr); c != 200 || kr.Results[0].Status != "sent" {
		t.Fatalf("a reg commit: %d %+v", c, kr)
	}
	refused("a commit while the hub awaits the key", commitOut(group, 2, members, []byte("c2"), commitReq(t, group, 2, []byte("c2"), ek2, "next", pubOf(epochKey(t))), ""), wire.ErrCodeAwaitingKey)
	ekBody := map[string]any{"group": group, "epoch": 2, "next": pubOf(ek2)}
	if c := call2(t, ts, "POST", "groups/epoch-key", kat.token, map[string]any{"key": signedFull2(t, "epoch-key", ekBody, epochKey(t))}, &e); c != 409 || e.Code != wire.ErrCodeStaleEpoch {
		t.Fatalf("a registration by another key: %d %+v", c, e)
	}
	if c := call2(t, ts, "POST", "groups/epoch-key", kat.token, map[string]any{"key": signedFull2(t, "epoch-key", map[string]any{"group": group, "epoch": 2, "next": randBytes(32)}, reg)}, &e); c != 400 {
		t.Fatalf("a 32-byte next: %d %+v", c, e)
	}
	if c := call2(t, ts, "POST", "groups/epoch-key", kat.token, map[string]any{"key": signed2(t, "epoch-key", ekBody, reg)}, &e); c != 400 || e.Code != wire.ErrCodeBadSignature {
		t.Fatalf("reg named by its component: %d %+v", c, e)
	}
	regd := signedFull2(t, "epoch-key", ekBody, reg)
	for i := range 2 { // the second is a retry after a lost reply
		if c := call2(t, ts, "POST", "groups/epoch-key", kat.token, map[string]any{"key": regd}, nil); c != 204 {
			t.Fatalf("registration %d: %d", i, c)
		}
	}
	c2 := []byte("mls-commit-2")
	if r := ravi.send2(ts, commitOut(group, 2, members, c2, commitReq(t, group, 2, c2, ek2, "next", pubOf(epochKey(t))), "")); r.Status != "sent" {
		t.Fatalf("a commit with the registered key: %+v", r)
	}

	// Missed commits, each with its receipt.
	var cs struct {
		Items []struct {
			Epoch   uint64     `json:"epoch"`
			Data    wire.Bytes `json:"data"`
			Receipt wire.Raw   `json:"receipt"`
		} `json:"items"`
	}
	if c := call2(t, ts, "GET", "groups/"+b64(group)+"/commits?after=-1", kat.token, nil, &cs); c != 200 || len(cs.Items) != 3 {
		t.Fatalf("commits: %d %+v", c, cs)
	}
	for i, it := range cs.Items {
		checkReceipt(t, it.Receipt, s.v2, group, uint64(i), it.Data)
	}
	if c := call2(t, ts, "GET", "groups/"+b64(group)+"/commits?after=1", kat.token, nil, &cs); c != 200 || len(cs.Items) != 1 || cs.Items[0].Epoch != 2 {
		t.Fatalf("commits after 1: %d %+v", c, cs)
	}
	eve := newV2User(t, ts, "eve", "a.test")
	if c := call2(t, ts, "GET", "groups/"+b64(group)+"/commits?after=-1", eve.token, nil, nil); c != 403 {
		t.Fatalf("commits for a group eve isn't in: %d, want 403", c)
	}

	// Version 1 doesn't see the group, and can't take its ID.
	kat1 := newUserOn(t, ts, "kat1", "a.test")
	call(t, ts, "POST", "groups/register", kat1.token, map[string]any{"group": group}, nil)
	if c := call(t, ts, "GET", "groups/"+b64(group)+"/commits?after=-1", kat1.token, nil, nil); c != 404 {
		t.Fatalf("a version 2 group's commits on version 1: %d, want 404", c)
	}
	v1pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if c := call(t, ts, "POST", "groups/create", kat1.token, map[string]any{"group": group, "kind": "group", "epoch-key": []byte(v1pub)}, nil); c != 409 {
		t.Fatalf("a version 2 group's ID on version 1: %d, want 409", c)
	}
}

// Two servers: a member commits through a hub on the other server (S2S commit), registers
// a reg commit's key there (S2S group/epoch-key), fetches missed commits from it (S2S
// commit/fetch), and hands the hub over (S2S group/register). Group traffic crosses
// servers under the groups allowlist.
func TestV2HubFederated(t *testing.T) {
	a, b, sa, sb := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, b, "ravi", "b.test")
	eve := newV2User(t, b, "eve", "b.test")
	contacts2(t, kat, ravi)
	kat.inbox()
	ravi.inbox()

	// ravi creates the group on b.test, its hub, and adds kat.
	group := randBytes(32)
	ek0, ek1, ek2 := epochKey(t), epochKey(t), epochKey(t)
	if c := call2(t, b, "POST", "groups/create", ravi.token, map[string]any{"group": group, "kind": "group", "epoch-key": pubOf(ek0)}, nil); c != 204 {
		t.Fatalf("groups/create: %d", c)
	}
	add := []byte("mls-commit-add-kat")
	r := ravi.send2(b, commitOut(group, 0, []string{ravi.id}, add, commitReq(t, group, 0, add, ek0, "next", pubOf(ek1)), "", kat.id))
	if r.Status != "sent" {
		t.Fatalf("commit: %+v", r)
	}
	if items := kat.eventually(1); items[0].Delivery.MLS != "welcome" {
		t.Fatalf("kat's Welcome: %+v", items[0].Delivery)
	}
	call2(t, a, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil)
	members := []string{ravi.id, kat.id}

	// kat commits from a.test, through the hub on b.test.
	c1 := []byte("mls-commit-1")
	kr := kat.send2(a, commitOut(group, 1, members, c1, commitReq(t, group, 1, c1, ek1, "next", pubOf(ek2)), "b.test"))
	if kr.Status != "sent" {
		t.Fatalf("a commit through a remote hub: %+v", kr)
	}
	checkReceipt(t, kr.Receipt, sb.v2, group, 1, c1)
	got := waitDelivery(t, ravi, c1)
	if !bytes.Equal(got.Receipt, kr.Receipt) || got.From != kat.id {
		t.Fatalf("ravi's copy of kat's commit: %+v", got)
	}
	// Its homeserver passes the hub's refusals back unchanged.
	if r := kat.send2(a, commitOut(group, 1, members, []byte("x"), commitReq(t, group, 1, []byte("x"), ek1, "next", pubOf(ek2)), "b.test")); r.Error != wire.ErrCodeStaleEpoch {
		t.Fatalf("a losing commit through a remote hub: %+v", r)
	}

	// A reg commit through the remote hub, then its key registered there.
	reg, ek3 := epochKey(t), epochKey(t)
	c2 := []byte("mls-commit-2")
	if r := kat.send2(a, commitOut(group, 2, members, c2, commitReq(t, group, 2, c2, ek2, "reg", pubOf(reg)), "b.test")); r.Status != "sent" {
		t.Fatalf("a reg commit through a remote hub: %+v", r)
	}
	key := signedFull2(t, "epoch-key", map[string]any{"group": group, "epoch": 3, "next": pubOf(ek3)}, reg)
	for i := range 2 {
		if c := call2(t, a, "POST", "groups/epoch-key", kat.token, map[string]any{"key": key, "hub": "b.test"}, nil); c != 204 {
			t.Fatalf("registration %d through a remote hub: %d", i, c)
		}
	}
	if g, err := sb.v2.st.Hub().Group(context.Background(), group); err != nil || g.Epoch != 3 || g.Awaiting || !bytes.Equal(g.EpochKey, pubOf(ek3)) {
		t.Fatalf("hub state after registration: %+v %v", g, err)
	}

	// Missed commits, from the remote hub through a.test.
	var cs struct {
		Items []struct {
			Epoch   uint64     `json:"epoch"`
			Data    wire.Bytes `json:"data"`
			Receipt wire.Raw   `json:"receipt"`
		} `json:"items"`
	}
	if c := call2(t, a, "GET", "groups/"+b64(group)+"/commits?after=0&hub=b.test", kat.token, nil, &cs); c != 200 || len(cs.Items) != 2 {
		t.Fatalf("commits through a.test: %d %+v", c, cs)
	}
	for _, it := range cs.Items {
		checkReceipt(t, it.Receipt, sb.v2, group, it.Epoch, it.Data)
	}
	if c := call2(t, a, "GET", "groups/"+b64(group)+"/commits?after=0", kat.token, nil, nil); c != 404 {
		t.Fatalf("without hub, from a server that isn't the hub: %d, want 404", c)
	}
	if err := sb.v2.st.Hub().PruneCommits(context.Background(), time.Now().Unix()+1); err != nil {
		t.Fatal(err)
	}
	if c := call2(t, a, "GET", "groups/"+b64(group)+"/commits?after=0&hub=b.test", kat.token, nil, nil); c != 410 {
		t.Fatalf("pruned epochs: %d, want 410", c)
	}

	// Application messages cross servers to members, and not to eve, who isn't in the group.
	app := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{ravi.id, eve.id}, "group": group, "epoch": 3, "mls": "app", "data": []byte("hello group")}
	if r := kat.send2(a, app); r.Status != "sent" {
		t.Fatalf("app message: %+v", r)
	}
	waitDelivery(t, ravi, []byte("hello group"))
	if items := eve.inbox(); len(items) != 0 {
		t.Fatalf("eve got %+v", items)
	}
	// A Welcome only from a contact: eve isn't kat's.
	w := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{eve.id}, "group": randBytes(32), "epoch": 1, "mls": "welcome", "data": []byte("w")}
	if r := kat.send2(a, w); r.Status != "sent" {
		t.Fatalf("welcome: %+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	if items := eve.inbox(); len(items) != 0 {
		t.Fatalf("eve took a Welcome from a stranger: %+v", items)
	}

	// Hub handoff to a.test, by ravi, at epoch 3, with a composite key.
	handoff := map[string]any{"group": randBytes(32), "kind": "group", "epoch": 3, "epoch-key": randBytes(32), "hub": "a.test"}
	if c := call2(t, b, "POST", "groups/create", ravi.token, handoff, nil); c != 400 {
		t.Fatalf("a handoff with a version 1 key: %d, want 400", c)
	}
	handoff["epoch-key"] = pubOf(ek3)
	if c := call2(t, b, "POST", "groups/create", ravi.token, handoff, nil); c != 204 {
		t.Fatalf("handoff: %d", c)
	}
	if g, err := sa.v2.st.Hub().Group(context.Background(), handoff["group"].([]byte)); err != nil || g.Epoch != 3 || !bytes.Equal(g.EpochKey, pubOf(ek3)) {
		t.Fatalf("the new hub's state: %+v %v", g, err)
	}
	if _, err := sa.st.Hub().Group(context.Background(), handoff["group"].([]byte)); err == nil {
		t.Fatal("a version 2 handoff landed in version 1's hub")
	}
	if c := call2(t, b, "POST", "groups/create", ravi.token, handoff, nil); c != 409 {
		t.Fatalf("handoff again: %d, want 409", c)
	}
}

// waitDelivery waits for a delivery carrying data in u's inbox.
func waitDelivery(t *testing.T, u *v2User, data []byte) *delivery {
	t.Helper()
	for range 100 {
		for _, it := range u.inbox() {
			if it.Delivery != nil && bytes.Equal(it.Delivery.Data, data) {
				return it.Delivery
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never got %q", u.handle, data)
	return nil
}

// Re-creating a group across the migration (SPEC §11.11, §6.8): the first member to migrate
// makes a version 2 group, and adds the other once their migrate appears. Their contact
// carries over as version 2 identifiers, so the Welcome is let in.
func TestV2RecreateAcrossMigration(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	sam := newUserOn(t, b, "sam", "b.test")
	befriend(t, kat, sam)

	kat2 := kat.migrateTo(a, "a.test")
	group := randBytes(32)
	ek0, ek1, ek2 := epochKey(t), epochKey(t), epochKey(t)
	if c := call2(t, a, "POST", "groups/create", kat2.token, map[string]any{"group": group, "kind": "group", "epoch-key": pubOf(ek0)}, nil); c != 204 {
		t.Fatalf("groups/create: %d", c)
	}
	// Alone so far: an empty commit (a key update) through the hub.
	c0 := []byte("mls-commit-0")
	if r := kat2.send2(a, commitOut(group, 0, []string{kat2.id}, c0, commitReq(t, group, 0, c0, ek0, "next", pubOf(ek1)), "")); r.Status != "sent" {
		t.Fatalf("commit 0: %+v", r)
	}

	sam2 := sam.migrateTo(b, "b.test")
	for range 100 {
		if contactsOf2(kat2)[sam2.id] == store.StateContact {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var cl claimed
	if c := call2(t, a, "POST", "keypackages/claim", kat2.token, map[string]any{"id": sam2.id}, &cl); c != 200 || len(cl.Packages) != 1 {
		t.Fatalf("kat2 claims sam2's packages: %d %+v", c, cl)
	}
	c1 := []byte("mls-commit-add-sam")
	if r := kat2.send2(a, commitOut(group, 1, []string{kat2.id}, c1, commitReq(t, group, 1, c1, ek1, "next", pubOf(ek2)), "", sam2.id)); r.Status != "sent" {
		t.Fatalf("adding sam2: %+v", r)
	}
	if w := waitDelivery(t, sam2, []byte("mls-welcome")); w.MLS != "welcome" || !bytes.Equal(w.Group, group) {
		t.Fatalf("sam2's Welcome: %+v", w)
	}
	app := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat2.id, sam2.id}, "group": group, "epoch": 2, "mls": "app", "data": []byte("on version 2 together")}
	if r := kat2.send2(a, app); r.Status != "sent" {
		t.Fatalf("app: %+v", r)
	}
	waitDelivery(t, sam2, []byte("on version 2 together"))
	var cs struct {
		Items []struct {
			Epoch uint64 `json:"epoch"`
		} `json:"items"`
	}
	if c := call2(t, b, "GET", "groups/"+b64(group)+"/commits?after=0&hub=a.test", sam2.token, nil, &cs); c != 200 || len(cs.Items) != 1 || cs.Items[0].Epoch != 1 {
		t.Fatalf("sam2's missed commits: %d %+v", c, cs)
	}
}

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
