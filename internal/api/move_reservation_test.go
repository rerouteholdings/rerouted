package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Move reservations (SPEC §6.6): the destination signs a reservation when asked about a
// device-signed move, and the old home appends the move only with one. These only use
// the client API.

// checkMove asks `to` about u's move entry (POST register with check), and returns the
// status and the reservation it answered with, if any.
func (u *testUser) checkMove(to *httptest.Server, entries []wire.Raw, entry wire.Raw, server string) (int, wire.Raw) {
	u.t.Helper()
	head := sha256.Sum256(entry)
	mv := signed(u.t, "move", map[string]any{"id": u.id, "server": server, "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, u.dev)
	var res struct {
		ID          string   `json:"id"`
		Reservation wire.Raw `json:"reservation"`
	}
	chain := append(append([]wire.Raw(nil), entries...), entry)
	c := call(u.t, to, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode, "check": true}, &res)
	return c, res.Reservation
}

// reserveMove is checkMove that has to succeed with a reservation.
func (u *testUser) reserveMove(to *httptest.Server, entries []wire.Raw, entry wire.Raw, server string) wire.Raw {
	u.t.Helper()
	c, res := u.checkMove(to, entries, entry, server)
	if c != 200 || res == nil {
		u.t.Fatalf("check at %s: %d, reservation %v", server, c, res != nil)
	}
	return res
}

// appendMove appends a move entry at `from` with a reservation (nil for none).
func (u *testUser) appendMove(from *httptest.Server, entry, reservation wire.Raw) (int, wire.Error) {
	u.t.Helper()
	req := map[string]any{"entry": entry}
	if reservation != nil {
		req["reservation"] = reservation
	}
	var e wire.Error
	c := call(u.t, from, "POST", "chain/append", u.token, req, &e)
	return c, e
}

// leave appends a device-signed move entry at `from`, with the reservation `to` gives
// when asked first, as a current client does. It returns the append's status.
func (u *testUser) leave(from, to *httptest.Server, entry wire.Raw, server string) int {
	u.t.Helper()
	res := u.reserveMove(to, u.chainOf(from), entry, server)
	c, _ := u.appendMove(from, entry, res)
	return c
}

// moveTo does a whole move: check at the destination, append at the old home with
// its reservation, register at the destination. It returns the chain.
func (u *testUser) moveTo(from, to *httptest.Server, server string, contacts []string) []wire.Raw {
	u.t.Helper()
	entries := u.chainOf(from)
	entry := u.moveEntry(entries, server, strings.Split(u.handle, ".")[0]+"."+server)
	res := u.reserveMove(to, entries, entry, server)
	if c, e := u.appendMove(from, entry, res); c != 200 {
		u.t.Fatalf("append the move to %s: %d %+v", server, c, e)
	}
	chain := u.chainOf(from)
	head := sha256.Sum256(chain[len(chain)-1])
	if contacts == nil {
		contacts = []string{}
	}
	mv := signed(u.t, "move", map[string]any{"id": u.id, "server": server, "head": head[:], "ts": time.Now().Unix(), "contacts": contacts, "groups": []wire.Bytes{}}, u.dev)
	if c := call(u.t, to, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode}, nil); c != 200 {
		u.t.Fatalf("register at %s: %d", server, c)
	}
	if c := u.signIn(to, server); c != 200 {
		u.t.Fatalf("sign in at %s: %d", server, c)
	}
	u.handle = strings.Split(u.handle, ".")[0] + "." + server
	return chain
}

// unchanged checks that a refused move left kat's chain and routing at her old home alone.
func (u *testUser) unchanged(from *httptest.Server, entries []wire.Raw, handle string) {
	u.t.Helper()
	if got := u.chainOf(from); len(got) != len(entries) {
		u.t.Fatalf("the chain changed: %d entries, had %d", len(got), len(entries))
	}
	var res struct {
		ID   string `json:"id"`
		Home string `json:"home"`
	}
	if c := call(u.t, from, "GET", "resolve/"+handle, "", nil, &res); c != 200 || res.ID != u.id {
		u.t.Fatalf("the handle stopped resolving at the old home: %d %+v", c, res)
	}
	if c := call(u.t, from, "GET", "inbox", u.token, nil, nil); c != 200 {
		u.t.Fatalf("the session at the old home: %d", c)
	}
}

// An older app appends a device-signed move without asking the destination for a
// reservation (it never gets one): refused before anything changes, and the destination
// still has nothing.
func TestMoveNeedsReservation(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	// Some older apps asked first (check) and ignored any extra field; others didn't ask.
	// Both then append bare.
	if c, _ := kat.checkMove(b, entries, entry, "b.test"); c != 200 {
		t.Fatalf("check: %d", c)
	}
	c, e := kat.appendMove(a, entry, nil)
	if c != 403 || e.Code != wire.ErrCodeNotAllowed {
		t.Fatalf("a move without a reservation: %d %+v, want 403 not-allowed", c, e)
	}
	kat.unchanged(a, entries, "kat.a.test")
	if c := kat.signIn(b, "b.test"); c == 200 {
		t.Fatal("b.test took kat")
	}
}

// The reservation names the identity, the destination, the entry, and an expiry, and is
// signed by the destination's server key.
func TestMoveReservationIssued(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	raw := kat.reserveMove(b, entries, entry, "b.test")
	sig, err := wire.DecodeSigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		ID     string     `json:"id"`
		Server string     `json:"server"`
		Entry  wire.Bytes `json:"entry"`
		Exp    int64      `json:"exp"`
	}
	if kid, ok := sig.KeyID(); sig.T != "move-reservation" || !ok || kid != sb.key.KID || sig.OpenClosed(&body) != nil {
		t.Fatalf("not a move-reservation signed by b.test's key: %+v", sig)
	}
	if err := sig.Verify("move-reservation", sb.key.Public()); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(entry)
	if body.ID != kat.id || body.Server != "b.test" || string(body.Entry) != string(sum[:]) || body.Exp < time.Now().Unix()+9*60 || body.Exp > time.Now().Unix()+11*60 {
		t.Fatalf("reservation body: %+v", body)
	}
	// A recovery-signed move needs none, and gets none.
	seq, prev := head(t, a, kat.id)
	next := sha256.Sum256(randBytes(32))
	rec := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-home", "home": "b.test"}, map[string]any{"op": "set-handle", "handle": "kat.b.test"}, map[string]any{"op": "set-recovery", "next": next[:]}}}, kat.rec)
	if c, res := kat.checkMove(b, entries, rec, "b.test"); c != 200 || res != nil {
		t.Fatalf("check of a recovery-signed move: %d, reservation %v", c, res != nil)
	}
	if c, e := kat.appendMove(a, rec, nil); c != 200 {
		t.Fatalf("a recovery-signed move without a reservation: %d %+v", c, e)
	}
}

// Every way a reservation can be wrong is refused before anything changes.
func TestMoveReservationRefusals(t *testing.T) {
	a, b, sa, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	ravi := newUserOn(t, a, "ravi", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	good := kat.reserveMove(b, entries, entry, "b.test")
	sum := sha256.Sum256(entry)
	forge := func(key ed25519.PrivateKey, kid string, body map[string]any) wire.Raw {
		s, err := wire.SignKID("move-reservation", body, key, kid)
		if err != nil {
			t.Fatal(err)
		}
		enc, _ := s.Encode()
		return enc
	}
	body := func(id, server string, entry []byte, exp int64) map[string]any {
		return map[string]any{"id": id, "server": server, "entry": entry, "exp": exp}
	}
	exp := time.Now().Unix() + 300
	tampered, _ := wire.DecodeSigned(good)
	tampered.S[5] ^= 1
	tamperedRaw, _ := tampered.Encode()
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	otherEntry := kat.moveEntry(entries, "b.test", "kat2.b.test")
	otherSum := sha256.Sum256(otherEntry)
	ackRes, _ := wire.SignKID("commit-receipt", body(kat.id, "b.test", sum[:], exp), sb.key.Priv, sb.key.KID)
	ack, _ := ackRes.Encode()
	for _, tc := range []struct {
		name   string
		res    wire.Raw
		status int
		code   string
	}{
		{"bad signature", tamperedRaw, 400, wire.ErrCodeBadSignature},
		{"signed by a stranger under b's key id", forge(stranger, sb.key.KID, body(kat.id, "b.test", sum[:], exp)), 400, wire.ErrCodeBadSignature},
		{"signed by the old home", forge(sa.key.Priv, sa.key.KID, body(kat.id, "b.test", sum[:], exp)), 400, wire.ErrCodeBadSignature},
		{"expired", forge(sb.key.Priv, sb.key.KID, body(kat.id, "b.test", sum[:], time.Now().Unix()-1)), 403, wire.ErrCodeNotAllowed},
		{"wrong entry", forge(sb.key.Priv, sb.key.KID, body(kat.id, "b.test", otherSum[:], exp)), 403, wire.ErrCodeNotAllowed},
		{"wrong server", forge(sb.key.Priv, sb.key.KID, body(kat.id, "a.test", sum[:], exp)), 403, wire.ErrCodeNotAllowed},
		{"wrong identity", forge(sb.key.Priv, sb.key.KID, body(ravi.id, "b.test", sum[:], exp)), 403, wire.ErrCodeNotAllowed},
		{"another signed type", ack, 403, wire.ErrCodeNotAllowed},
		{"an extra member", forge(sb.key.Priv, sb.key.KID, map[string]any{"id": kat.id, "server": "b.test", "entry": sum[:], "exp": exp, "x": 1}), 403, wire.ErrCodeNotAllowed},
		{"signed with an embedded key", signed(t, "move-reservation", body(kat.id, "b.test", sum[:], exp), sb.key.Priv), 403, wire.ErrCodeNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := kat.appendMove(a, entry, tc.res)
			if c != tc.status || e.Code != tc.code {
				t.Fatalf("%d %+v, want %d %s", c, e, tc.status, tc.code)
			}
			kat.unchanged(a, entries, "kat.a.test")
		})
	}
	// The real one still works afterwards.
	if c, e := kat.appendMove(a, entry, good); c != 200 {
		t.Fatalf("the valid reservation: %d %+v", c, e)
	}
}

// PauseMoves still refuses a device-signed move at the old home, reservation or not.
func TestMoveReservationPaused(t *testing.T) {
	a, b, sa, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	res := kat.reserveMove(b, entries, entry, "b.test")
	sa.cfg.PauseMoves = true
	c, e := kat.appendMove(a, entry, res)
	if c != 403 || e.Code != wire.ErrCodeNotAllowed || !strings.Contains(e.Msg, "paused") {
		t.Fatalf("append while paused: %d %+v", c, e)
	}
	kat.unchanged(a, entries, "kat.a.test")
}

// While kat's reservation stands, her new handle at the destination is held: another
// identity can't register it or reserve it, until she registers.
func TestMoveReservationHoldsHandle(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	other := newUserOn(t, a, "other", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	res := kat.reserveMove(b, entries, entry, "b.test")
	// A new signup for the name.
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub)
	genesis := signed(t, "chain-entry", map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey)), "name": "grabber"},
		map[string]any{"op": "set-home", "home": "b.test"},
		map[string]any{"op": "set-handle", "handle": "kat.b.test"},
		map[string]any{"op": "set-recovery", "next": commit[:]},
	}}, dev)
	var e wire.Error
	if c := call(t, b, "POST", "register", "", map[string]any{"genesis": genesis, "invite": testRegCode}, &e); c != 409 || e.Code != wire.ErrCodeHandleTaken {
		t.Fatalf("a signup for a held handle: %d %+v", c, e)
	}
	// Another identity moving in under the same name.
	oe := other.chainOf(a)
	if c, _ := other.checkMove(b, oe, other.moveEntry(oe, "b.test", "kat.b.test"), "b.test"); c != 409 {
		t.Fatalf("another identity's check for a held handle: %d, want 409", c)
	}
	// Kat's own re-ask is fine, and her move completes.
	if c, again := kat.checkMove(b, entries, entry, "b.test"); c != 200 || again == nil {
		t.Fatalf("kat asks again: %d", c)
	}
	if c, e := kat.appendMove(a, entry, res); c != 200 {
		t.Fatalf("append: %d %+v", c, e)
	}
	chain := kat.chainOf(a)
	h := sha256.Sum256(chain[len(chain)-1])
	mv := signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": h[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)
	if c := call(t, b, "POST", "register", "", map[string]any{"chain": chain, "move": mv, "invite": testRegCode}, nil); c != 200 {
		t.Fatalf("register: %d", c)
	}
	var r struct {
		ID string `json:"id"`
	}
	if c := call(t, b, "GET", "resolve/kat.b.test", "", nil, &r); c != 200 || r.ID != kat.id {
		t.Fatalf("resolve: %d %+v", c, r)
	}
}

// a → b → a → b, each leg with a reservation from its destination.
func TestMoveReturnWithReservations(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	kat.moveTo(a, b, "b.test", nil)
	kat.moveTo(b, a, "a.test", nil)
	kat.moveTo(a, b, "b.test", nil)
	var r struct {
		ID string `json:"id"`
	}
	if c := call(t, b, "GET", "resolve/kat.b.test", "", nil, &r); c != 200 || r.ID != kat.id {
		t.Fatalf("resolve after returning: %d %+v", c, r)
	}
}
