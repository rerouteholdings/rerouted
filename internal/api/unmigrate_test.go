package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

// The recovery code outranks a device-signed migrate (SPEC §6.8, Undoing a migration):
// POST recover takes a recovery-signed entry at the migrate's position, and in the same
// step the version 1 identity gets its handle back, the version 2 identity is closed, and
// contact lists that had moved to the version 2 identity name the version 1 one again.
func TestMigrationUndone(t *testing.T) {
	ts := testServer(t)
	kat, ravi := newUser(t, ts, "kat"), newUser(t, ts, "ravi")
	befriend(t, kat, ravi)
	r2 := ravi.migrateTo(ts, "chat.test")
	k2 := kat.migrateTo(ts, "chat.test") // device-signed: a thief's, say
	if got := contactsOf2(r2); got[k2.id] == "" {
		t.Fatalf("ravi's version 2 contacts before the undo: %v", got)
	}

	entries := kat.chainOf(ts)
	n := len(entries)
	prev := sha256.Sum256(entries[n-2])
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	next := sha256.Sum256(nextPub)
	undo := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": n - 1, "prev": prev[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-recovery", "next": next[:]}},
	}, kat.rec)
	if c := call(t, ts, "POST", "recover", "", map[string]any{"entry": undo}, nil); c != 200 {
		t.Fatalf("recover over the migrate: %d", c)
	}

	// The version 1 identity is open again: its handle resolves to it, and it can send.
	var res struct {
		ID string `json:"id"`
	}
	if c := call(t, ts, "GET", "resolve/"+kat.handle, kat.token, nil, &res); c != 200 || res.ID != kat.id {
		t.Fatalf("the version 1 handle after the undo: %d %s", c, res.ID)
	}
	if c := call2(t, ts, "GET", "resolve/"+kat.handle, r2.token, nil, nil); c != 404 {
		t.Fatalf("the handle still resolves on version 2: %d", c)
	}
	// The version 2 identity is closed: its session is gone, and it can't sign in again.
	if c := call2(t, ts, "GET", "inbox", k2.token, nil, nil); c != 401 {
		t.Fatalf("the version 2 identity's session: %d", c)
	}
	if c := call2(t, ts, "POST", "auth/challenge", "", map[string]any{"id": k2.id, "key": edOf(k2.dev)}, nil); c != 403 {
		t.Fatalf("the version 2 identity's sign-in: %d", c)
	}
	// ravi's version 2 contact list names kat's version 1 identity again.
	if got := contactsOf2(r2); got[k2.id] != "" || got[kat.id] == "" {
		t.Fatalf("ravi's version 2 contacts after the undo: %v", got)
	}
}
