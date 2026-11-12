package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// Ending sessions never fails silently. A sign-out that can't be stored says so, and a
// device removal whose sessions can't be ended changes nothing, so the removed device is
// never left signed in.
func TestSessionsEndOrSayTheyDidnt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	st, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")

	pub2, dev2, _ := ed25519.GenerateKey(rand.Reader)
	seq, prev := head(t, ts, kat.id)
	add := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "add-device", "key": []byte(pub2)}}}, kat.dev)
	if code := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": add}, nil); code != 200 {
		t.Fatalf("add-device: %d", code)
	}

	// Ending a session deletes its token: make that fail.
	if _, err := db.Exec("CREATE TRIGGER fail_tokens BEFORE DELETE ON tokens BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if code := call(t, ts, "POST", "auth/logout", kat.token, map[string]any{}, nil); code != 503 {
		t.Fatalf("sign-out with storage failing: %d, want 503", code)
	}
	sum := sha256.Sum256(add)
	rm := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 2, "prev": sum[:], "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "remove-device", "key": []byte(kat.dev.Public().(ed25519.PublicKey))}}}, dev2)
	if code := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": rm}, nil); code != 503 {
		t.Fatalf("removing a device with storage failing: %d, want 503", code)
	}
	if now, _ := head(t, ts, kat.id); now != seq+1 {
		t.Fatalf("the chain changed anyway: head %d, want %d", now, seq+1)
	}

	if _, err := db.Exec("DROP TRIGGER fail_tokens"); err != nil {
		t.Fatal(err)
	}
	if code := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": rm}, nil); code != 200 {
		t.Fatalf("the retry: %d", code)
	}
	if code := call(t, ts, "GET", "contacts", kat.token, nil, nil); code != 401 {
		t.Fatalf("the removed device's session: %d, want 401", code)
	}
}
