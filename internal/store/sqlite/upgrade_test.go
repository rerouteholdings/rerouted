package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// Earlier schemas (versions 3, 4, and 5), verbatim, for upgrade tests.
var shippedSchemas = map[int]string{
	3: `CREATE TABLE IF NOT EXISTS chains   (id TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces   (k TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens   (hash BLOB PRIMARY KEY, id TEXT NOT NULL, device BLOB NOT NULL, name TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kps      (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, last_resort INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (owner TEXT NOT NULL, other TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, request BLOB, PRIMARY KEY (owner, other));
CREATE TABLE IF NOT EXISTS invites  (owner TEXT NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL, uses INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (owner, hash));
CREATE TABLE IF NOT EXISTS groups_allowed (owner TEXT NOT NULL, grp BLOB NOT NULL, PRIMARY KEY (owner, grp));
CREATE TABLE IF NOT EXISTS inbox    (cursor INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, ts INTEGER NOT NULL, delivery BLOB, notice BLOB);
CREATE INDEX IF NOT EXISTS inbox_owner ON inbox (owner, cursor);
CREATE TABLE IF NOT EXISTS acks     (owner TEXT NOT NULL, device BLOB NOT NULL, upto INTEGER NOT NULL, PRIMARY KEY (owner, device));
CREATE TABLE IF NOT EXISTS seen     (owner TEXT NOT NULL, did BLOB NOT NULL, PRIMARY KEY (owner, did));
CREATE TABLE IF NOT EXISTS hub      (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS commits  (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS remote   (id TEXT PRIMARY KEY, home TEXT NOT NULL, entries BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS outbox   (n INTEGER PRIMARY KEY AUTOINCREMENT, dest TEXT NOT NULL, path TEXT NOT NULL, body BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, v INTEGER NOT NULL, signed BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media    (id BLOB PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, mime TEXT NOT NULL, public INTEGER NOT NULL, created INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS account_keys (id TEXT NOT NULL, via TEXT NOT NULL, wrapped BLOB NOT NULL, PRIMARY KEY (id, via));
CREATE TABLE IF NOT EXISTS account_data (id TEXT PRIMARY KEY, version INTEGER NOT NULL, ct BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS backups  (id TEXT NOT NULL, seq INTEGER NOT NULL, ct BLOB NOT NULL, snapshot INTEGER NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS reports  (n INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, origin TEXT NOT NULL, reporter TEXT NOT NULL, reported TEXT NOT NULL, body BLOB NOT NULL);
`,
	4: `CREATE TABLE IF NOT EXISTS chains   (id TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces   (k TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens   (hash BLOB PRIMARY KEY, id TEXT NOT NULL, device BLOB NOT NULL, name TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kps      (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, last_resort INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (owner TEXT NOT NULL, other TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, request BLOB, PRIMARY KEY (owner, other));
CREATE TABLE IF NOT EXISTS invites  (owner TEXT NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL, uses INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (owner, hash));
CREATE TABLE IF NOT EXISTS groups_allowed (owner TEXT NOT NULL, grp BLOB NOT NULL, PRIMARY KEY (owner, grp));
CREATE TABLE IF NOT EXISTS inbox    (cursor INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, ts INTEGER NOT NULL, delivery BLOB, notice BLOB);
CREATE INDEX IF NOT EXISTS inbox_owner ON inbox (owner, cursor);
CREATE TABLE IF NOT EXISTS acks     (owner TEXT NOT NULL, device BLOB NOT NULL, upto INTEGER NOT NULL, PRIMARY KEY (owner, device));
CREATE TABLE IF NOT EXISTS seen     (owner TEXT NOT NULL, did BLOB NOT NULL, PRIMARY KEY (owner, did));
CREATE TABLE IF NOT EXISTS hub      (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS commits  (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, ts INTEGER NOT NULL DEFAULT 0, request BLOB, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS remote   (id TEXT PRIMARY KEY, home TEXT NOT NULL, entries BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS outbox   (n INTEGER PRIMARY KEY AUTOINCREMENT, dest TEXT NOT NULL, path TEXT NOT NULL, body BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, v INTEGER NOT NULL, signed BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media    (id BLOB PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, mime TEXT NOT NULL, public INTEGER NOT NULL, created INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS account_keys (id TEXT NOT NULL, via TEXT NOT NULL, wrapped BLOB NOT NULL, PRIMARY KEY (id, via));
CREATE TABLE IF NOT EXISTS account_data (id TEXT PRIMARY KEY, version INTEGER NOT NULL, ct BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS backups  (id TEXT NOT NULL, seq INTEGER NOT NULL, ct BLOB NOT NULL, snapshot INTEGER NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS reports  (n INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, origin TEXT NOT NULL, reporter TEXT NOT NULL, reported TEXT NOT NULL, body BLOB NOT NULL);
`,
	5: `CREATE TABLE IF NOT EXISTS move_registrations (id TEXT NOT NULL, operation BLOB NOT NULL, PRIMARY KEY (id, operation));
CREATE TABLE IF NOT EXISTS chains   (id TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces   (k TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens   (hash BLOB PRIMARY KEY, id TEXT NOT NULL, device BLOB NOT NULL, name TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kps      (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, last_resort INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (owner TEXT NOT NULL, other TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, request BLOB, PRIMARY KEY (owner, other));
CREATE TABLE IF NOT EXISTS invites  (owner TEXT NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL, uses INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (owner, hash));
CREATE TABLE IF NOT EXISTS groups_allowed (owner TEXT NOT NULL, grp BLOB NOT NULL, PRIMARY KEY (owner, grp));
CREATE TABLE IF NOT EXISTS inbox    (cursor INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, ts INTEGER NOT NULL, delivery BLOB, notice BLOB);
CREATE INDEX IF NOT EXISTS inbox_owner ON inbox (owner, cursor);
CREATE TABLE IF NOT EXISTS acks     (owner TEXT NOT NULL, device BLOB NOT NULL, upto INTEGER NOT NULL, PRIMARY KEY (owner, device));
CREATE TABLE IF NOT EXISTS seen     (owner TEXT NOT NULL, did BLOB NOT NULL, PRIMARY KEY (owner, did));
CREATE TABLE IF NOT EXISTS hub      (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS commits  (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, ts INTEGER NOT NULL DEFAULT 0, request BLOB, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS remote   (id TEXT PRIMARY KEY, home TEXT NOT NULL, entries BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS outbox   (n INTEGER PRIMARY KEY AUTOINCREMENT, dest TEXT NOT NULL, path TEXT NOT NULL, body BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, v INTEGER NOT NULL, signed BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media    (id BLOB PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, mime TEXT NOT NULL, public INTEGER NOT NULL, created INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS account_keys (id TEXT NOT NULL, via TEXT NOT NULL, wrapped BLOB NOT NULL, PRIMARY KEY (id, via));
CREATE TABLE IF NOT EXISTS account_data (id TEXT PRIMARY KEY, version INTEGER NOT NULL, ct BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS backups  (id TEXT NOT NULL, seq INTEGER NOT NULL, ct BLOB NOT NULL, snapshot INTEGER NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS reports  (n INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, origin TEXT NOT NULL, reporter TEXT NOT NULL, reported TEXT NOT NULL, body BLOB NOT NULL);
`,
}

// Every shipped schema before version 6 upgrades to the current one with its data: wrapped keys keep their bytes
// and count as stored at the upgrade (so a staged recovery wrap gets its full grace period),
// reservations work, and handle claims see them.
func TestMigrateShippedSchemas(t *testing.T) {
	for v, schema := range shippedSchemas {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rerouted.db")
			db, err := sql.Open("sqlite", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{
				schema,
				"INSERT INTO chains (id, seq, entry) VALUES ('kat', 0, x'01')",
				"INSERT INTO handles (handle, id) VALUES ('kat.test', 'kat')",
				`INSERT INTO account_keys (id, via, wrapped) VALUES ('kat', 'recovery-next', x'7b7d'), ('kat', 'recovery', x'7b7e')`,
				"PRAGMA user_version = " + string(rune('0'+v)),
			} {
				if _, err := db.Exec(q); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			before := time.Now().Unix()
			st, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			var uv int
			if err := st.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != SchemaVersion {
				t.Fatalf("user_version %d (%v), want %d", uv, err, SchemaVersion)
			}
			ctx := context.Background()
			var slots []store.KeySlot
			err = st.Account().UpdateKeys(ctx, "kat", func(chain [][]byte, s []store.KeySlot) ([]store.KeyChange, error) {
				slots = s
				return nil, nil
			})
			if err != nil || len(slots) != 2 {
				t.Fatalf("keys after upgrade: %v %+v", err, slots)
			}
			for _, k := range slots {
				if k.Stored < before-5 || (k.Slot == "recovery-next" && string(k.Wrapped) != "{}") {
					t.Fatalf("key after upgrade: %+v", k)
				}
			}
			r := &store.MoveReservation{ID: "ravi", Entry: []byte("e"), Handle: "ravi.test", Exp: before + 600, Hold: before + 600 + 30*86400}
			if err := st.Chains().Create(ctx, "ravi", []byte("r"), "ravi.old"); err != nil {
				t.Fatal(err)
			}
			if ok, err := st.Chains().RegisterMove(ctx, store.MoveRegistration{ID: "ravi", Handle: "ravi.test", Operation: []byte("op"), Entries: [][]byte{[]byte("r"), []byte("away")}, Expected: [][]byte{[]byte("r")}, Check: true, Reserve: r}); !ok || err != nil {
				t.Fatalf("reserve after upgrade: %v %v", ok, err)
			}
			if err := st.Chains().Create(ctx, "grabber", []byte("g"), "ravi.test"); err != store.ErrHandleTaken {
				t.Fatalf("held handle after upgrade: %v", err)
			}
			if id, err := st.Chains().ByHandle(ctx, "kat.test"); err != nil || id != "kat" {
				t.Fatalf("handles after upgrade: %q %v", id, err)
			}
			// Opening again is a no-op: the upgrade doesn't run twice.
			st.Close()
			st2, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			st2.Close()
		})
	}
}

// A registration that fails partway leaves the reservation it would have consumed.
func TestReservationConsumedOnlyByCommit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Chains().Create(ctx, "kat", []byte("g"), "kat.old"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	m := store.MoveRegistration{ID: "kat", Handle: "kat.new", Operation: []byte("op"), Entries: [][]byte{[]byte("g"), []byte("away")}, Expected: [][]byte{[]byte("g")}, Check: true,
		Reserve: &store.MoveReservation{ID: "kat", Entry: []byte("h"), Handle: "kat.new", Exp: now + 600, Hold: now + 86400}}
	if ok, err := s.Chains().RegisterMove(ctx, m); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_move BEFORE INSERT ON move_registrations BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	m.Check, m.Reserve = false, nil
	if _, err := s.Chains().RegisterMove(ctx, m); err == nil {
		t.Fatal("injected failure succeeded")
	}
	if rs, _ := s.Chains().Reservations(ctx, "kat"); len(rs) != 1 {
		t.Fatalf("a failed registration consumed the reservation: %d left", len(rs))
	}
	if _, err := s.db.Exec("DROP TRIGGER fail_move"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Chains().RegisterMove(ctx, m); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if rs, _ := s.Chains().Reservations(ctx, "kat"); len(rs) != 0 {
		t.Fatalf("%d reservations after the registration", len(rs))
	}
}

// A return registration that fails partway clears nothing; the committed one clears the
// earlier stay's data and non-recovery wraps, and keeps recovery wraps.
func TestReturnClearIsAtomic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Chains().Create(ctx, "kat", []byte("g"), "kat.here"); err != nil {
		t.Fatal(err)
	}
	if err := s.Chains().Append(ctx, "kat", 0, []byte("away")); err != nil {
		t.Fatal(err)
	}
	for slot, w := range map[string]string{"recovery": "r", "recovery-next/aa": "n", "recovery-retained/bb/cc": "o", "passphrase": "p"} {
		if err := s.Account().SetKey(ctx, "kat", slot, []byte(w)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Account().PutData(ctx, "kat", 0, []byte("old data")); err != nil {
		t.Fatal(err)
	}
	if err := s.Backups().Put(ctx, "kat", store.Segment{Seq: 1, CT: []byte("old segment")}); err != nil {
		t.Fatal(err)
	}
	have := [][]byte{[]byte("g"), []byte("away")}
	m := store.MoveRegistration{ID: "kat", Handle: "kat.here", Operation: []byte("op"), Expected: have, Entries: append(append([][]byte(nil), have...), []byte("back"))}
	count := func() (keys, data, segs int) {
		s.db.QueryRow("SELECT count(*) FROM account_keys").Scan(&keys)
		s.db.QueryRow("SELECT count(*) FROM account_data").Scan(&data)
		s.db.QueryRow("SELECT count(*) FROM backups").Scan(&segs)
		return
	}
	if _, err := s.db.Exec("CREATE TRIGGER fail_move BEFORE INSERT ON move_registrations BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chains().RegisterMove(ctx, m); err == nil {
		t.Fatal("injected failure succeeded")
	}
	if k, d, b := count(); k != 4 || d != 1 || b != 1 {
		t.Fatalf("a failed return cleared data: %d keys, %d data, %d segments", k, d, b)
	}
	s.db.Exec("DROP TRIGGER fail_move")
	if ok, err := s.Chains().RegisterMove(ctx, m); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if k, d, b := count(); k != 3 || d != 0 || b != 0 {
		t.Fatalf("after the return: %d keys (want the 3 recovery wraps), %d data, %d segments", k, d, b)
	}
	if _, err := s.Account().Key(ctx, "kat", "passphrase"); err != store.ErrNotFound {
		t.Fatal("the passphrase wrap survived the return")
	}
}

// The schema the alpha servers ran before version 7, verbatim.
const schemaV6 = `CREATE TABLE IF NOT EXISTS move_registrations (id TEXT NOT NULL, operation BLOB NOT NULL, PRIMARY KEY (id, operation));
CREATE TABLE IF NOT EXISTS move_reservations (id TEXT NOT NULL, entry BLOB NOT NULL, handle TEXT NOT NULL, exp INTEGER NOT NULL, hold INTEGER NOT NULL, PRIMARY KEY (id, entry));
CREATE INDEX IF NOT EXISTS move_reservations_handle ON move_reservations (handle);
CREATE TABLE IF NOT EXISTS chains   (id TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces   (k TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens   (hash BLOB PRIMARY KEY, id TEXT NOT NULL, device BLOB NOT NULL, name TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kps      (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, last_resort INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (owner TEXT NOT NULL, other TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, request BLOB, PRIMARY KEY (owner, other));
CREATE TABLE IF NOT EXISTS invites  (owner TEXT NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL, uses INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (owner, hash));
CREATE TABLE IF NOT EXISTS groups_allowed (owner TEXT NOT NULL, grp BLOB NOT NULL, PRIMARY KEY (owner, grp));
CREATE TABLE IF NOT EXISTS inbox    (cursor INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, ts INTEGER NOT NULL, delivery BLOB, notice BLOB);
CREATE INDEX IF NOT EXISTS inbox_owner ON inbox (owner, cursor);
CREATE TABLE IF NOT EXISTS acks     (owner TEXT NOT NULL, device BLOB NOT NULL, upto INTEGER NOT NULL, PRIMARY KEY (owner, device));
CREATE TABLE IF NOT EXISTS seen     (owner TEXT NOT NULL, did BLOB NOT NULL, PRIMARY KEY (owner, did));
CREATE TABLE IF NOT EXISTS hub      (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS commits  (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, ts INTEGER NOT NULL DEFAULT 0, request BLOB, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS remote   (id TEXT PRIMARY KEY, home TEXT NOT NULL, entries BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS outbox   (n INTEGER PRIMARY KEY AUTOINCREMENT, dest TEXT NOT NULL, path TEXT NOT NULL, body BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, v INTEGER NOT NULL, signed BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media    (id BLOB PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, mime TEXT NOT NULL, public INTEGER NOT NULL, created INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS account_keys (id TEXT NOT NULL, via TEXT NOT NULL, wrapped BLOB NOT NULL, stored INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (id, via));
CREATE TABLE IF NOT EXISTS account_data (id TEXT PRIMARY KEY, version INTEGER NOT NULL, ct BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS backups  (id TEXT NOT NULL, seq INTEGER NOT NULL, ct BLOB NOT NULL, snapshot INTEGER NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS reports  (n INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, origin TEXT NOT NULL, reporter TEXT NOT NULL, reported TEXT NOT NULL, body BLOB NOT NULL);
`

// Version 6 upgrades to 7: delivery IDs already seen stay seen, and count as seen at the
// upgrade, so pruning doesn't forget them early; the sent table works.
func TestMigrateV6ToV7(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerouted.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{schemaV6, "INSERT INTO seen (owner, did) VALUES ('kat', x'01')", "PRAGMA user_version = 6"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	before := time.Now().Unix()
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var uv int
	if err := st.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != SchemaVersion {
		t.Fatalf("user_version %d (%v), want %d", uv, err, SchemaVersion)
	}
	ctx := context.Background()
	if _, isNew, err := st.Inbox().Deliver(ctx, "kat", []byte{1}, store.Item{TS: before, Delivery: []byte("{}")}); err != nil || isNew {
		t.Fatalf("an ID seen before the upgrade: new %v, %v", isNew, err)
	}
	if n, err := st.Inbox().PruneSeen(ctx, before-60); err != nil || n != 0 {
		t.Fatalf("pruning right after the upgrade removed %d (%v)", n, err)
	}
	if err := st.Sent().Put(ctx, "kat", []byte{2}, []byte("r"), before); err != nil {
		t.Fatal(err)
	}
	if b, err := st.Sent().Get(ctx, "kat", []byte{2}); err != nil || string(b) != "r" {
		t.Fatalf("sent after upgrade: %q %v", b, err)
	}
}

// The version 7 schema, verbatim, for the upgrade to wire version 2's columns.
const schemaV7 = `
CREATE TABLE IF NOT EXISTS move_registrations (id TEXT NOT NULL, operation BLOB NOT NULL, PRIMARY KEY (id, operation));
CREATE TABLE IF NOT EXISTS move_reservations (id TEXT NOT NULL, entry BLOB NOT NULL, handle TEXT NOT NULL, exp INTEGER NOT NULL, hold INTEGER NOT NULL, PRIMARY KEY (id, entry));
CREATE INDEX IF NOT EXISTS move_reservations_handle ON move_reservations (handle);
CREATE TABLE IF NOT EXISTS chains   (id TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nonces   (k TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS nonces_expires ON nonces (expires);
CREATE TABLE IF NOT EXISTS tokens   (hash BLOB PRIMARY KEY, id TEXT NOT NULL, device BLOB NOT NULL, name TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kps      (n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, last_resort INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS contacts (owner TEXT NOT NULL, other TEXT NOT NULL, state TEXT NOT NULL, since INTEGER NOT NULL, request BLOB, PRIMARY KEY (owner, other));
CREATE TABLE IF NOT EXISTS invites  (owner TEXT NOT NULL, hash BLOB NOT NULL, public INTEGER NOT NULL, uses INTEGER NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (owner, hash));
CREATE TABLE IF NOT EXISTS groups_allowed (owner TEXT NOT NULL, grp BLOB NOT NULL, PRIMARY KEY (owner, grp));
CREATE TABLE IF NOT EXISTS inbox    (cursor INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, ts INTEGER NOT NULL, delivery BLOB, notice BLOB);
CREATE INDEX IF NOT EXISTS inbox_owner ON inbox (owner, cursor);
CREATE TABLE IF NOT EXISTS acks     (owner TEXT NOT NULL, device BLOB NOT NULL, upto INTEGER NOT NULL, PRIMARY KEY (owner, device));
CREATE TABLE IF NOT EXISTS seen     (owner TEXT NOT NULL, did BLOB NOT NULL, ts INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (owner, did));
CREATE TABLE IF NOT EXISTS sent     (sender TEXT NOT NULL, did BLOB NOT NULL, result BLOB NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (sender, did));
CREATE TABLE IF NOT EXISTS hub      (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS commits  (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, ts INTEGER NOT NULL DEFAULT 0, request BLOB, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS remote   (id TEXT PRIMARY KEY, home TEXT NOT NULL, entries BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS outbox   (n INTEGER PRIMARY KEY AUTOINCREMENT, dest TEXT NOT NULL, path TEXT NOT NULL, body BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, v INTEGER NOT NULL, signed BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS media    (id BLOB PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, mime TEXT NOT NULL, public INTEGER NOT NULL, created INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS account_keys (id TEXT NOT NULL, via TEXT NOT NULL, wrapped BLOB NOT NULL, stored INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (id, via));
CREATE TABLE IF NOT EXISTS account_data (id TEXT PRIMARY KEY, version INTEGER NOT NULL, ct BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS backups  (id TEXT NOT NULL, seq INTEGER NOT NULL, ct BLOB NOT NULL, snapshot INTEGER NOT NULL, PRIMARY KEY (id, seq));
CREATE TABLE IF NOT EXISTS reports  (n INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, origin TEXT NOT NULL, reporter TEXT NOT NULL, reported TEXT NOT NULL, body BLOB NOT NULL);
`

// Version 7 to 8: everything stored before is wire version 1, and the version 2 view sees
// none of it; key packages stored before have no binding.
func TestMigrateV7ToV8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerouted.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		schemaV7,
		"INSERT INTO chains (id, seq, entry) VALUES ('kat', 0, x'01'), ('kat', 1, x'02')",
		"INSERT INTO handles (handle, id) VALUES ('kat.test', 'kat')",
		"INSERT INTO tokens (hash, id, device, name, expires) VALUES (x'aa', 'kat', x'01', 'laptop', 9999999999)",
		"INSERT INTO remote (id, home, entries) VALUES ('ravi', 'b.test', '[\"AQ\"]')",
		"INSERT INTO outbox (dest, path, body, next, created) VALUES ('b.test', 'deliver', x'7b7d', 0, 0)",
		"INSERT INTO kps (id, device, data, last_resort) VALUES ('kat', x'01', x'0102', 0)",
		"PRAGMA user_version = 7",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var uv int
	if err := st.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != SchemaVersion || SchemaVersion != 8 {
		t.Fatalf("user_version %d (%v), want 8", uv, err)
	}
	ctx := context.Background()
	v1, v2 := store.Store(st), st.ForWire(2)
	if e, err := v1.Chains().Entries(ctx, "kat", -1); err != nil || len(e) != 2 {
		t.Fatalf("version 1 chain after upgrade: %d %v", len(e), err)
	}
	if _, err := v2.Chains().Entries(ctx, "kat", -1); err != store.ErrNotFound {
		t.Fatalf("version 2 view sees a version 1 chain: %v", err)
	}
	if id, _, err := v1.Sessions().LookupToken(ctx, []byte{0xaa}, 1000); err != nil || id != "kat" {
		t.Fatalf("version 1 token after upgrade: %q %v", id, err)
	}
	if _, _, err := v2.Sessions().LookupToken(ctx, []byte{0xaa}, 1000); err == nil {
		t.Fatal("a version 1 token works on the version 2 view")
	}
	if home, _, err := v1.Remote().Get(ctx, "ravi"); err != nil || home != "b.test" {
		t.Fatalf("cached chain after upgrade: %q %v", home, err)
	}
	if _, _, err := v2.Remote().Get(ctx, "ravi"); err != store.ErrNotFound {
		t.Fatalf("version 2 view sees a version 1 cached chain: %v", err)
	}
	if due, err := v1.Outbox().Due(ctx, 10, 10); err != nil || len(due) != 1 {
		t.Fatalf("outbox after upgrade: %d %v", len(due), err)
	}
	if due, err := v2.Outbox().Due(ctx, 10, 10); err != nil || len(due) != 0 {
		t.Fatalf("version 2 outbox sees version 1's: %d %v", len(due), err)
	}
	if kps, err := v1.KeyPackages().Claim(ctx, "kat", [][]byte{{1}}); err != nil || len(kps) != 1 || kps[0].Binding != nil {
		t.Fatalf("key package after upgrade: %+v %v", kps, err)
	}
	// Opening again is a no-op.
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
}

// Each wire version's view keeps its own chains, tokens, cached chains, and outbox, over
// one handle namespace.
func TestWireViews(t *testing.T) {
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	v1, v2 := store.Store(st), st.ForWire(2)
	if err := v2.Chains().Create(ctx, "kat2", []byte("g2"), "kat.test"); err != nil {
		t.Fatal(err)
	}
	if err := v1.Chains().Create(ctx, "kat1", []byte("g1"), "kat.test"); err != store.ErrHandleTaken {
		t.Fatalf("a handle held in version 2 isn't taken in version 1: %v", err)
	}
	if err := v1.Chains().Append(ctx, "kat2", 0, []byte("e")); err != store.ErrNotFound {
		t.Fatalf("version 1 appended to a version 2 chain: %v", err)
	}
	if err := v2.Chains().Append(ctx, "kat2", 0, []byte("e")); err != nil {
		t.Fatal(err)
	}
	if e, err := v2.Chains().Entries(ctx, "kat2", -1); err != nil || len(e) != 2 {
		t.Fatalf("version 2 chain: %d %v", len(e), err)
	}
	if id, err := v1.Chains().ByHandle(ctx, "kat.test"); err != nil || id != "kat2" {
		t.Fatalf("handles are one namespace: %q %v", id, err)
	}
	if err := v2.Sessions().CreateToken(ctx, []byte{1}, "kat2", []byte{2}, "", 9999999999); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v1.Sessions().LookupToken(ctx, []byte{1}, 1000); err == nil {
		t.Fatal("a version 2 token works on version 1")
	}
	if id, _, err := v2.Sessions().LookupToken(ctx, []byte{1}, 1000); err != nil || id != "kat2" {
		t.Fatalf("version 2 token: %q %v", id, err)
	}
	if err := v2.Outbox().Enqueue(ctx, "b.test", "deliver", []byte("{}"), 5); err != nil {
		t.Fatal(err)
	}
	if d, _ := v1.Outbox().Dests(ctx, 10); len(d) != 0 {
		t.Fatalf("version 1 outbox sees version 2's: %v", d)
	}
	if d, _ := v2.Outbox().Dests(ctx, 10); len(d) != 1 {
		t.Fatalf("version 2 outbox: %v", d)
	}
	b := []byte("binding")
	if _, err := v2.KeyPackages().Upload(ctx, "kat2", []byte{2}, []store.KeyPackage{{Data: []byte("kp"), Binding: b}}, &store.KeyPackage{Data: []byte("lr"), Binding: b}); err != nil {
		t.Fatal(err)
	}
	kps, err := v2.KeyPackages().Claim(ctx, "kat2", [][]byte{{2}})
	if err != nil || len(kps) != 1 || string(kps[0].Binding) != "binding" || string(kps[0].Data) != "kp" {
		t.Fatalf("claimed %+v %v", kps, err)
	}
	if kps, _ := v2.KeyPackages().Claim(ctx, "kat2", [][]byte{{2}}); len(kps) != 1 || !kps[0].LastResort || string(kps[0].Binding) != "binding" {
		t.Fatalf("last resort %+v", kps)
	}
}
