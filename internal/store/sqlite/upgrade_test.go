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
	if err := st.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != 7 {
		t.Fatalf("user_version %d (%v), want 7", uv, err)
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
