// Package sqlite is rerouted's store.Store, on SQLite (pure Go, no cgo).
//
// Writes use synchronous=FULL, so a commit receipt never goes out before the
// hub's new epoch is on disk (SPEC §11.6). OpenTemp gives tests and demos a
// throwaway database with the same code.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// SchemaVersion is stored in PRAGMA user_version. Bump it with a migration
// whenever the schema changes.
const SchemaVersion = 7

const schema = `
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

type Store struct {
	db       *sql.DB
	mediaDir string // files live here, beside the database
	tempDir  string // removed on Close: set by OpenTemp
}

// Open opens (or creates) the database at path.
func Open(path string) (*Store, error) { return open(path, "FULL") }

// OpenTemp opens a throwaway database in a new temporary directory, which Close
// removes. Nothing in it is meant to outlast the process, so writes aren't synced
// to disk. For tests and demos.
func OpenTemp() (*Store, error) {
	dir, err := os.MkdirTemp("", "rerouted-")
	if err != nil {
		return nil, err
	}
	s, err := open(filepath.Join(dir, "rerouted.db"), "OFF")
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	s.tempDir = dir
	return s, nil
}

func open(path, sync string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=synchronous("+sync+")&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; simplest correct choice for SQLite
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		db.Close()
		return nil, err
	}
	if v > SchemaVersion {
		db.Close()
		return nil, errors.New("database was created by a newer rerouted; refusing to open it")
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Version 2: the hub can await a `reg` registration (SPEC §11.6).
	if v == 1 {
		if _, err := db.Exec("ALTER TABLE hub ADD COLUMN awaiting INTEGER NOT NULL DEFAULT 0"); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Version 3: commits record when they were accepted, so they can be pruned after
	// 30 days (SPEC §11.6). Existing ones count from the upgrade. New tables come from schema.
	if (v == 1 || v == 2) && !hasColumn(db, "commits", "ts") {
		if _, err := db.Exec("ALTER TABLE commits ADD COLUMN ts INTEGER NOT NULL DEFAULT 0"); err != nil {
			db.Close()
			return nil, err
		}
		if _, err := db.Exec("UPDATE commits SET ts = strftime('%s','now')"); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Version 4: commits keep the accepted commit-request, so an exact retry gets its
	// receipt back (SPEC §11.6). Older commits have none, and a retry of one stays stale.
	if v >= 1 && v <= 3 && !hasColumn(db, "commits", "request") {
		if _, err := db.Exec("ALTER TABLE commits ADD COLUMN request BLOB"); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Version 6: key slots record when they were stored, so a staged recovery wrap is kept
	// for its grace period (SPEC §6.3). Existing ones count from the upgrade, in one
	// transaction so a crash can't leave them looking old. Move reservations (SPEC §6.6)
	// are a new table, from schema.
	if v < 6 && !hasColumn(db, "account_keys", "stored") {
		if err := migrateKeyTimes(db); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Version 7: seen delivery IDs record when they were seen, so they can be pruned.
	// Existing ones count from the upgrade. Sent results (POST send) are a new table, from
	// schema.
	if v < 7 && !hasColumn(db, "seen", "ts") {
		if err := migrateSeenTimes(db); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Indexes on columns that older databases only have after the migrations above.
	if _, err := db.Exec(indexes); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA user_version = " + strconv.Itoa(SchemaVersion)); err != nil {
		db.Close()
		return nil, err
	}
	mediaDir := filepath.Join(filepath.Dir(path), "media")
	if err := os.MkdirAll(mediaDir, 0o700); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, mediaDir: mediaDir}, nil
}

const indexes = `
CREATE INDEX IF NOT EXISTS seen_ts ON seen (ts);
CREATE INDEX IF NOT EXISTS sent_ts ON sent (ts);
`

func migrateSeenTimes(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("ALTER TABLE seen ADD COLUMN ts INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE seen SET ts = strftime('%s','now')"); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateKeyTimes(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("ALTER TABLE account_keys ADD COLUMN stored INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE account_keys SET stored = strftime('%s','now')"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	err := s.db.Close()
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
	return err
}

func (s *Store) Chains() store.Chains           { return chains{s.db} }
func (s *Store) Sessions() store.Sessions       { return sessions{s.db} }
func (s *Store) KeyPackages() store.KeyPackages { return keyPackages{s.db} }
func (s *Store) Contacts() store.Contacts       { return contacts{s.db} }
func (s *Store) Invites() store.Invites         { return invites{s.db} }
func (s *Store) Sent() store.Sent               { return sent{s.db} }
func (s *Store) Inbox() store.Inbox             { return inbox{s.db} }
func (s *Store) Hub() store.Hub                 { return hub{s.db} }
func (s *Store) Remote() store.Remote           { return remote{s.db} }
func (s *Store) Outbox() store.Outbox           { return outbox{s.db} }
func (s *Store) Profiles() store.Profiles       { return profiles{s.db} }
func (s *Store) Media() store.Media             { return media{s.db, s.mediaDir} }
func (s *Store) Account() store.Account         { return account{s.db} }
func (s *Store) Backups() store.Backups         { return backups{s.db} }
func (s *Store) Reports() store.Reports         { return reports{s.db} }

// hasColumn reports whether a table has a column, for migrations.
func hasColumn(db *sql.DB, table, column string) bool {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil && name == column {
			return true
		}
	}
	return false
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func isConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "constraint")
}

// ---- chains ----

type chains struct{ db *sql.DB }

// heldByOther reports whether another identity owns `handle`, or holds it with a move
// reservation whose hold hasn't ended at `now` (SPEC §6.6).
func heldByOther(ctx context.Context, tx *sql.Tx, handle, id string, now int64) (bool, error) {
	var owner string
	err := tx.QueryRowContext(ctx, "SELECT id FROM handles WHERE handle = ?", handle).Scan(&owner)
	if err == nil && owner != id {
		return true, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM move_reservations WHERE handle = ? AND id != ? AND hold >= ?", handle, id, now).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (c chains) Reservations(ctx context.Context, id string) ([]store.MoveReservation, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT id, entry, handle, exp, hold FROM move_reservations WHERE id = ? ORDER BY entry", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.MoveReservation
	for rows.Next() {
		var r store.MoveReservation
		if err := rows.Scan(&r.ID, &r.Entry, &r.Handle, &r.Exp, &r.Hold); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c chains) PruneReservations(ctx context.Context, now int64) (int, error) {
	res, err := c.db.ExecContext(ctx, "DELETE FROM move_reservations WHERE hold < ?", now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// Version 5 receipts are created by schema, without inferring acceptance from old chains.
func (c chains) RegisterMove(ctx context.Context, m store.MoveRegistration) (bool, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	receipts, err := tx.QueryContext(ctx, "SELECT operation FROM move_registrations WHERE id = ?", m.ID)
	if err != nil {
		return false, err
	}
	hasReceipts, same, conflict := false, false, false
	for receipts.Next() {
		var op []byte
		if err := receipts.Scan(&op); err != nil {
			receipts.Close()
			return false, err
		}
		hasReceipts = true
		a, b := store.MatchMoveReceipt(op, m.Operation)
		same, conflict = same || a, conflict || b
	}
	err = receipts.Err()
	receipts.Close()
	if err != nil {
		return false, err
	}
	if same {
		return false, nil
	}
	if conflict {
		return false, store.ErrConflict
	}
	rows, err := tx.QueryContext(ctx, "SELECT entry FROM chains WHERE id = ? ORDER BY seq", m.ID)
	if err != nil {
		return false, err
	}
	var have [][]byte
	for rows.Next() {
		var e []byte
		if err := rows.Scan(&e); err != nil {
			rows.Close()
			return false, err
		}
		have = append(have, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if m.Probe && !hasReceipts && len(m.Entries) > 0 && store.SameChain(have, m.Entries) {
		return false, nil
	}
	if m.Probe {
		return false, store.ErrNotFound
	}
	if !store.MoveMatches(have, m) {
		return false, store.ErrConflict
	}
	if held, err := heldByOther(ctx, tx, m.Handle, m.ID, time.Now().Unix()); err != nil {
		return false, err
	} else if held {
		return false, store.ErrHandleTaken
	}
	if m.Check {
		if m.Reserve == nil {
			return false, nil
		}
		r := m.Reserve
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO move_reservations (id, entry, handle, exp, hold) VALUES (?, ?, ?, ?, ?)", r.ID, r.Entry, r.Handle, r.Exp, r.Hold); err != nil {
			return false, err
		}
		return true, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR REPLACE INTO handles (handle, id) VALUES (?, ?)", m.Handle, m.ID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM chains WHERE id = ?", m.ID); err != nil {
		return false, err
	}
	for i, e := range m.Entries {
		if _, err = tx.ExecContext(ctx, "INSERT INTO chains (id, seq, entry) VALUES (?, ?, ?)", m.ID, i, e); err != nil {
			return false, err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM contacts WHERE owner = ?", m.ID); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM groups_allowed WHERE owner = ?", m.ID); err != nil {
		return false, err
	}
	for _, v := range m.Contacts {
		if _, err = tx.ExecContext(ctx, "INSERT OR REPLACE INTO contacts (owner, other, state, since, request) VALUES (?, ?, ?, ?, ?)", m.ID, v.ID, v.State, v.Since, v.Request); err != nil {
			return false, err
		}
	}
	for _, g := range m.Groups {
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO groups_allowed (owner, grp) VALUES (?, ?)", m.ID, g); err != nil {
			return false, err
		}
	}
	if len(m.Expected) > 0 { // a return: the earlier stay's data goes, recovery wraps stay
		if err = clearEarlierStay(ctx, tx, m.ID); err != nil {
			return false, err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO move_registrations (id, operation) VALUES (?, ?)", m.ID, m.Operation); err != nil {
		return false, err
	}
	// Registering consumes the identity's reservations, and with them the handle hold.
	if _, err = tx.ExecContext(ctx, "DELETE FROM move_reservations WHERE id = ?", m.ID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// clearEarlierStay deletes a returning identity's account data, backups, and key slots
// other than recovery wraps (store.IsRecoverySlot).
func clearEarlierStay(ctx context.Context, tx *sql.Tx, id string) error {
	for _, q := range []string{"DELETE FROM account_data WHERE id = ?", "DELETE FROM backups WHERE id = ?"} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT via FROM account_keys WHERE id = ?", id)
	if err != nil {
		return err
	}
	var drop []string
	for rows.Next() {
		var via string
		if err := rows.Scan(&via); err != nil {
			rows.Close()
			return err
		}
		if !store.IsRecoverySlot(via) {
			drop = append(drop, via)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, via := range drop {
		if _, err := tx.ExecContext(ctx, "DELETE FROM account_keys WHERE id = ? AND via = ?", id, via); err != nil {
			return err
		}
	}
	return nil
}

func (c chains) Create(ctx context.Context, id string, genesis []byte, handle string) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing []byte
	switch err := tx.QueryRowContext(ctx, "SELECT entry FROM chains WHERE id = ? AND seq = 0", id).Scan(&existing); {
	case err == nil:
		if string(existing) == string(genesis) {
			return nil
		}
		return store.ErrConflict
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if handle != "" {
		if held, err := heldByOther(ctx, tx, handle, id, time.Now().Unix()); err != nil {
			return err
		} else if held {
			return store.ErrHandleTaken
		}
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO handles (handle, id) VALUES (?, ?)", handle, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO chains (id, seq, entry) VALUES (?, 0, ?)", id, genesis); err != nil {
		return err
	}
	return tx.Commit()
}

func (c chains) Fork(ctx context.Context, id string, from, headSeq uint64, entries [][]byte) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var head sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT MAX(seq) FROM chains WHERE id = ?", id).Scan(&head); err != nil {
		return err
	}
	if !head.Valid {
		return store.ErrNotFound
	}
	if uint64(head.Int64) != headSeq || from == 0 || from > headSeq+1 {
		return store.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM chains WHERE id = ? AND seq >= ?", id, from); err != nil {
		return err
	}
	for i, e := range entries {
		if _, err := tx.ExecContext(ctx, "INSERT INTO chains (id, seq, entry) VALUES (?, ?, ?)", id, from+uint64(i), e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c chains) Append(ctx context.Context, id string, prevSeq uint64, entry []byte) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var head sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT MAX(seq) FROM chains WHERE id = ?", id).Scan(&head); err != nil {
		return err
	}
	if !head.Valid {
		return store.ErrNotFound
	}
	if uint64(head.Int64) != prevSeq {
		return store.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO chains (id, seq, entry) VALUES (?, ?, ?)", id, prevSeq+1, entry); err != nil {
		if isConstraint(err) {
			return store.ErrConflict
		}
		return err
	}
	return tx.Commit()
}

func (c chains) Entries(ctx context.Context, id string, after int64) ([][]byte, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT entry FROM chains WHERE id = ? AND seq > ? ORDER BY seq", id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var e []byte
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if out == nil && after < 0 {
		return nil, store.ErrNotFound
	}
	return out, rows.Err()
}

func (c chains) ByHandle(ctx context.Context, handle string) (string, error) {
	var id string
	err := c.db.QueryRowContext(ctx, "SELECT id FROM handles WHERE handle = ?", handle).Scan(&id)
	return id, notFound(err)
}

func (c chains) ReleaseHandle(ctx context.Context, handle string) (string, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM handles WHERE handle = ?", handle).Scan(&id); err != nil {
		return "", notFound(err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM handles WHERE handle = ?", handle); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

// ---- sessions ----

type sessions struct{ db *sql.DB }

func nonceKey(id string, device, nonce []byte) string {
	return id + "|" + string(wire.HexBytes(device)) + "|" + string(wire.HexBytes(nonce))
}

func (x sessions) PutNonce(ctx context.Context, id string, device, nonce []byte, expires int64) error {
	_, err := x.db.ExecContext(ctx, "INSERT OR REPLACE INTO nonces (k, expires) VALUES (?, ?)", nonceKey(id, device, nonce), expires)
	return err
}

func (x sessions) UseNonce(ctx context.Context, key string, expires, now int64) (bool, error) {
	// Inserts the key, or takes over an expired record of it; a live one is left alone.
	res, err := x.db.ExecContext(ctx, `INSERT INTO nonces (k, expires) VALUES (?, ?)
		ON CONFLICT (k) DO UPDATE SET expires = excluded.expires WHERE nonces.expires < ?`, key, expires, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (x sessions) PruneNonces(ctx context.Context, now int64) (int, error) {
	res, err := x.db.ExecContext(ctx, "DELETE FROM nonces WHERE expires < ?", now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (x sessions) TakeNonce(ctx context.Context, id string, device, nonce []byte, now int64) error {
	res, err := x.db.ExecContext(ctx, "DELETE FROM nonces WHERE k = ? AND expires >= ?", nonceKey(id, device, nonce), now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (x sessions) CreateToken(ctx context.Context, tokenHash []byte, id string, device []byte, name string, expires int64) error {
	_, err := x.db.ExecContext(ctx, "INSERT INTO tokens (hash, id, device, name, expires) VALUES (?, ?, ?, ?, ?)", tokenHash, id, device, name, expires)
	return err
}

const tokenTTL = 30 * 24 * 3600

func (x sessions) LookupToken(ctx context.Context, tokenHash []byte, now int64) (string, []byte, error) {
	var id string
	var dev []byte
	err := x.db.QueryRowContext(ctx, "SELECT id, device FROM tokens WHERE hash = ? AND expires >= ?", tokenHash, now).Scan(&id, &dev)
	if err != nil {
		return "", nil, notFound(err)
	}
	x.db.ExecContext(ctx, "UPDATE tokens SET expires = ? WHERE hash = ?", now+tokenTTL, tokenHash)
	return id, dev, nil
}

func (x sessions) RevokeToken(ctx context.Context, tokenHash []byte) error {
	_, err := x.db.ExecContext(ctx, "DELETE FROM tokens WHERE hash = ?", tokenHash)
	return err
}

func (x sessions) RevokeDevice(ctx context.Context, id string, device []byte) error {
	_, err := x.db.ExecContext(ctx, "DELETE FROM tokens WHERE id = ? AND device = ?", id, device)
	return err
}

// ---- key packages ----

type keyPackages struct{ db *sql.DB }

const maxKeyPackages = 200

func (k keyPackages) Upload(ctx context.Context, id string, device []byte, packages [][]byte, lastResort []byte) (int, error) {
	tx, err := k.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int
	tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM kps WHERE id = ? AND device = ? AND last_resort = 0", id, device).Scan(&n)
	if n+len(packages) > maxKeyPackages {
		return n, store.ErrOverQuota
	}
	for _, p := range packages {
		if _, err := tx.ExecContext(ctx, "INSERT INTO kps (id, device, data, last_resort) VALUES (?, ?, ?, 0)", id, device, p); err != nil {
			return n, err
		}
	}
	if lastResort != nil {
		tx.ExecContext(ctx, "DELETE FROM kps WHERE id = ? AND device = ? AND last_resort = 1", id, device)
		if _, err := tx.ExecContext(ctx, "INSERT INTO kps (id, device, data, last_resort) VALUES (?, ?, ?, 1)", id, device, lastResort); err != nil {
			return n, err
		}
	}
	return n + len(packages), tx.Commit()
}

func (k keyPackages) Clear(ctx context.Context, id string, device []byte) error {
	_, err := k.db.ExecContext(ctx, "DELETE FROM kps WHERE id = ? AND device = ? AND last_resort = 0", id, device)
	return err
}

func (k keyPackages) Count(ctx context.Context, id string, device []byte) (int, bool, error) {
	var n, lr int
	err := k.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(last_resort = 0), 0), COALESCE(SUM(last_resort = 1), 0) FROM kps WHERE id = ? AND device = ?", id, device).Scan(&n, &lr)
	return n, lr > 0, err
}

func (k keyPackages) Claim(ctx context.Context, id string, devices [][]byte) ([]store.KeyPackage, error) {
	tx, err := k.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var out []store.KeyPackage
	for _, d := range devices {
		var n int64
		var data []byte
		err := tx.QueryRowContext(ctx, "SELECT n, data FROM kps WHERE id = ? AND device = ? AND last_resort = 0 ORDER BY n LIMIT 1", id, d).Scan(&n, &data)
		if err == nil {
			tx.ExecContext(ctx, "DELETE FROM kps WHERE n = ?", n)
			out = append(out, store.KeyPackage{Device: d, Data: data})
			continue
		}
		if err := tx.QueryRowContext(ctx, "SELECT data FROM kps WHERE id = ? AND device = ? AND last_resort = 1", id, d).Scan(&data); err == nil {
			out = append(out, store.KeyPackage{Device: d, Data: data, LastResort: true})
		}
	}
	return out, tx.Commit()
}

// ---- contacts ----

type contacts struct{ db *sql.DB }

func (c contacts) Get(ctx context.Context, owner, other string) (*store.Contact, error) {
	ct := store.Contact{ID: other}
	err := c.db.QueryRowContext(ctx, "SELECT state, since, request FROM contacts WHERE owner = ? AND other = ?", owner, other).Scan(&ct.State, &ct.Since, &ct.Request)
	if err != nil {
		return nil, notFound(err)
	}
	return &ct, nil
}

func (c contacts) Put(ctx context.Context, owner string, ct store.Contact) error {
	_, err := c.db.ExecContext(ctx, "INSERT OR REPLACE INTO contacts (owner, other, state, since, request) VALUES (?, ?, ?, ?, ?)", owner, ct.ID, ct.State, ct.Since, ct.Request)
	return err
}

func (c contacts) Delete(ctx context.Context, owner, other string) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM contacts WHERE owner = ? AND other = ?", owner, other)
	return err
}

func (c contacts) List(ctx context.Context, owner string, after string, limit int) ([]store.Contact, string, error) {
	limit = max(limit, 1) // pages hold at least one item, so the next cursor is always one of them
	rows, err := c.db.QueryContext(ctx, "SELECT other, state, since, request FROM contacts WHERE owner = ? AND other > ? AND state != 'declined' ORDER BY other LIMIT ?", owner, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []store.Contact
	for rows.Next() {
		var ct store.Contact
		if err := rows.Scan(&ct.ID, &ct.State, &ct.Since, &ct.Request); err != nil {
			return nil, "", err
		}
		out = append(out, ct)
	}
	next := ""
	if len(out) > limit {
		out, next = out[:limit], out[limit-1].ID
	}
	return out, next, rows.Err()
}

func (c contacts) Owners(ctx context.Context, other string) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT owner FROM contacts WHERE other = ? AND state NOT IN ('blocked', 'declined')", other)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (c contacts) AllowGroup(ctx context.Context, owner string, group []byte) error {
	_, err := c.db.ExecContext(ctx, "INSERT OR IGNORE INTO groups_allowed (owner, grp) VALUES (?, ?)", owner, group)
	return err
}

func (c contacts) DisallowGroup(ctx context.Context, owner string, group []byte) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM groups_allowed WHERE owner = ? AND grp = ?", owner, group)
	return err
}

func (c contacts) GroupAllowed(ctx context.Context, owner string, group []byte) (bool, error) {
	var n int
	err := c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups_allowed WHERE owner = ? AND grp = ?", owner, group).Scan(&n)
	return n > 0, err
}

// ---- inbox ----

type inbox struct{ db *sql.DB }

func (x inbox) Append(ctx context.Context, owner string, it store.Item) (string, error) {
	res, err := x.db.ExecContext(ctx, "INSERT INTO inbox (owner, ts, delivery, notice) VALUES (?, ?, ?, ?)", owner, it.TS, it.Delivery, it.Notice)
	if err != nil {
		return "", err
	}
	n, _ := res.LastInsertId()
	return strconv.FormatInt(n, 10), nil
}

func (x inbox) List(ctx context.Context, owner string, device []byte, after string, limit int) ([]store.Item, string, bool, error) {
	limit = max(limit, 1) // pages hold at least one item, so the next cursor is always one of them
	from, err := strconv.ParseInt(after, 10, 64)
	if after == "" || err != nil {
		from = 0
		x.db.QueryRowContext(ctx, "SELECT upto FROM acks WHERE owner = ? AND device = ?", owner, device).Scan(&from)
	}
	rows, err := x.db.QueryContext(ctx, "SELECT cursor, ts, delivery, notice FROM inbox WHERE owner = ? AND cursor > ? ORDER BY cursor LIMIT ?", owner, from, limit+1)
	if err != nil {
		return nil, "", false, err
	}
	defer rows.Close()
	var out []store.Item
	for rows.Next() {
		var it store.Item
		var c int64
		if err := rows.Scan(&c, &it.TS, &it.Delivery, &it.Notice); err != nil {
			return nil, "", false, err
		}
		it.Cursor = strconv.FormatInt(c, 10)
		out = append(out, it)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[limit-1].Cursor
	}
	return out, next, false, rows.Err()
}

func (x inbox) Ack(ctx context.Context, owner string, device []byte, upto string) error {
	n, err := strconv.ParseInt(upto, 10, 64)
	if err != nil {
		return nil
	}
	_, err = x.db.ExecContext(ctx, `INSERT INTO acks (owner, device, upto) VALUES (?, ?, ?)
		ON CONFLICT (owner, device) DO UPDATE SET upto = MAX(upto, excluded.upto)`, owner, device, n)
	return err
}

func (x inbox) Prune(ctx context.Context, owner string, devices [][]byte, before int64) error {
	// The lowest ack across current devices: everything at or below it has been seen by all.
	low := int64(-1)
	for _, d := range devices {
		var upto int64
		if err := x.db.QueryRowContext(ctx, "SELECT upto FROM acks WHERE owner = ? AND device = ?", owner, d).Scan(&upto); err != nil {
			low = 0 // a device that never acked holds everything back
			break
		}
		if low < 0 || upto < low {
			low = upto
		}
	}
	if low < 0 {
		low = 0
	}
	_, err := x.db.ExecContext(ctx, "DELETE FROM inbox WHERE owner = ? AND (cursor <= ? OR ts < ?)", owner, low, before)
	return err
}

func (x inbox) Deliver(ctx context.Context, owner string, id []byte, it store.Item) (string, bool, error) {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO seen (owner, did, ts) VALUES (?, ?, ?)", owner, id, it.TS)
	if err != nil {
		return "", false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return "", false, err
	}
	res, err = tx.ExecContext(ctx, "INSERT INTO inbox (owner, ts, delivery, notice) VALUES (?, ?, ?, ?)", owner, it.TS, it.Delivery, it.Notice)
	if err != nil {
		return "", false, err
	}
	n, err := res.LastInsertId()
	if err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return strconv.FormatInt(n, 10), true, nil
}

func (x inbox) PruneSeen(ctx context.Context, before int64) (int, error) {
	res, err := x.db.ExecContext(ctx, "DELETE FROM seen WHERE ts < ?", before)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ---- sent results ----

type sent struct{ db *sql.DB }

func (x sent) Get(ctx context.Context, sender string, id []byte) ([]byte, error) {
	var b []byte
	err := x.db.QueryRowContext(ctx, "SELECT result FROM sent WHERE sender = ? AND did = ?", sender, id).Scan(&b)
	return b, notFound(err)
}

func (x sent) Put(ctx context.Context, sender string, id, result []byte, ts int64) error {
	_, err := x.db.ExecContext(ctx, "INSERT OR IGNORE INTO sent (sender, did, result, ts) VALUES (?, ?, ?, ?)", sender, id, result, ts)
	return err
}

func (x sent) Prune(ctx context.Context, before int64) (int, error) {
	res, err := x.db.ExecContext(ctx, "DELETE FROM sent WHERE ts < ?", before)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ---- hub ----

type hub struct{ db *sql.DB }

func (h hub) Register(ctx context.Context, g store.HubGroup) error {
	_, err := h.db.ExecContext(ctx, "INSERT INTO hub (grp, epoch, key) VALUES (?, ?, ?)", g.Group, g.Epoch, g.EpochKey)
	if isConstraint(err) {
		return store.ErrConflict
	}
	return err
}

func (h hub) Group(ctx context.Context, group []byte) (*store.HubGroup, error) {
	g := store.HubGroup{Group: group}
	err := h.db.QueryRowContext(ctx, "SELECT epoch, key, awaiting FROM hub WHERE grp = ?", group).Scan(&g.Epoch, &g.EpochKey, &g.Awaiting)
	if err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

func (h hub) Accept(ctx context.Context, group []byte, epoch uint64, nextKey []byte, awaiting bool, c store.Commit) error {
	receipt, err := c.Receipt.Encode()
	if err != nil {
		return err
	}
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE hub SET epoch = epoch + 1, key = ?, awaiting = ? WHERE grp = ? AND epoch = ? AND awaiting = 0", nextKey, awaiting, group, epoch)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := h.Group(ctx, group); errors.Is(err, store.ErrNotFound) {
			return store.ErrNotFound
		}
		return store.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO commits (grp, epoch, data, receipt, ts, request) VALUES (?, ?, ?, ?, ?, ?)", group, c.Epoch, c.Data, receipt, c.TS, c.Request); err != nil {
		return err
	}
	return tx.Commit() // durable (synchronous=FULL) before the caller sends the receipt
}

func (h hub) SetKey(ctx context.Context, group []byte, epoch uint64, reg, next []byte) error {
	res, err := h.db.ExecContext(ctx, "UPDATE hub SET key = ?, awaiting = 0 WHERE grp = ? AND epoch = ? AND awaiting = 1 AND key = ?", next, group, epoch, reg)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (h hub) Commits(ctx context.Context, group []byte, from uint64) ([]store.Commit, error) {
	if _, err := h.Group(ctx, group); err != nil {
		return nil, err
	}
	rows, err := h.db.QueryContext(ctx, "SELECT epoch, data, receipt, ts, request FROM commits WHERE grp = ? AND epoch >= ? ORDER BY epoch", group, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Commit
	for rows.Next() {
		var c store.Commit
		var receipt []byte
		if err := rows.Scan(&c.Epoch, &c.Data, &receipt, &c.TS, &c.Request); err != nil {
			return nil, err
		}
		if c.Receipt, err = wire.DecodeSigned(receipt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (h hub) PruneCommits(ctx context.Context, before int64) error {
	_, err := h.db.ExecContext(ctx, "DELETE FROM commits WHERE ts < ?", before)
	return err
}

// ---- remote chains ----

type remote struct{ db *sql.DB }

func (r remote) Put(ctx context.Context, id, home string, entries [][]byte) error {
	b, err := wire.Marshal(entries)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, "INSERT OR REPLACE INTO remote (id, home, entries) VALUES (?, ?, ?)", id, home, b)
	return err
}

func (r remote) Get(ctx context.Context, id string) (string, [][]byte, error) {
	var home string
	var b []byte
	if err := r.db.QueryRowContext(ctx, "SELECT home, entries FROM remote WHERE id = ?", id).Scan(&home, &b); err != nil {
		return "", nil, notFound(err)
	}
	var stored []wire.Bytes
	if err := wire.Unmarshal(b, &stored); err != nil {
		return "", nil, err
	}
	entries := make([][]byte, len(stored))
	for i, e := range stored {
		entries[i] = e
	}
	return home, entries, nil
}

func (r remote) HasContactOn(ctx context.Context, home string) (bool, error) {
	var one int
	err := r.db.QueryRowContext(ctx, "SELECT 1 FROM remote r JOIN contacts c ON c.other = r.id WHERE r.home = ? AND c.state = 'contact' LIMIT 1", home).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ---- outbox ----

type outbox struct{ db *sql.DB }

func (o outbox) Enqueue(ctx context.Context, dest, path string, body []byte, now int64) error {
	_, err := o.db.ExecContext(ctx, "INSERT INTO outbox (dest, path, body, next, created) VALUES (?, ?, ?, ?, ?)", dest, path, body, now, now)
	return err
}

func (o outbox) Due(ctx context.Context, now int64, limit int) ([]store.OutboxItem, error) {
	rows, err := o.db.QueryContext(ctx, "SELECT n, dest, path, body, attempts, created FROM outbox WHERE next <= ? ORDER BY n LIMIT ?", now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.OutboxItem
	for rows.Next() {
		var it store.OutboxItem
		if err := rows.Scan(&it.ID, &it.Dest, &it.Path, &it.Body, &it.Attempts, &it.Created); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (o outbox) Done(ctx context.Context, id int64) error {
	_, err := o.db.ExecContext(ctx, "DELETE FROM outbox WHERE n = ?", id)
	return err
}

func (o outbox) Retry(ctx context.Context, id int64, next int64) error {
	_, err := o.db.ExecContext(ctx, "UPDATE outbox SET attempts = attempts + 1, next = ? WHERE n = ?", next, id)
	return err
}

var _ store.Store = (*Store)(nil)

// ---- invites ----

type invites struct{ db *sql.DB }

func (x invites) Create(ctx context.Context, inv store.Invite) error {
	_, err := x.db.ExecContext(ctx, "INSERT OR REPLACE INTO invites (owner, hash, public, uses, expires, created) VALUES (?, ?, ?, ?, ?, ?)",
		inv.Owner, inv.Hash, inv.Public, inv.Uses, inv.Expires, inv.Created)
	return err
}

func (x invites) Revoke(ctx context.Context, owner string, hash []byte) error {
	res, err := x.db.ExecContext(ctx, "DELETE FROM invites WHERE owner = ? AND hash = ?", owner, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (x invites) List(ctx context.Context, owner string, now int64) ([]store.Invite, error) {
	rows, err := x.db.QueryContext(ctx, "SELECT hash, public, uses, expires, created FROM invites WHERE owner = ? AND (expires = 0 OR expires >= ?) ORDER BY created", owner, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.Invite{}
	for rows.Next() {
		inv := store.Invite{Owner: owner}
		if err := rows.Scan(&inv.Hash, &inv.Public, &inv.Uses, &inv.Expires, &inv.Created); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

func (x invites) Use(ctx context.Context, owner string, hash []byte, now int64) (*store.Invite, error) {
	tx, err := x.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	inv := store.Invite{Owner: owner, Hash: hash}
	err = tx.QueryRowContext(ctx, "SELECT public, uses, expires, created FROM invites WHERE owner = ? AND hash = ?", owner, hash).
		Scan(&inv.Public, &inv.Uses, &inv.Expires, &inv.Created)
	if err != nil {
		return nil, notFound(err)
	}
	if inv.Expires != 0 && inv.Expires < now {
		return nil, store.ErrNotFound
	}
	switch {
	case inv.Uses == 1:
		_, err = tx.ExecContext(ctx, "DELETE FROM invites WHERE owner = ? AND hash = ?", owner, hash)
	case inv.Uses > 1:
		_, err = tx.ExecContext(ctx, "UPDATE invites SET uses = uses - 1 WHERE owner = ? AND hash = ?", owner, hash)
	}
	if err != nil {
		return nil, err
	}
	if inv.Uses > 0 {
		inv.Uses--
	}
	return &inv, tx.Commit()
}
