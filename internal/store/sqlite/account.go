package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// ---- account ----

type account struct {
	db   *sql.DB
	wire int // UpdateKeys reads this wire version's chains
}

func (a account) Keys(ctx context.Context, id string) ([][]byte, error) {
	rows, err := a.db.QueryContext(ctx, "SELECT wrapped FROM account_keys WHERE id = ? ORDER BY via", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (a account) Key(ctx context.Context, id, via string) ([]byte, error) {
	var b []byte
	err := a.db.QueryRowContext(ctx, "SELECT wrapped FROM account_keys WHERE id = ? AND via = ?", id, via).Scan(&b)
	return b, notFound(err)
}

func (a account) SetKey(ctx context.Context, id, via string, wrapped []byte) error {
	_, err := a.db.ExecContext(ctx, "INSERT INTO account_keys (id, via, wrapped, stored) VALUES (?, ?, ?, ?) ON CONFLICT (id, via) DO UPDATE SET wrapped = excluded.wrapped, stored = excluded.stored", id, via, wrapped, time.Now().Unix())
	return err
}

// UpdateKeys runs in one transaction. The store has one connection, so it's serialized
// with every chain write too.
func (a account) UpdateKeys(ctx context.Context, id string, decide func([][]byte, []store.KeySlot) ([]store.KeyChange, error)) error {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT entry FROM chains WHERE id = ? AND wire = ? ORDER BY seq", id, a.wire)
	if err != nil {
		return err
	}
	var chain [][]byte
	for rows.Next() {
		var e []byte
		if err := rows.Scan(&e); err != nil {
			rows.Close()
			return err
		}
		chain = append(chain, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return store.ErrNotFound
	}
	rows, err = tx.QueryContext(ctx, "SELECT via, wrapped, stored FROM account_keys WHERE id = ? ORDER BY via", id)
	if err != nil {
		return err
	}
	var slots []store.KeySlot
	for rows.Next() {
		var k store.KeySlot
		if err := rows.Scan(&k.Slot, &k.Wrapped, &k.Stored); err != nil {
			rows.Close()
			return err
		}
		slots = append(slots, k)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	changes, err := decide(chain, slots)
	if err != nil {
		return err
	}
	for _, c := range changes {
		switch {
		case c.Slot == "" || (!c.Delete && c.Wrapped == nil):
			return store.ErrInvalidChange
		case c.Delete:
			_, err = tx.ExecContext(ctx, "DELETE FROM account_keys WHERE id = ? AND via = ?", id, c.Slot)
		default:
			_, err = tx.ExecContext(ctx, "INSERT INTO account_keys (id, via, wrapped, stored) VALUES (?, ?, ?, ?) ON CONFLICT (id, via) DO UPDATE SET wrapped = excluded.wrapped, stored = excluded.stored", id, c.Slot, c.Wrapped, c.Stored)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a account) RemoveKey(ctx context.Context, id, via string) error {
	_, err := a.db.ExecContext(ctx, "DELETE FROM account_keys WHERE id = ? AND via = ?", id, via)
	return err
}

func (a account) Data(ctx context.Context, id string) (int64, []byte, error) {
	var v int64
	var ct []byte
	err := a.db.QueryRowContext(ctx, "SELECT version, ct FROM account_data WHERE id = ?", id).Scan(&v, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	return v, ct, err
}

func (a account) PutData(ctx context.Context, id string, replaces int64, ct []byte) (int64, error) {
	var res sql.Result
	var err error
	if replaces == 0 {
		res, err = a.db.ExecContext(ctx, "INSERT INTO account_data (id, version, ct) VALUES (?, 1, ?) ON CONFLICT (id) DO NOTHING", id, ct)
	} else {
		res, err = a.db.ExecContext(ctx, "UPDATE account_data SET version = version + 1, ct = ? WHERE id = ? AND version = ?", ct, id, replaces)
	}
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, store.ErrConflict
	}
	return replaces + 1, nil
}

// ---- backups ----

type backups struct{ db *sql.DB }

func (b backups) Put(ctx context.Context, id string, seg store.Segment) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old []byte
	var snap bool
	err = tx.QueryRowContext(ctx, "SELECT ct, snapshot FROM backups WHERE id = ? AND seq = ?", id, seg.Seq).Scan(&old, &snap)
	switch {
	case err == nil && bytes.Equal(old, seg.CT) && snap == seg.Snapshot:
		return nil
	case err == nil:
		return store.ErrExists
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	var newest sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT MAX(seq) FROM backups WHERE id = ?", id).Scan(&newest); err != nil {
		return err
	}
	if newest.Valid && seg.Seq <= newest.Int64 {
		return store.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO backups (id, seq, ct, snapshot) VALUES (?, ?, ?, ?)", id, seg.Seq, seg.CT, seg.Snapshot); err != nil {
		return err
	}
	if seg.Snapshot {
		if _, err := tx.ExecContext(ctx, "DELETE FROM backups WHERE id = ? AND seq < ?", id, seg.Seq); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (b backups) List(ctx context.Context, id string) ([]store.Segment, error) {
	rows, err := b.db.QueryContext(ctx, "SELECT seq, snapshot, length(ct) FROM backups WHERE id = ? ORDER BY seq", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Segment
	for rows.Next() {
		var s store.Segment
		if err := rows.Scan(&s.Seq, &s.Snapshot, &s.Size); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (b backups) Get(ctx context.Context, id string, seq int64) (*store.Segment, error) {
	s := store.Segment{Seq: seq}
	err := b.db.QueryRowContext(ctx, "SELECT ct, snapshot FROM backups WHERE id = ? AND seq = ?", id, seq).Scan(&s.CT, &s.Snapshot)
	if err != nil {
		return nil, notFound(err)
	}
	return &s, nil
}

func (b backups) Usage(ctx context.Context, id string) (int64, error) {
	var n sql.NullInt64
	err := b.db.QueryRowContext(ctx, "SELECT SUM(length(ct)) FROM backups WHERE id = ?", id).Scan(&n)
	return n.Int64, err
}
