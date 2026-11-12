package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// ---- profiles ----

type profiles struct{ db *sql.DB }

func (p profiles) Put(ctx context.Context, id string, v int64, signed []byte) error {
	res, err := p.db.ExecContext(ctx, `INSERT INTO profiles (id, v, signed) VALUES (?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET v = excluded.v, signed = excluded.signed WHERE excluded.v > profiles.v`, id, v, signed)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (p profiles) Get(ctx context.Context, id string) ([]byte, error) {
	var b []byte
	err := p.db.QueryRowContext(ctx, "SELECT signed FROM profiles WHERE id = ?", id).Scan(&b)
	return b, notFound(err)
}

// ---- media: bytes in files named by the hex ID, records in the database ----

// The media table's `removed` column: 0 while the file is live.
const (
	mediaRemoved = 1 // deleted after a report
	mediaExpired = 2 // past 30 days
)

type media struct {
	db  *sql.DB
	dir string
}

func (m media) path(id []byte) string { return filepath.Join(m.dir, hex.EncodeToString(id)) }

func (m media) Write(ctx context.Context, meta *store.MediaMeta, r io.Reader, max int64) error {
	tmp, err := os.CreateTemp(m.dir, "upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, max+1))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > max {
		return store.ErrOverQuota
	}
	meta.Size, meta.SHA256 = n, h.Sum(nil)
	if err := os.Rename(tmp.Name(), m.path(meta.ID)); err != nil {
		return err
	}
	_, err = m.db.ExecContext(ctx, "INSERT INTO media (id, owner, size, sha256, mime, public, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
		meta.ID, meta.Owner, meta.Size, meta.SHA256, meta.Mime, meta.Public, meta.Created)
	if err != nil {
		os.Remove(m.path(meta.ID))
	}
	return err
}

func (m media) Get(ctx context.Context, id []byte) (*store.MediaMeta, error) {
	meta := store.MediaMeta{ID: id}
	var state int
	err := m.db.QueryRowContext(ctx, "SELECT owner, size, sha256, mime, public, created, removed FROM media WHERE id = ?", id).
		Scan(&meta.Owner, &meta.Size, &meta.SHA256, &meta.Mime, &meta.Public, &meta.Created, &state)
	if err != nil {
		return nil, notFound(err)
	}
	meta.Removed, meta.Expired = state == mediaRemoved, state == mediaExpired
	return &meta, nil
}

func (m media) Open(ctx context.Context, id []byte) (io.ReadCloser, error) {
	meta, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if meta.Removed || meta.Expired {
		return nil, store.ErrNotFound
	}
	f, err := os.Open(m.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrNotFound
	}
	return f, err
}

func (m media) Usage(ctx context.Context, owner string) (int64, error) {
	var n sql.NullInt64
	err := m.db.QueryRowContext(ctx, "SELECT SUM(size) FROM media WHERE owner = ? AND removed = 0", owner).Scan(&n)
	return n.Int64, err
}

func (m media) Remove(ctx context.Context, id []byte) error {
	res, err := m.db.ExecContext(ctx, "UPDATE media SET removed = ? WHERE id = ?", mediaRemoved, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	os.Remove(m.path(id))
	return nil
}

func (m media) Expire(ctx context.Context, before int64) (int, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT id FROM media WHERE public = 0 AND removed = 0 AND created < ?", before)
	if err != nil {
		return 0, err
	}
	var ids [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		os.Remove(m.path(id))
		if _, err := m.db.ExecContext(ctx, "UPDATE media SET removed = ? WHERE id = ?", mediaExpired, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
