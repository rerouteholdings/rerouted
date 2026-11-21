package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// Community servers (SPEC §16): schema version 11's tables, all prefixed cm_, all keyed by
// the server name a community is hosted under. Trees and files live beside the database,
// under media/community/<name>/.
const communitySchema = `
CREATE TABLE IF NOT EXISTS cm_communities (name TEXT PRIMARY KEY, id BLOB NOT NULL, grp BLOB, created INTEGER NOT NULL, pruned INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS cm_chain    (name TEXT NOT NULL, seq INTEGER NOT NULL, entry BLOB NOT NULL, hash BLOB NOT NULL, PRIMARY KEY (name, seq));
CREATE TABLE IF NOT EXISTS cm_holds    (name TEXT PRIMARY KEY, community BLOB NOT NULL, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cm_former   (name TEXT NOT NULL, id TEXT NOT NULL, home TEXT NOT NULL, PRIMARY KEY (name, id));
CREATE TABLE IF NOT EXISTS cm_listed   (name TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY (name, id));
CREATE TABLE IF NOT EXISTS cm_members  (name TEXT NOT NULL, id TEXT NOT NULL, home TEXT NOT NULL, since INTEGER NOT NULL, PRIMARY KEY (name, id));
CREATE TABLE IF NOT EXISTS cm_tokens   (hash BLOB PRIMARY KEY, name TEXT NOT NULL, id TEXT NOT NULL, home TEXT NOT NULL, device BLOB NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS cm_tokens_id ON cm_tokens (name, id);
CREATE TABLE IF NOT EXISTS cm_kps      (n INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, id TEXT NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, binding BLOB NOT NULL, last_resort INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS cm_kps_dev ON cm_kps (name, id, device);
CREATE TABLE IF NOT EXISTS cm_groups   (grp BLOB PRIMARY KEY, name TEXT NOT NULL, see TEXT NOT NULL, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0, info BLOB, tree BLOB, tree_size INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS cm_commits  (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, request BLOB NOT NULL, proof BLOB, ts INTEGER NOT NULL, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS cm_regs     (grp BLOB NOT NULL, id TEXT NOT NULL, device BLOB NOT NULL, since INTEGER NOT NULL, PRIMARY KEY (grp, id, device));
CREATE TABLE IF NOT EXISTS cm_trees    (name TEXT NOT NULL, hash BLOB NOT NULL, size INTEGER NOT NULL, uploaded INTEGER NOT NULL, uploader TEXT NOT NULL, PRIMARY KEY (name, hash));
CREATE TABLE IF NOT EXISTS cm_tree_uses (grp BLOB NOT NULL, epoch INTEGER NOT NULL, name TEXT NOT NULL, hash BLOB NOT NULL, keep INTEGER NOT NULL, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS cm_inbox    (cursor INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ts INTEGER NOT NULL, grp BLOB, from_id TEXT NOT NULL DEFAULT '', from_dev BLOB, to_id TEXT NOT NULL DEFAULT '', to_dev BLOB, members INTEGER NOT NULL DEFAULT 0, channel INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0, delivery BLOB, notice BLOB);
CREATE INDEX IF NOT EXISTS cm_inbox_name ON cm_inbox (name, cursor);
CREATE INDEX IF NOT EXISTS cm_inbox_channel ON cm_inbox (name, channel, seq);
CREATE TABLE IF NOT EXISTS cm_acks     (name TEXT NOT NULL, id TEXT NOT NULL, device BLOB NOT NULL, upto INTEGER NOT NULL, PRIMARY KEY (name, id, device));
CREATE TABLE IF NOT EXISTS cm_channels (name TEXT NOT NULL, channel INTEGER NOT NULL, last INTEGER NOT NULL, PRIMARY KEY (name, channel));
CREATE TABLE IF NOT EXISTS cm_sent     (name TEXT NOT NULL, sender TEXT NOT NULL, did BLOB NOT NULL, result BLOB NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (name, sender, did));
CREATE TABLE IF NOT EXISTS cm_code_uses (name TEXT NOT NULL, code BLOB NOT NULL, used INTEGER NOT NULL, PRIMARY KEY (name, code));
CREATE TABLE IF NOT EXISTS cm_requests (name TEXT NOT NULL, id TEXT NOT NULL, home TEXT NOT NULL, ts INTEGER NOT NULL, approver TEXT NOT NULL DEFAULT '', approved INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (name, id));
CREATE TABLE IF NOT EXISTS cm_segments (name TEXT NOT NULL, channel INTEGER NOT NULL, s_start INTEGER NOT NULL, s_end INTEGER NOT NULL, ct BLOB NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (name, channel, s_start));
CREATE TABLE IF NOT EXISTS cm_deletes  (name TEXT NOT NULL, channel INTEGER NOT NULL, seq INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (name, channel, seq));
CREATE TABLE IF NOT EXISTS cm_media    (name TEXT NOT NULL, id BLOB NOT NULL, author TEXT NOT NULL, size INTEGER NOT NULL, sha256 BLOB NOT NULL, created INTEGER NOT NULL, state INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (name, id));
CREATE TABLE IF NOT EXISTS cm_icons    (name TEXT NOT NULL, hash BLOB NOT NULL, mime TEXT NOT NULL, data BLOB NOT NULL, uploaded INTEGER NOT NULL, PRIMARY KEY (name, hash));
CREATE TABLE IF NOT EXISTS cm_reads    (name TEXT NOT NULL, id TEXT NOT NULL, channel INTEGER NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (name, id, channel));
CREATE TABLE IF NOT EXISTS cm_replaced (grp BLOB PRIMARY KEY, name TEXT NOT NULL, new_grp BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS cm_epochs   (grp BLOB NOT NULL, epoch INTEGER NOT NULL, key BLOB NOT NULL, info BLOB, tree BLOB, tree_size INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL, PRIMARY KEY (grp, epoch));
CREATE TABLE IF NOT EXISTS cm_undos    (grp BLOB NOT NULL, epoch INTEGER NOT NULL, hash BLOB NOT NULL, undo BLOB NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (grp, epoch, hash));
CREATE TABLE IF NOT EXISTS cm_reports  (n INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, rid BLOB NOT NULL, ts INTEGER NOT NULL, reporter TEXT NOT NULL, body BLOB NOT NULL, at BLOB, UNIQUE (name, rid));
`

type communities struct {
	db, rdb *sql.DB
	dir     string // media/community
}

func (c communities) cdir(name, kind string) string {
	return filepath.Join(c.dir, strings.ReplaceAll(name, "/", "_"), kind)
}

// groupKnown reports whether a group ID is taken here, as a community group or a
// homeserver hub's group: group IDs are one namespace on a server (SPEC §11.5).
func groupKnown(ctx context.Context, tx *sql.Tx, group []byte) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM cm_groups WHERE grp = ?) + (SELECT count(*) FROM hub WHERE grp = ?)", group, group).Scan(&n)
	return n > 0, err
}

func (c communities) Create(ctx context.Context, cm store.Community, entries, hashes [][]byte, owner store.CommunityMember, g *store.CGroup) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_communities WHERE name = ?", cm.Name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return store.ErrExists
	}
	// A move reservation holds the name for its community (SPEC §16.6): anything else is
	// refused while the hold lasts, and the community's own move-in ends it.
	var held []byte
	var until int64
	switch err := tx.QueryRowContext(ctx, "SELECT community, until FROM cm_holds WHERE name = ?", cm.Name).Scan(&held, &until); {
	case err == nil:
		if until > cm.Created && !bytes.Equal(held, cm.ID) {
			return store.ErrExists
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM cm_holds WHERE name = ?", cm.Name); err != nil {
			return err
		}
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if g != nil {
		if known, err := groupKnown(ctx, tx, g.Group); err != nil {
			return err
		} else if known {
			return store.ErrConflict
		}
		cm.Group = g.Group
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_communities (name, id, grp, created) VALUES (?, ?, ?, ?)", cm.Name, cm.ID, cm.Group, cm.Created); err != nil {
		return err
	}
	for _, id := range cm.Listed {
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_listed (name, id) VALUES (?, ?) ON CONFLICT DO NOTHING", cm.Name, id); err != nil {
			return err
		}
	}
	for ch, last := range cm.Seqs {
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_channels (name, channel, last) VALUES (?, ?, ?)", cm.Name, ch, last); err != nil {
			return err
		}
	}
	for i, e := range entries {
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_chain (name, seq, entry, hash) VALUES (?, ?, ?, ?)", cm.Name, i, e, hashes[i]); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_members (name, id, home, since) VALUES (?, ?, ?, ?)", cm.Name, owner.ID, owner.Home, owner.Since); err != nil {
		return err
	}
	if g != nil {
		if err := insertGroup(ctx, tx, *g); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func insertGroup(ctx context.Context, tx *sql.Tx, g store.CGroup) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO cm_groups (grp, name, see, epoch, key, awaiting, info, tree, tree_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		g.Group, g.Name, g.See, g.Epoch, g.Key, g.Awaiting, g.Info, g.Tree, g.TreeSize)
	return err
}

func (c communities) Get(ctx context.Context, name string) (*store.Community, error) {
	cm := store.Community{Name: name}
	err := c.rdb.QueryRowContext(ctx, "SELECT id, grp, created FROM cm_communities WHERE name = ?", name).Scan(&cm.ID, &cm.Group, &cm.Created)
	if err != nil {
		return nil, notFound(err)
	}
	return &cm, nil
}

func (c communities) Entries(ctx context.Context, name string, after int64) ([][]byte, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT entry FROM cm_chain WHERE name = ? AND seq > ? ORDER BY seq", name, after)
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
	return out, rows.Err()
}

func (c communities) Append(ctx context.Context, name string, seq uint64, entry, hash []byte, remove []string) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var head sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT MAX(seq) FROM cm_chain WHERE name = ?", name).Scan(&head); err != nil {
		return err
	}
	if !head.Valid || uint64(head.Int64)+1 != seq {
		return store.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_chain (name, seq, entry, hash) VALUES (?, ?, ?, ?)", name, seq, entry, hash); err != nil {
		return err
	}
	for _, id := range remove {
		if err := removeMember(ctx, tx, name, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func removeMember(ctx context.Context, tx *sql.Tx, name, id string) error {
	// A former member's chain stays available to members (SPEC §16.1).
	if _, err := tx.ExecContext(ctx, `INSERT INTO cm_former (name, id, home) SELECT name, id, home FROM cm_members WHERE name = ? AND id = ?
		ON CONFLICT (name, id) DO UPDATE SET home = excluded.home`, name, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cm_members WHERE name = ? AND id = ?", name, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM cm_reads WHERE name = ? AND id = ?", name, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM cm_regs WHERE id = ? AND grp IN (SELECT grp FROM cm_groups WHERE name = ?)", id, name)
	return err
}

// ---- members ----

func (c communities) AddMember(ctx context.Context, name string, m store.CommunityMember) error {
	_, err := c.db.ExecContext(ctx, "INSERT INTO cm_members (name, id, home, since) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", name, m.ID, m.Home, m.Since)
	return err
}

func (c communities) RemoveMember(ctx context.Context, name, id string) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := removeMember(ctx, tx, name, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (c communities) Member(ctx context.Context, name, id string) (*store.CommunityMember, error) {
	m := store.CommunityMember{ID: id}
	err := c.rdb.QueryRowContext(ctx, "SELECT home, since FROM cm_members WHERE name = ? AND id = ?", name, id).Scan(&m.Home, &m.Since)
	if err != nil {
		return nil, notFound(err)
	}
	return &m, nil
}

func (c communities) FormerMember(ctx context.Context, name, id string) (*store.CommunityMember, error) {
	m := store.CommunityMember{ID: id}
	err := c.rdb.QueryRowContext(ctx, "SELECT home FROM cm_former WHERE name = ? AND id = ?", name, id).Scan(&m.Home)
	if err != nil {
		return nil, notFound(err)
	}
	return &m, nil
}

func (c communities) Hold(ctx context.Context, name string, community []byte, until, now int64) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_communities WHERE name = ?", name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return store.ErrExists
	}
	var held []byte
	var was int64
	switch err := tx.QueryRowContext(ctx, "SELECT community, until FROM cm_holds WHERE name = ?", name).Scan(&held, &was); {
	case err == nil:
		if was > now && !bytes.Equal(held, community) {
			return store.ErrExists
		}
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cm_holds (name, community, until) VALUES (?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET community = excluded.community, until = excluded.until`, name, community, until); err != nil {
		return err
	}
	return tx.Commit()
}

func (c communities) Members(ctx context.Context, name string) ([]store.CommunityMember, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT id, home, since FROM cm_members WHERE name = ? ORDER BY id", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CommunityMember
	for rows.Next() {
		var m store.CommunityMember
		if err := rows.Scan(&m.ID, &m.Home, &m.Since); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (c communities) Listed(ctx context.Context, name, id string) (bool, error) {
	var n int
	err := c.rdb.QueryRowContext(ctx, "SELECT count(*) FROM cm_listed WHERE name = ? AND id = ?", name, id).Scan(&n)
	return n > 0, err
}

func (c communities) MemberCount(ctx context.Context, name string) (int, error) {
	var n int
	err := c.rdb.QueryRowContext(ctx, "SELECT count(*) FROM cm_members WHERE name = ?", name).Scan(&n)
	return n, err
}

// ---- sessions ----

func (c communities) CreateToken(ctx context.Context, name string, hash []byte, id, home string, dev []byte, expires int64) error {
	_, err := c.db.ExecContext(ctx, "INSERT INTO cm_tokens (hash, name, id, home, device, expires) VALUES (?, ?, ?, ?, ?, ?)", hash, name, id, home, dev, expires)
	return err
}

// LookupToken extends the token's expiry as homeserver tokens do: written only when it's
// under 30 days away, then a minute past, so a burst of requests costs one write.
func (c communities) LookupToken(ctx context.Context, name string, hash []byte, now int64) (string, string, []byte, error) {
	var id, home string
	var dev []byte
	var exp int64
	err := c.rdb.QueryRowContext(ctx, "SELECT id, home, device, expires FROM cm_tokens WHERE hash = ? AND name = ?", hash, name).Scan(&id, &home, &dev, &exp)
	if err != nil {
		return "", "", nil, notFound(err)
	}
	if exp <= now {
		return "", "", nil, store.ErrNotFound
	}
	const ttl = 30 * 24 * 3600
	if exp < now+ttl {
		if _, err := c.db.ExecContext(ctx, "UPDATE cm_tokens SET expires = ? WHERE hash = ?", now+ttl+60, hash); err != nil {
			return "", "", nil, err
		}
	}
	return id, home, dev, nil
}

func (c communities) RevokeToken(ctx context.Context, hash []byte) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM cm_tokens WHERE hash = ?", hash)
	return err
}

func (c communities) RevokeDevice(ctx context.Context, name, id string, dev []byte) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM cm_tokens WHERE name = ? AND id = ? AND device = ?", name, id, dev)
	return err
}

func (c communities) SessionIDs(ctx context.Context, name string, now int64) ([]string, error) {
	return strings1(c.rdb.QueryContext(ctx, "SELECT DISTINCT id FROM cm_tokens WHERE name = ? AND expires > ? ORDER BY id", name, now))
}

func (c communities) SessionDevices(ctx context.Context, name, id string, now int64) ([][]byte, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT DISTINCT device FROM cm_tokens WHERE name = ? AND id = ? AND expires > ?", name, id, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var d []byte
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func strings1(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---- key packages ----

func (c communities) UploadKPs(ctx context.Context, name, id string, dev []byte, kps []store.CKeyPackage, lastResort *store.CKeyPackage, replace bool) (int, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if replace {
		if _, err := tx.ExecContext(ctx, "DELETE FROM cm_kps WHERE name = ? AND id = ? AND device = ? AND last_resort = 0", name, id, dev); err != nil {
			return 0, err
		}
	}
	for _, k := range kps {
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_kps (name, id, device, data, binding, last_resort) VALUES (?, ?, ?, ?, ?, 0)", name, id, dev, k.Data, k.Binding); err != nil {
			return 0, err
		}
	}
	if lastResort != nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM cm_kps WHERE name = ? AND id = ? AND device = ? AND last_resort = 1", name, id, dev); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_kps (name, id, device, data, binding, last_resort) VALUES (?, ?, ?, ?, ?, 1)", name, id, dev, lastResort.Data, lastResort.Binding); err != nil {
			return 0, err
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_kps WHERE name = ? AND id = ? AND device = ? AND last_resort = 0", name, id, dev).Scan(&n); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func (c communities) CountKPs(ctx context.Context, name, id string, dev []byte) (int, bool, error) {
	var n, lr int
	err := c.rdb.QueryRowContext(ctx, "SELECT count(*) FILTER (WHERE last_resort = 0), count(*) FILTER (WHERE last_resort = 1) FROM cm_kps WHERE name = ? AND id = ? AND device = ?", name, id, dev).Scan(&n, &lr)
	return n, lr > 0, err
}

func (c communities) ClaimKPs(ctx context.Context, name, id string, devs [][]byte) ([]store.CKeyPackage, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var out []store.CKeyPackage
	for _, d := range devs {
		k := store.CKeyPackage{Device: d}
		var n int64
		err := tx.QueryRowContext(ctx, "SELECT n, data, binding, last_resort FROM cm_kps WHERE name = ? AND id = ? AND device = ? ORDER BY last_resort, n LIMIT 1", name, id, d).Scan(&n, &k.Data, &k.Binding, &k.LastResort)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !k.LastResort {
			if _, err := tx.ExecContext(ctx, "DELETE FROM cm_kps WHERE n = ?", n); err != nil {
				return nil, err
			}
		}
		out = append(out, k)
	}
	return out, tx.Commit()
}

func (c communities) PruneKPs(ctx context.Context, name string, before int64) (int, error) {
	res, err := c.db.ExecContext(ctx, `DELETE FROM cm_kps WHERE name = ?1
		AND id NOT IN (SELECT id FROM cm_members WHERE name = ?1)
		AND id NOT IN (SELECT id FROM cm_tokens WHERE name = ?1 AND expires > ?2)`, name, before+30*24*3600)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ---- groups ----

func (c communities) RegisterGroup(ctx context.Context, g store.CGroup) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if known, err := groupKnown(ctx, tx, g.Group); err != nil {
		return err
	} else if known {
		return store.ErrConflict
	}
	if err := insertGroup(ctx, tx, g); err != nil {
		return err
	}
	if g.See == "" {
		res, err := tx.ExecContext(ctx, "UPDATE cm_communities SET grp = ? WHERE name = ? AND grp IS NULL", g.Group, g.Name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrConflict
		}
	}
	return tx.Commit()
}

// groupCols are a group's columns, with the group that replaced it, if any (SPEC §16.5).
const groupCols = "grp, name, see, epoch, key, awaiting, info, tree, tree_size, (SELECT new_grp FROM cm_replaced r WHERE r.grp = cm_groups.grp)"

func scanGroup(sc interface{ Scan(...any) error }) (*store.CGroup, error) {
	var g store.CGroup
	if err := sc.Scan(&g.Group, &g.Name, &g.See, &g.Epoch, &g.Key, &g.Awaiting, &g.Info, &g.Tree, &g.TreeSize, &g.Replaced); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c communities) Group(ctx context.Context, group []byte) (*store.CGroup, error) {
	g, err := scanGroup(c.db.QueryRowContext(ctx, "SELECT "+groupCols+" FROM cm_groups WHERE grp = ?", group))
	return g, notFound(err)
}

func (c communities) Groups(ctx context.Context, name string) ([]store.CGroup, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT "+groupCols+" FROM cm_groups WHERE name = ?", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CGroup
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// replacedBy is the group that replaced group, or nil.
func replacedBy(ctx context.Context, tx *sql.Tx, group []byte) ([]byte, error) {
	var by []byte
	err := tx.QueryRowContext(ctx, "SELECT new_grp FROM cm_replaced WHERE grp = ?", group).Scan(&by)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return by, err
}

func (c communities) ReplaceGroup(ctx context.Context, g store.CGroup, old []byte) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if known, err := groupKnown(ctx, tx, g.Group); err != nil {
		return err
	} else if known {
		return store.ErrConflict
	}
	var name, see string
	if err := tx.QueryRowContext(ctx, "SELECT name, see FROM cm_groups WHERE grp = ?", old).Scan(&name, &see); err != nil {
		return notFound(err)
	}
	if name != g.Name || see != g.See {
		return store.ErrNotFound
	}
	if by, err := replacedBy(ctx, tx, old); err != nil {
		return err
	} else if by != nil {
		return store.ErrReplaced
	}
	if err := insertGroup(ctx, tx, g); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_replaced (grp, name, new_grp) VALUES (?, ?, ?)", old, g.Name, g.Group); err != nil {
		return err
	}
	if g.See == "" {
		res, err := tx.ExecContext(ctx, "UPDATE cm_communities SET grp = ? WHERE name = ? AND grp = ?", g.Group, g.Name, old)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
	}
	return tx.Commit()
}

const treeKeep = 30 * 24 * 3600

func (c communities) Accept(ctx context.Context, a store.CAccept) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var name string
	var epoch uint64
	var awaiting bool
	if err := tx.QueryRowContext(ctx, "SELECT name, epoch, awaiting FROM cm_groups WHERE grp = ?", a.Group).Scan(&name, &epoch, &awaiting); err != nil {
		return notFound(err)
	}
	// A replaced group takes no more commits (SPEC §16.5), checked here so a commit can't
	// slip in beside the replacement.
	if by, err := replacedBy(ctx, tx, a.Group); err != nil {
		return err
	} else if by != nil {
		return store.ErrReplaced
	}
	if epoch != a.Epoch || awaiting {
		return store.ErrConflict
	}
	// An undone commit can't come back (SPEC §16.5).
	sum := sha256.Sum256(a.Commit.Data)
	var undone int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_undos WHERE grp = ? AND epoch = ? AND hash = ?", a.Group, a.Epoch, sum[:]).Scan(&undone); err != nil {
		return err
	}
	if undone > 0 {
		return store.ErrGone
	}
	if j := a.Join; j != nil {
		var member int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_members WHERE name = ? AND id = ?", name, j.ID).Scan(&member); err != nil {
			return err
		}
		if member == 0 {
			var n int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_members WHERE name = ?", name).Scan(&n); err != nil {
				return err
			}
			if j.Cap > 0 && n >= j.Cap {
				return store.ErrOverQuota
			}
		}
		var used int
		err := tx.QueryRowContext(ctx, "SELECT used FROM cm_code_uses WHERE name = ? AND code = ?", name, j.Code).Scan(&used)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if j.Limit > 0 && used >= j.Limit {
			return store.ErrOverQuota
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_code_uses (name, code, used) VALUES (?, ?, 1) ON CONFLICT (name, code) DO UPDATE SET used = used + 1", name, j.Code); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO cm_members (name, id, home, since) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", name, j.ID, j.Home, a.Commit.TS); err != nil {
			return err
		}
		if err := register(ctx, tx, a.Group, j.ID, j.Dev); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_commits (grp, epoch, data, receipt, request, proof, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
		a.Group, a.Epoch, a.Commit.Data, a.Commit.Receipt, a.Commit.Request, a.Commit.Proof, a.Commit.TS); err != nil {
		return err
	}
	// The epoch's state before the commit, for an undo (SPEC §16.5).
	if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO cm_epochs (grp, epoch, key, info, tree, tree_size, ts) SELECT grp, epoch, key, info, tree, tree_size, ? FROM cm_groups WHERE grp = ?",
		a.Commit.TS, a.Group); err != nil {
		return err
	}
	// A commit without a GroupInfo clears the old one: the old epoch's GroupInfo next to
	// the new epoch number is a pair a joiner would have to refuse (SPEC §16.6).
	if _, err := tx.ExecContext(ctx, "UPDATE cm_groups SET epoch = ?, key = ?, awaiting = ?, info = ?, tree = ?, tree_size = ? WHERE grp = ?",
		a.Epoch+1, a.Key, a.Awaiting, a.Info, a.Tree, a.TreeSize, a.Group); err != nil {
		return err
	}
	if a.Tree != nil {
		if _, err := tx.ExecContext(ctx, "INSERT OR REPLACE INTO cm_tree_uses (grp, epoch, name, hash, keep) VALUES (?, ?, ?, ?, ?)", a.Group, a.Epoch+1, name, a.Tree, a.Commit.TS+treeKeep); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c communities) SetKey(ctx context.Context, group []byte, epoch uint64, reg, next []byte) error {
	res, err := c.db.ExecContext(ctx, "UPDATE cm_groups SET key = ?, awaiting = 0 WHERE grp = ? AND epoch = ? AND awaiting = 1 AND key = ?", next, group, epoch, reg)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrConflict
	}
	return nil
}

func (c communities) Commits(ctx context.Context, group []byte, from uint64) ([]store.CCommit, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT epoch, data, receipt, request, proof, ts FROM cm_commits WHERE grp = ? AND epoch >= ? ORDER BY epoch", group, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CCommit
	for rows.Next() {
		var cm store.CCommit
		if err := rows.Scan(&cm.Epoch, &cm.Data, &cm.Receipt, &cm.Request, &cm.Proof, &cm.TS); err != nil {
			return nil, err
		}
		out = append(out, cm)
	}
	return out, rows.Err()
}

func (c communities) Undo(ctx context.Context, u store.CUndo) (store.CItem, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return store.CItem{}, err
	}
	defer tx.Rollback()
	var name string
	var epoch uint64
	if err := tx.QueryRowContext(ctx, "SELECT name, epoch FROM cm_groups WHERE grp = ?", u.Group).Scan(&name, &epoch); err != nil {
		return store.CItem{}, notFound(err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_undos WHERE grp = ? AND epoch = ? AND hash = ?", u.Group, u.Epoch, u.Hash).Scan(&n); err != nil {
		return store.CItem{}, err
	}
	if n > 0 {
		return store.CItem{}, store.ErrExists // the same undo again
	}
	if epoch != u.Epoch+1 {
		if epoch > u.Epoch+1 {
			return store.CItem{}, store.ErrConflict
		}
		return store.CItem{}, store.ErrNotFound
	}
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT data FROM cm_commits WHERE grp = ? AND epoch = ?", u.Group, u.Epoch).Scan(&data); err != nil {
		return store.CItem{}, notFound(err)
	}
	if sum := sha256.Sum256(data); !bytes.Equal(sum[:], u.Hash) {
		return store.CItem{}, store.ErrNotFound
	}
	res, err := tx.ExecContext(ctx, "UPDATE cm_groups SET epoch = e.epoch, key = e.key, awaiting = 0, info = e.info, tree = e.tree, tree_size = e.tree_size FROM (SELECT epoch, key, info, tree, tree_size FROM cm_epochs WHERE grp = ? AND epoch = ?) AS e WHERE cm_groups.grp = ?", u.Group, u.Epoch, u.Group)
	if err != nil {
		return store.CItem{}, err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return store.CItem{}, store.ErrGone // accepted before this server kept epoch states
	}
	for _, q := range []string{"DELETE FROM cm_commits WHERE grp = ? AND epoch = ?", "DELETE FROM cm_tree_uses WHERE grp = ? AND epoch = ? + 1"} {
		if _, err := tx.ExecContext(ctx, q, u.Group, u.Epoch); err != nil {
			return store.CItem{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_undos (grp, epoch, hash, undo, ts) VALUES (?, ?, ?, ?, ?)", u.Group, u.Epoch, u.Hash, u.Undo, u.Notice.TS); err != nil {
		return store.CItem{}, err
	}
	// The notice goes into the inbox in the same step, so it's ahead of the next commit.
	it := u.Notice
	r, err := tx.ExecContext(ctx, "INSERT INTO cm_inbox (name, ts, grp, notice) VALUES (?, ?, ?, ?)", name, it.TS, u.Group, it.Notice)
	if err != nil {
		return store.CItem{}, err
	}
	if it.Cursor, err = r.LastInsertId(); err != nil {
		return store.CItem{}, err
	}
	it.Group = u.Group
	return it, tx.Commit()
}

func (c communities) Undos(ctx context.Context, group []byte, from uint64) ([][]byte, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT undo FROM cm_undos WHERE grp = ? AND epoch >= ? ORDER BY epoch, ts", group, from)
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

// register records a device's registration, from the newest cursor on: it gets the
// group's items stored after this.
func register(ctx context.Context, tx *sql.Tx, group []byte, id string, dev []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO cm_regs (grp, id, device, since) VALUES (?, ?, ?, (SELECT COALESCE(MAX(cursor), 0) FROM cm_inbox))
		ON CONFLICT DO NOTHING`, group, id, dev)
	return err
}

func (c communities) Register(ctx context.Context, name string, group []byte, id string, dev []byte) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := register(ctx, tx, group, id, dev); err != nil {
		return err
	}
	return tx.Commit()
}

func (c communities) Unregister(ctx context.Context, group []byte, id string, dev []byte) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM cm_regs WHERE grp = ? AND id = ? AND device = ?", group, id, dev)
	return err
}

func (c communities) UnregisterIdentity(ctx context.Context, group []byte, id string) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM cm_regs WHERE grp = ? AND id = ?", group, id)
	return err
}

func (c communities) Registered(ctx context.Context, group []byte, id string, dev []byte) (bool, error) {
	var n int
	err := c.db.QueryRowContext(ctx, "SELECT count(*) FROM cm_regs WHERE grp = ? AND id = ? AND device = ?", group, id, dev).Scan(&n)
	return n > 0, err
}

func (c communities) Regs(ctx context.Context, group []byte) ([]store.CReg, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT id, device FROM cm_regs WHERE grp = ? ORDER BY id", group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CReg
	for rows.Next() {
		var r store.CReg
		if err := rows.Scan(&r.ID, &r.Dev); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- ratchet trees ----

func (c communities) treePath(name string, hash []byte) string {
	return filepath.Join(c.cdir(name, "trees"), hex.EncodeToString(hash))
}

func (c communities) PutTree(ctx context.Context, name string, r io.Reader, max int64, uploader string, now int64) ([]byte, int64, error) {
	dir := c.cdir(name, "trees")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, 0, err
	}
	tmp, err := os.CreateTemp(dir, "upload-*")
	if err != nil {
		return nil, 0, err
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
		return nil, 0, err
	}
	if n > max {
		return nil, 0, store.ErrOverQuota
	}
	sum := h.Sum(nil)
	if err := os.Rename(tmp.Name(), c.treePath(name, sum)); err != nil {
		return nil, 0, err
	}
	_, err = c.db.ExecContext(ctx, `INSERT INTO cm_trees (name, hash, size, uploaded, uploader) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (name, hash) DO UPDATE SET uploaded = excluded.uploaded`, name, sum, n, now, uploader)
	return sum, n, err
}

func (c communities) TreeSize(ctx context.Context, name string, hash []byte) (int64, error) {
	var n int64
	err := c.db.QueryRowContext(ctx, "SELECT size FROM cm_trees WHERE name = ? AND hash = ?", name, hash).Scan(&n)
	return n, notFound(err)
}

func (c communities) UseTree(ctx context.Context, name string, hash, group []byte, epoch uint64, keep int64) error {
	_, err := c.db.ExecContext(ctx, `INSERT INTO cm_tree_uses (grp, epoch, name, hash, keep) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (grp, epoch) DO UPDATE SET keep = MAX(keep, excluded.keep)`, group, epoch, name, hash, keep)
	return err
}

func (c communities) TreeFor(ctx context.Context, group []byte, epoch uint64) (io.ReadCloser, int64, error) {
	var name string
	var hash []byte
	var size int64
	err := c.db.QueryRowContext(ctx, `SELECT u.name, u.hash, t.size FROM cm_tree_uses u JOIN cm_trees t ON t.name = u.name AND t.hash = u.hash
		WHERE u.grp = ? AND u.epoch = ?`, group, epoch).Scan(&name, &hash, &size)
	if err != nil {
		return nil, 0, notFound(err)
	}
	f, err := os.Open(c.treePath(name, hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, store.ErrNotFound
	}
	return f, size, err
}

func (c communities) PruneTrees(ctx context.Context, unusedBefore, now int64) (int, error) {
	// A group's current epoch keeps its tree however old it is.
	if _, err := c.db.ExecContext(ctx, `DELETE FROM cm_tree_uses WHERE keep < ?
		AND NOT EXISTS (SELECT 1 FROM cm_groups g WHERE g.grp = cm_tree_uses.grp AND g.epoch = cm_tree_uses.epoch)`, now); err != nil {
		return 0, err
	}
	rows, err := c.db.QueryContext(ctx, `SELECT name, hash FROM cm_trees t WHERE uploaded < ?
		AND NOT EXISTS (SELECT 1 FROM cm_tree_uses u WHERE u.name = t.name AND u.hash = t.hash)
		AND NOT EXISTS (SELECT 1 FROM cm_groups g WHERE g.name = t.name AND g.tree = t.hash)`, unusedBefore)
	if err != nil {
		return 0, err
	}
	type tree struct {
		name string
		hash []byte
	}
	var gone []tree
	for rows.Next() {
		var t tree
		if err := rows.Scan(&t.name, &t.hash); err != nil {
			rows.Close()
			return 0, err
		}
		gone = append(gone, t)
	}
	rows.Close()
	for _, t := range gone {
		if _, err := c.db.ExecContext(ctx, "DELETE FROM cm_trees WHERE name = ? AND hash = ?", t.name, t.hash); err != nil {
			return 0, err
		}
		os.Remove(c.treePath(t.name, t.hash))
	}
	return len(gone), nil
}

// ---- the inbox ----

func (c communities) Put(ctx context.Context, name string, items []store.CItem) ([]store.CItem, error) {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := make([]store.CItem, len(items))
	for i, it := range items {
		if it.Numbered {
			var last uint64
			err := tx.QueryRowContext(ctx, "SELECT last FROM cm_channels WHERE name = ? AND channel = ?", name, it.Channel).Scan(&last)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			it.Seq = last + 1
			if _, err := tx.ExecContext(ctx, "INSERT INTO cm_channels (name, channel, last) VALUES (?, ?, ?) ON CONFLICT (name, channel) DO UPDATE SET last = excluded.last", name, it.Channel, it.Seq); err != nil {
				return nil, err
			}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO cm_inbox (name, ts, grp, from_id, from_dev, to_id, to_dev, members, channel, seq, delivery, notice)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			name, it.TS, nilIfEmpty(it.Group), it.FromID, nilIfEmpty(it.FromDev), it.ToID, nilIfEmpty(it.ToDev), it.Members, it.Channel, it.Seq, it.Delivery, it.Notice)
		if err != nil {
			return nil, err
		}
		if it.Cursor, err = res.LastInsertId(); err != nil {
			return nil, err
		}
		out[i] = it
	}
	return out, tx.Commit()
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

const itemCols = "cursor, ts, grp, from_id, from_dev, to_id, to_dev, members, channel, seq, deleted, delivery, notice"

func scanItems(rows *sql.Rows, err error) ([]store.CItem, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CItem
	for rows.Next() {
		var it store.CItem
		if err := rows.Scan(&it.Cursor, &it.TS, &it.Group, &it.FromID, &it.FromDev, &it.ToID, &it.ToDev, &it.Members, &it.Channel, &it.Seq, &it.Deleted, &it.Delivery, &it.Notice); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (c communities) List(ctx context.Context, name, id string, dev []byte, after int64, limit int) ([]store.CItem, error) {
	return scanItems(c.rdb.QueryContext(ctx, `SELECT `+itemCols+` FROM cm_inbox i WHERE i.name = ?1 AND i.cursor > ?2 AND (
		(i.grp IS NOT NULL AND NOT (i.from_id = ?3 AND i.from_dev = ?4)
			AND EXISTS (SELECT 1 FROM cm_regs r WHERE r.grp = i.grp AND r.id = ?3 AND r.device = ?4 AND r.since < i.cursor))
		OR (i.to_id = ?3 AND (i.to_dev IS NULL OR i.to_dev = ?4))
		OR (i.members = 1 AND EXISTS (SELECT 1 FROM cm_members m WHERE m.name = i.name AND m.id = ?3))
	) ORDER BY i.cursor LIMIT ?5`, name, after, id, dev, limit))
}

func (c communities) Pruned(ctx context.Context, name string) (int64, error) {
	var n int64
	err := c.rdb.QueryRowContext(ctx, "SELECT pruned FROM cm_communities WHERE name = ?", name).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

func (c communities) Ack(ctx context.Context, name, id string, dev []byte, upto int64) error {
	_, err := c.db.ExecContext(ctx, `INSERT INTO cm_acks (name, id, device, upto) VALUES (?, ?, ?, ?)
		ON CONFLICT (name, id, device) DO UPDATE SET upto = MAX(upto, excluded.upto)`, name, id, dev, upto)
	return err
}

func (c communities) ChannelItems(ctx context.Context, name string, channel, from uint64, limit int) ([]store.CItem, error) {
	return scanItems(c.rdb.QueryContext(ctx, "SELECT "+itemCols+" FROM cm_inbox WHERE name = ? AND channel = ? AND seq >= ? AND seq > 0 ORDER BY seq LIMIT ?", name, channel, from, limit))
}

func (c communities) ChannelItem(ctx context.Context, name string, channel, seq uint64) (*store.CItem, error) {
	items, err := scanItems(c.db.QueryContext(ctx, "SELECT "+itemCols+" FROM cm_inbox WHERE name = ? AND channel = ? AND seq = ?", name, channel, seq))
	if err != nil {
		return nil, err
	}
	if len(items) == 0 || seq == 0 {
		return nil, store.ErrNotFound
	}
	return &items[0], nil
}

func (c communities) ChannelHead(ctx context.Context, name string, channel uint64) (uint64, error) {
	var last uint64
	err := c.db.QueryRowContext(ctx, "SELECT last FROM cm_channels WHERE name = ? AND channel = ?", name, channel).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return last, err
}

func (c communities) ChannelHeads(ctx context.Context, name string) (map[uint64]uint64, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT channel, last FROM cm_channels WHERE name = ?", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint64]uint64{}
	for rows.Next() {
		var ch, last uint64
		if err := rows.Scan(&ch, &last); err != nil {
			return nil, err
		}
		out[ch] = last
	}
	return out, rows.Err()
}

func (c communities) DeleteItem(ctx context.Context, name string, channel, seq, by uint64, now int64) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE cm_inbox SET deleted = ?, delivery = NULL WHERE name = ? AND channel = ? AND seq = ? AND deleted = 0", by, name, channel, seq); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_deletes (name, channel, seq, ts) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", name, channel, seq, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (c communities) Prune(ctx context.Context, before int64) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE cm_communities SET pruned = MAX(pruned, COALESCE((SELECT MAX(cursor) FROM cm_inbox i WHERE i.name = cm_communities.name AND i.ts < ?), 0))`, before); err != nil {
		return err
	}
	for _, q := range []string{
		"DELETE FROM cm_inbox WHERE ts < ?",
		"DELETE FROM cm_commits WHERE ts < ?",
		"DELETE FROM cm_epochs WHERE ts < ?",
		"DELETE FROM cm_undos WHERE ts < ?",
		"DELETE FROM cm_sent WHERE ts < ?",
	} {
		if _, err := tx.ExecContext(ctx, q, before); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c communities) SentResult(ctx context.Context, name, sender string, id []byte) ([]byte, error) {
	var b []byte
	err := c.db.QueryRowContext(ctx, "SELECT result FROM cm_sent WHERE name = ? AND sender = ? AND did = ?", name, sender, id).Scan(&b)
	return b, notFound(err)
}

func (c communities) PutSentResult(ctx context.Context, name, sender string, id, result []byte, now int64) error {
	_, err := c.db.ExecContext(ctx, "INSERT INTO cm_sent (name, sender, did, result, ts) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING", name, sender, id, result, now)
	return err
}

// ---- codes ----

func (c communities) CodeUses(ctx context.Context, name string, code []byte) (int, error) {
	var n int
	err := c.db.QueryRowContext(ctx, "SELECT used FROM cm_code_uses WHERE name = ? AND code = ?", name, code).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// ---- join requests ----

func (c communities) PutRequest(ctx context.Context, name string, r store.CRequest) error {
	_, err := c.db.ExecContext(ctx, "INSERT INTO cm_requests (name, id, home, ts) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", name, r.ID, r.Home, r.TS)
	return err
}

func (c communities) Request(ctx context.Context, name, id string) (*store.CRequest, error) {
	r := store.CRequest{ID: id}
	err := c.db.QueryRowContext(ctx, "SELECT home, ts, approver, approved FROM cm_requests WHERE name = ? AND id = ?", name, id).Scan(&r.Home, &r.TS, &r.Approver, &r.ApprovedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &r, nil
}

func (c communities) Requests(ctx context.Context, name string, after string, limit int) ([]store.CRequest, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT id, home, ts, approver, approved FROM cm_requests WHERE name = ? AND id > ? ORDER BY id LIMIT ?", name, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CRequest
	for rows.Next() {
		var r store.CRequest
		if err := rows.Scan(&r.ID, &r.Home, &r.TS, &r.Approver, &r.ApprovedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c communities) CountRequests(ctx context.Context, name string) (int, error) {
	var n int
	err := c.rdb.QueryRowContext(ctx, "SELECT count(*) FROM cm_requests WHERE name = ?", name).Scan(&n)
	return n, err
}

func (c communities) HoldRequest(ctx context.Context, name, id, approver string, now, since int64) error {
	res, err := c.db.ExecContext(ctx, `UPDATE cm_requests SET approver = ?3, approved = ?4 WHERE name = ?1 AND id = ?2
		AND (approver = '' OR approver = ?3 OR approved <= ?5)`, name, id, approver, now, since)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := c.Request(ctx, name, id); err != nil {
			return err
		}
		return store.ErrConflict
	}
	return nil
}

func (c communities) DeleteRequest(ctx context.Context, name, id string) error {
	res, err := c.db.ExecContext(ctx, "DELETE FROM cm_requests WHERE name = ? AND id = ?", name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---- history segments ----

func (c communities) PutSegment(ctx context.Context, name string, s store.CSegment, replace bool) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var end uint64
	var ct []byte
	var ts int64
	err = tx.QueryRowContext(ctx, "SELECT s_end, ct, ts FROM cm_segments WHERE name = ? AND channel = ? AND s_start = ?", name, s.Channel, s.Start).Scan(&end, &ct, &ts)
	switch {
	case err == nil && end == s.End && string(ct) == string(s.CT):
		return nil // a retry
	case err == nil && replace && end == s.End:
		var deleted int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_deletes WHERE name = ? AND channel = ? AND seq BETWEEN ? AND ? AND ts >= ?", name, s.Channel, s.Start, s.End, ts).Scan(&deleted); err != nil {
			return err
		}
		if deleted == 0 {
			return store.ErrConflict
		}
		if _, err := tx.ExecContext(ctx, "UPDATE cm_segments SET ct = ?, ts = ? WHERE name = ? AND channel = ? AND s_start = ?", s.CT, s.TS, name, s.Channel, s.Start); err != nil {
			return err
		}
		return tx.Commit()
	case err == nil:
		return store.ErrConflict
	case !errors.Is(err, sql.ErrNoRows):
		return err
	case replace:
		return store.ErrConflict
	}
	// Segments never overlap: a start at or below a stored segment's end is taken.
	var overlap int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM cm_segments WHERE name = ? AND channel = ? AND s_start <= ? AND s_end >= ?", name, s.Channel, s.End, s.Start).Scan(&overlap); err != nil {
		return err
	}
	if overlap > 0 {
		return store.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cm_segments (name, channel, s_start, s_end, ct, ts) VALUES (?, ?, ?, ?, ?, ?)", name, s.Channel, s.Start, s.End, s.CT, s.TS); err != nil {
		return err
	}
	return tx.Commit()
}

func (c communities) Segments(ctx context.Context, name string, channel uint64, after uint64, limit int) ([]store.CSegment, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT s_start, s_end, length(ct), ts FROM cm_segments WHERE name = ? AND channel = ? AND s_start > ? ORDER BY s_start LIMIT ?", name, channel, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CSegment
	for rows.Next() {
		s := store.CSegment{Channel: channel}
		if err := rows.Scan(&s.Start, &s.End, &s.Size, &s.TS); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (c communities) Segment(ctx context.Context, name string, channel, start uint64) (*store.CSegment, error) {
	s := store.CSegment{Channel: channel, Start: start}
	err := c.rdb.QueryRowContext(ctx, "SELECT s_end, ct, ts FROM cm_segments WHERE name = ? AND channel = ? AND s_start = ?", name, channel, start).Scan(&s.End, &s.CT, &s.TS)
	if err != nil {
		return nil, notFound(err)
	}
	s.Size = int64(len(s.CT))
	return &s, nil
}

func (c communities) DeleteSegments(ctx context.Context, name string, channel uint64) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM cm_segments WHERE name = ? AND channel = ?", name, channel)
	return err
}

func (c communities) SegmentUsage(ctx context.Context, name string) (int64, error) {
	var n sql.NullInt64
	err := c.rdb.QueryRowContext(ctx, "SELECT SUM(length(ct)) FROM cm_segments WHERE name = ?", name).Scan(&n)
	return n.Int64, err
}

func (c communities) DeletedSince(ctx context.Context, name string, channel, start, end uint64, ts int64) (bool, error) {
	var n int
	err := c.rdb.QueryRowContext(ctx, "SELECT count(*) FROM cm_deletes WHERE name = ? AND channel = ? AND seq BETWEEN ? AND ? AND ts >= ?", name, channel, start, end, ts).Scan(&n)
	return n > 0, err
}

// ---- files ----

func (c communities) mediaPath(name string, id []byte) string {
	return filepath.Join(c.cdir(name, "media"), hex.EncodeToString(id))
}

func (c communities) PutMedia(ctx context.Context, name string, m *store.CMedia, r io.Reader, max int64) error {
	dir := c.cdir(name, "media")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "upload-*")
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
	m.Size, m.SHA256 = n, h.Sum(nil)
	if err := os.Rename(tmp.Name(), c.mediaPath(name, m.ID)); err != nil {
		return err
	}
	_, err = c.db.ExecContext(ctx, "INSERT INTO cm_media (name, id, author, size, sha256, created) VALUES (?, ?, ?, ?, ?, ?)", name, m.ID, m.Author, m.Size, m.SHA256, m.Created)
	if err != nil {
		os.Remove(c.mediaPath(name, m.ID))
	}
	return err
}

func (c communities) Media(ctx context.Context, name string, id []byte) (*store.CMedia, error) {
	m := store.CMedia{ID: id}
	var state int
	err := c.rdb.QueryRowContext(ctx, "SELECT author, size, sha256, created, state FROM cm_media WHERE name = ? AND id = ?", name, id).Scan(&m.Author, &m.Size, &m.SHA256, &m.Created, &state)
	if err != nil {
		return nil, notFound(err)
	}
	m.Removed, m.Expired = state == mediaRemoved, state == mediaExpired
	return &m, nil
}

func (c communities) OpenMedia(ctx context.Context, name string, id []byte) (io.ReadCloser, error) {
	f, err := os.Open(c.mediaPath(name, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrNotFound
	}
	return f, err
}

func (c communities) MediaUsage(ctx context.Context, name string) (int64, error) {
	var n sql.NullInt64
	err := c.rdb.QueryRowContext(ctx, "SELECT SUM(size) FROM cm_media WHERE name = ? AND state = 0", name).Scan(&n)
	return n.Int64, err
}

func (c communities) RemoveMedia(ctx context.Context, name string, id []byte) error {
	res, err := c.db.ExecContext(ctx, "UPDATE cm_media SET state = ? WHERE name = ? AND id = ?", mediaRemoved, name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	os.Remove(c.mediaPath(name, id))
	return nil
}

func (c communities) ExpireMedia(ctx context.Context, name string, before int64) (int, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT id FROM cm_media WHERE name = ? AND state = 0 AND created < ?", name, before)
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
		os.Remove(c.mediaPath(name, id))
		if _, err := c.db.ExecContext(ctx, "UPDATE cm_media SET state = ? WHERE name = ? AND id = ?", mediaExpired, name, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// ---- reports ----

func (c communities) AddReport(ctx context.Context, name string, r store.CReport) error {
	_, err := c.db.ExecContext(ctx, "INSERT INTO cm_reports (name, rid, ts, reporter, body, at) VALUES (?, ?, ?, ?, ?, ?)", name, r.ID, r.TS, r.Reporter, r.Body, r.At)
	return err
}

func (c communities) Reports(ctx context.Context, name string, after int64, limit int) ([]store.CReport, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT n, rid, ts, reporter, body, at FROM cm_reports WHERE name = ? AND n > ? ORDER BY n LIMIT ?", name, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CReport
	for rows.Next() {
		var r store.CReport
		if err := rows.Scan(&r.N, &r.ID, &r.TS, &r.Reporter, &r.Body, &r.At); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c communities) CloseReport(ctx context.Context, name string, id []byte) error {
	res, err := c.db.ExecContext(ctx, "DELETE FROM cm_reports WHERE name = ? AND rid = ?", name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---- icons (SPEC §16.2.3) ----

func (c communities) PutIcon(ctx context.Context, name string, hash []byte, mime string, data []byte, now int64) error {
	_, err := c.db.ExecContext(ctx, `INSERT INTO cm_icons (name, hash, mime, data, uploaded) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (name, hash) DO UPDATE SET mime = excluded.mime, uploaded = excluded.uploaded`, name, hash, mime, data, now)
	return err
}

func (c communities) Icon(ctx context.Context, name string, hash []byte) (string, []byte, error) {
	var mime string
	var data []byte
	err := c.rdb.QueryRowContext(ctx, "SELECT mime, data FROM cm_icons WHERE name = ? AND hash = ?", name, hash).Scan(&mime, &data)
	return mime, data, notFound(err)
}

func (c communities) PruneIcons(ctx context.Context, name string, keep []byte, before int64) (int, error) {
	if keep == nil {
		keep = []byte{} // no hash is empty
	}
	res, err := c.db.ExecContext(ctx, "DELETE FROM cm_icons WHERE name = ? AND uploaded < ? AND hash != ?", name, before, keep)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ---- read positions (SPEC §16.4) ----

func (c communities) SetRead(ctx context.Context, name, id string, channel, seq uint64) error {
	_, err := c.db.ExecContext(ctx, `INSERT INTO cm_reads (name, id, channel, seq) VALUES (?, ?, ?, ?)
		ON CONFLICT (name, id, channel) DO UPDATE SET seq = max(seq, excluded.seq)`, name, id, channel, seq)
	return err
}

func (c communities) Reads(ctx context.Context, name, id string) ([]store.CRead, error) {
	rows, err := c.rdb.QueryContext(ctx, "SELECT channel, seq FROM cm_reads WHERE name = ? AND id = ? ORDER BY channel", name, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.CRead
	for rows.Next() {
		var r store.CRead
		if err := rows.Scan(&r.Channel, &r.Seq); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (c communities) DeleteChannelReads(ctx context.Context, name string, channel uint64) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM cm_reads WHERE name = ? AND channel = ?", name, channel)
	return err
}
