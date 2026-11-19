package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
)

// BackupTo writes a consistent copy of the database to path with VACUUM INTO. It's safe
// while the server runs: the copy is one read transaction, so it sees every write committed
// before it started and none after. path must not exist yet, or be an empty file: create
// it first to choose its mode.
func (s *Store) BackupTo(path string) error {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		return errors.New("backup: " + path + " already exists")
	}
	// Through the writer connection: VACUUM INTO counts as a write for query_only, which
	// the readers have. For a read-only Store it's a mode=ro connection, which allows it.
	_, err := s.db.Exec("VACUUM INTO ?", path)
	return err
}

// OpenReadOnly opens an existing database for reading only, for operator commands that
// look but don't change anything (status, accounts, backup). Unlike Open, it never creates
// the database or upgrades its schema, so a newer rerouted binary installed beside a
// running older server can read the database without changing it under that server.
// Writes through the returned Store fail. SchemaVersion says which schema it has.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	// The readers, as in Open.
	rdb, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		db.Close()
		return nil, err
	}
	rdb.SetMaxOpenConns(2)
	return &Store{db: db, rdb: rdb, mediaDir: filepath.Join(filepath.Dir(path), "media"), wire: 1}, nil
}

// SchemaVersion returns the database's schema version (PRAGMA user_version). Below the
// package's SchemaVersion, the running server hasn't upgraded it yet.
func (s *Store) SchemaVersion() (int, error) {
	var v int
	err := s.rdb.QueryRow("PRAGMA user_version").Scan(&v)
	return v, err
}

// LocalChain is one identity whose chain this server stores, with its encoded entries in
// order.
type LocalChain struct {
	ID      string
	Wire    int
	Entries [][]byte
}

// LocalChains returns every chain stored here, of every wire version, for operator
// commands. Identities that moved away keep their chain, ending in the move.
func (s *Store) LocalChains(ctx context.Context) ([]LocalChain, error) {
	rows, err := s.rdb.QueryContext(ctx, "SELECT id, wire, entry FROM chains ORDER BY id, seq")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LocalChain
	for rows.Next() {
		var id string
		var w int
		var entry []byte
		if err := rows.Scan(&id, &w, &entry); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].ID != id {
			out = append(out, LocalChain{ID: id, Wire: w})
		}
		last := &out[len(out)-1]
		last.Entries = append(last.Entries, entry)
	}
	return out, rows.Err()
}

// CommunityCount is a community this server hosts, with its member count.
type CommunityCount struct {
	Name    string
	Created int64
	Members int
}

// CommunityCounts lists the communities created here and how many members each has.
func (s *Store) CommunityCounts(ctx context.Context) ([]CommunityCount, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT c.name, c.created, (SELECT count(*) FROM cm_members m WHERE m.name = c.name)
		FROM cm_communities c ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommunityCount
	for rows.Next() {
		var c CommunityCount
		if err := rows.Scan(&c.Name, &c.Created, &c.Members); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
