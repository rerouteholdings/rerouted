package sqlite

import (
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// snapshotBeforeMigration copies the database at path, at schema version old, to
// path.pre-v{old} with VACUUM INTO: a consistent copy, even of a database in WAL mode. Only
// the newest such snapshot is kept. A snapshot already there for the same version is kept as
// it is: it was made before an upgrade that didn't finish, so it's the better copy.
func snapshotBeforeMigration(db *sql.DB, path string, old int) error {
	snap := path + ".pre-v" + strconv.Itoa(old)
	if _, err := os.Stat(snap); err == nil {
		slog.Info("database upgrade: keeping the snapshot from an earlier attempt", "snapshot", snap)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		tmp := snap + ".tmp"
		os.Remove(tmp)
		if _, err := db.Exec("VACUUM INTO ?", tmp); err != nil {
			os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, snap); err != nil {
			os.Remove(tmp)
			return err
		}
		os.Chmod(snap, 0o600)
		slog.Info("database upgrade: saved a copy of the database before upgrading it", "snapshot", snap, "from", old, "to", SchemaVersion)
	}
	// Keep only this snapshot.
	matches, _ := filepath.Glob(path + ".pre-v*")
	for _, m := range matches {
		if m == snap {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(m, path+".pre-v")); err != nil {
			continue // not one of ours
		}
		if err := os.Remove(m); err == nil {
			slog.Info("database upgrade: removed an older snapshot", "snapshot", m)
		}
	}
	return nil
}
