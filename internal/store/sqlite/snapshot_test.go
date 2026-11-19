package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Upgrading a database first copies it as it was, keeping only the newest copy.
func TestSnapshotBeforeMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rerouted-v1.db")
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
	old := path + ".pre-v3"
	os.WriteFile(old, []byte("an older snapshot"), 0o600)
	other := path + ".pre-vnotes"
	os.WriteFile(other, []byte("not ours"), 0o600)

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	snap := path + ".pre-v6"
	sdb, err := sql.Open("sqlite", "file:"+snap+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	var uv, n int
	if err := sdb.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != 6 {
		t.Fatalf("snapshot user_version %d, %v", uv, err)
	}
	if err := sdb.QueryRow("SELECT COUNT(*) FROM seen").Scan(&n); err != nil || n != 1 {
		t.Fatalf("snapshot rows %d, %v", n, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the older snapshot is still there")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("removed a file that isn't a snapshot")
	}
	// Opening the upgraded database again makes no new snapshot.
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if m, _ := filepath.Glob(path + ".pre-v[0-9]*"); len(m) != 1 {
		t.Fatalf("snapshots: %v", m)
	}
}

// When the copy can't be made, the database isn't upgraded.
func TestSnapshotFailureRefusesMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rerouted-v1.db")
	db, _ := sql.Open("sqlite", "file:"+path)
	for _, q := range []string{schemaV6, "PRAGMA user_version = 6"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	// A directory where the temporary copy would go makes VACUUM INTO fail.
	os.Mkdir(path+".pre-v6.tmp", 0o700)
	os.WriteFile(filepath.Join(path+".pre-v6.tmp", "x"), nil, 0o600)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "wasn't upgraded") {
		t.Fatalf("err = %v", err)
	}
	db, _ = sql.Open("sqlite", "file:"+path)
	defer db.Close()
	var uv int
	if err := db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != 6 {
		t.Fatalf("user_version %d, %v", uv, err)
	}
}

func TestNewerDatabaseMessage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerouted-v1.db")
	db, _ := sql.Open("sqlite", "file:"+path)
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+3)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, err := Open(path)
	if err == nil {
		t.Fatal("opened a newer database")
	}
	for _, want := range []string{
		fmt.Sprintf("schema version %d", SchemaVersion+3),
		fmt.Sprintf("supports up to %d", SchemaVersion),
		"Install the newer rerouted again",
		"rerouted-v1.db.pre-v* snapshot",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
}
