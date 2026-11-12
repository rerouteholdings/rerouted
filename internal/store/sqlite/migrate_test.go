package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// A version 1 database gains the hub's awaiting column, keeps its data.
func TestMigrateV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerouted-v1.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE hub (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL)",
		"INSERT INTO hub (grp, epoch, key) VALUES (x'01', 3, x'02')",
		"PRAGMA user_version = 1",
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
	g, err := st.Hub().Group(context.Background(), []byte{1})
	if err != nil || g.Epoch != 3 || g.Awaiting {
		t.Fatalf("after migration: %+v %v", g, err)
	}
	if err := st.Hub().Accept(context.Background(), []byte{1}, 3, []byte{9}, true, store.Commit{Epoch: 3, Data: []byte{7}}); err != nil {
		t.Fatal(err)
	}
	if g, _ := st.Hub().Group(context.Background(), []byte{1}); !g.Awaiting {
		t.Fatal("awaiting wasn't stored")
	}
}

// A version 2 database gains commit timestamps and
// the new tables, and keeps its commits.
func TestMigrateV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerouted-v1.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE hub (grp BLOB PRIMARY KEY, epoch INTEGER NOT NULL, key BLOB NOT NULL, awaiting INTEGER NOT NULL DEFAULT 0)",
		"CREATE TABLE commits (grp BLOB NOT NULL, epoch INTEGER NOT NULL, data BLOB NOT NULL, receipt BLOB NOT NULL, PRIMARY KEY (grp, epoch))",
		"INSERT INTO hub (grp, epoch, key) VALUES (x'01', 1, x'02')",
		"PRAGMA user_version = 2",
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
	ctx := context.Background()
	if err := st.Profiles().Put(ctx, "tr:x", 1, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := st.Hub().PruneCommits(ctx, 0); err != nil {
		t.Fatal(err)
	}
}
