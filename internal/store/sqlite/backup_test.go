package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

func TestBackupToWhileOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "rerouted-v1.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Reports().Add(ctx, store.Report{Received: 1, Origin: "a.test", Reporter: "r", Reported: "x", Body: []byte("hi")}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("INSERT INTO chains (id, seq, entry, wire) VALUES ('b', 0, x'02', 2), ('a', 0, x'00', 1), ('a', 1, x'01', 1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("INSERT INTO cm_communities (name, id, created) VALUES ('c.test', x'00', 5)"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("INSERT INTO cm_members (name, id, home, since) VALUES ('c.test', 'a', 'h.test', 5), ('c.test', 'b', 'h.test', 6)"); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "copy.db")
	if err := st.BackupTo(out); err != nil {
		t.Fatal(err)
	}
	if err := st.BackupTo(out); err == nil {
		t.Fatal("BackupTo overwrote an existing file")
	}

	// The backup command's way: a read-only Store beside the running server's.
	ro, err := OpenReadOnly(filepath.Join(dir, "rerouted-v1.db"))
	if err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(t.TempDir(), "copy2.db")
	if err := ro.BackupTo(out2); err != nil {
		t.Fatal("read-only BackupTo:", err)
	}
	ro.Close()

	cp, err := OpenReadOnly(out2)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if v, err := cp.SchemaVersion(); err != nil || v != SchemaVersion {
		t.Fatalf("schema %d (%v), want %d", v, err, SchemaVersion)
	}
	rs, err := cp.Reports().List(ctx, 10)
	if err != nil || len(rs) != 1 || string(rs[0].Body) != "hi" {
		t.Fatalf("reports in the copy: %v %v", rs, err)
	}
	chains, err := cp.LocalChains(ctx)
	if err != nil || len(chains) != 2 || chains[0].ID != "a" || len(chains[0].Entries) != 2 || chains[1].Wire != 2 {
		t.Fatalf("LocalChains = %+v, %v", chains, err)
	}
	cs, err := cp.CommunityCounts(ctx)
	if err != nil || len(cs) != 1 || cs[0].Members != 2 || cs[0].Created != 5 {
		t.Fatalf("CommunityCounts = %+v, %v", cs, err)
	}
	if err := cp.Reports().Add(ctx, store.Report{Body: []byte("no")}); err == nil {
		t.Fatal("a read-only store accepted a write")
	}
}

func TestOpenReadOnlyNeverCreates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.db")
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("opened a database that doesn't exist")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("OpenReadOnly created the file")
	}
}
