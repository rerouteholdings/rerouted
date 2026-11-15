package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// Version 11: community servers' tables are new, and nothing stored before changes.
func TestMigrateV10ToV11(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rerouted.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	v10 := strings.Replace(schemaV9, "handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL)", "handles  (handle TEXT PRIMARY KEY, id TEXT NOT NULL, hold INTEGER NOT NULL DEFAULT 0)", 1)
	for _, q := range []string{v10, "INSERT INTO handles (handle, id) VALUES ('kat.test', 'kat')", "PRAGMA user_version = 10"} {
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
	var uv int
	if err := st.db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil || uv != 11 || SchemaVersion != 11 {
		t.Fatalf("user_version %d (%v)", uv, err)
	}
	if id, err := st.Chains().ByHandle(context.Background(), "kat.test"); err != nil || id != "kat" {
		t.Fatalf("handle after upgrade: %q %v", id, err)
	}
	for _, table := range []string{"cm_communities", "cm_chain", "cm_members", "cm_groups", "cm_commits", "cm_inbox", "cm_segments", "cm_media", "cm_reports", "cm_code_uses", "cm_trees", "cm_icons", "cm_reads"} {
		var n int
		if err := st.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("no table %s after the upgrade", table)
		}
	}
}

func newCommunityStore(t *testing.T) store.Communities {
	t.Helper()
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cs := st.Communities()
	ctx := context.Background()
	g := &store.CGroup{Name: "c.test", Group: []byte("members-group-0123456789abcdefgh"), Key: []byte("k0")}
	if err := cs.Create(ctx, store.Community{Name: "c.test", ID: []byte("id"), Created: 1}, [][]byte{[]byte("e0")}, [][]byte{[]byte("h0")}, store.CommunityMember{ID: "owner", Home: "h.test", Since: 1}, g); err != nil {
		t.Fatal(err)
	}
	return cs
}

// The hub step for a code join counts the code's uses and the member cap in its transaction.
func TestCommunityAcceptJoinLimits(t *testing.T) {
	cs := newCommunityStore(t)
	ctx := context.Background()
	group := []byte("members-group-0123456789abcdefgh")
	join := func(epoch uint64, id string, limit, cap int) error {
		return cs.Accept(ctx, store.CAccept{Group: group, Epoch: epoch, Key: []byte("k"), Commit: store.CCommit{Epoch: epoch, Data: []byte(id), Receipt: []byte("r"), Request: []byte(id), TS: 2},
			Join: &store.CJoin{ID: id, Home: "h.test", Dev: []byte("dev-" + id), Code: []byte("code"), Limit: limit, Cap: cap}})
	}
	if err := join(0, "ravi", 1, 1000); err != nil {
		t.Fatal(err)
	}
	if err := join(1, "mia", 1, 1000); !errors.Is(err, store.ErrOverQuota) {
		t.Fatalf("a second use of a one-use code: %v", err)
	}
	if err := join(1, "mia", 0, 2); !errors.Is(err, store.ErrOverQuota) {
		t.Fatalf("a third member past a cap of 2: %v", err)
	}
	if err := join(0, "lee", 0, 1000); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a join on a stale epoch: %v", err)
	}
	if n, _ := cs.CodeUses(ctx, "c.test", []byte("code")); n != 1 {
		t.Fatalf("uses %d", n)
	}
	if ok, _ := cs.Registered(ctx, group, "ravi", []byte("dev-ravi")); !ok {
		t.Fatal("the joiner's device isn't registered")
	}
	// Group traffic reaches registered devices but the sender's, from their registration on.
	cs.Register(ctx, "c.test", group, "owner", []byte("dev-owner"))
	items, err := cs.Put(ctx, "c.test", []store.CItem{{TS: 3, Group: group, FromID: "ravi", FromDev: []byte("dev-ravi"), Channel: 1, Numbered: true, Delivery: []byte("{}")}})
	if err != nil || items[0].Seq != 1 {
		t.Fatalf("put: %v %+v", err, items)
	}
	if got, _ := cs.List(ctx, "c.test", "owner", []byte("dev-owner"), 0, 10); len(got) != 1 {
		t.Fatalf("owner got %d", len(got))
	}
	if got, _ := cs.List(ctx, "c.test", "ravi", []byte("dev-ravi"), 0, 10); len(got) != 0 {
		t.Fatalf("the sender got its own: %d", len(got))
	}
	cs.Register(ctx, "c.test", group, "mia", []byte("dev-mia"))
	if got, _ := cs.List(ctx, "c.test", "mia", []byte("dev-mia"), 0, 10); len(got) != 0 {
		t.Fatalf("a device got what came before its registration: %d", len(got))
	}
	// A ban's kick ends the membership and the registrations in the append's transaction.
	if err := cs.Append(ctx, "c.test", 1, []byte("e1"), []byte("h1"), []string{"ravi"}); err != nil {
		t.Fatal(err)
	}
	if err := cs.Append(ctx, "c.test", 1, []byte("e1b"), []byte("h1b"), nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("an append on a stale head: %v", err)
	}
	if ok, _ := cs.Registered(ctx, group, "ravi", []byte("dev-ravi")); ok {
		t.Fatal("a removed member is still registered")
	}
	if err := cs.Create(ctx, store.Community{Name: "c.test", ID: []byte("x")}, nil, nil, store.CommunityMember{ID: "x"}, nil); !errors.Is(err, store.ErrExists) {
		t.Fatalf("a second community on one name: %v", err)
	}
}

func TestIcons(t *testing.T) {
	cs := newCommunityStore(t)
	ctx := context.Background()
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := cs.PutIcon(ctx, "c.example.org", a, "image/png", []byte("png"), 100); err != nil {
		t.Fatal(err)
	}
	if err := cs.PutIcon(ctx, "c.example.org", b, "image/webp", []byte("webp"), 100); err != nil {
		t.Fatal(err)
	}
	if mt, data, err := cs.Icon(ctx, "c.example.org", a); err != nil || mt != "image/png" || string(data) != "png" {
		t.Fatalf("%q %q %v", mt, data, err)
	}
	if _, _, err := cs.Icon(ctx, "other.example.org", a); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another community's icon: %v", err)
	}
	// Within 24 hours, both stay; after, only the one kept.
	if n, err := cs.PruneIcons(ctx, "c.example.org", nil, 100); err != nil || n != 0 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if n, err := cs.PruneIcons(ctx, "c.example.org", a, 101); err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if _, _, err := cs.Icon(ctx, "c.example.org", b); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the unnamed icon stayed: %v", err)
	}
	if n, err := cs.PruneIcons(ctx, "c.example.org", nil, 101); err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
}
