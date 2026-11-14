package sqlite

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// A wire version 1 identity migrating to version 2 (SPEC §6.8), all at once: the closing
// entry, the new identity and its handle, and the allowlists carried over.
func TestWireMigration(t *testing.T) {
	ctx := context.Background()
	s, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v1, v2 := s.ForWire(wire.V1), s.ForWire(wire.V2)
	if err := v1.Chains().Create(ctx, "kat1", []byte("g1"), "kat.test"); err != nil {
		t.Fatal(err)
	}
	if err := v2.Chains().Create(ctx, "ravi2", []byte("gr"), "ravi.test"); err != nil {
		t.Fatal(err)
	}
	if err := v1.Chains().Create(ctx, "eve1", []byte("ge"), "eve.test"); err != nil {
		t.Fatal(err)
	}
	put := func(owner, other, state string) {
		if err := s.Contacts().Put(ctx, owner, store.Contact{ID: other, State: state, Since: 7, Request: []byte("r")}); err != nil {
			t.Fatal(err)
		}
	}
	put("kat1", "ravi1", store.StateContact)   // migrated, elsewhere: mapped by the caller
	put("kat1", "sam1", store.StateContact)    // hasn't migrated: kept for when it does
	put("kat1", "mal1", store.StateBlocked)    // blocks carry over
	put("kat1", "pat1", store.StatePendingOut) // pending requests don't
	put("ravi2", "kat1", store.StateContact)   // a version 2 owner: rewritten
	put("eve1", "kat1", store.StateContact)    // a version 1 owner: left alone
	if err := s.Contacts().AllowGroup(ctx, "kat1", []byte("g")); err != nil {
		t.Fatal(err)
	}
	m := store.Migration{From: "kat1", To: "kat2", PrevSeq: 0, Entry: []byte("migrate"), Genesis: []byte("g2"), Handle: "kat.test", Contacts: map[string]string{"ravi1": "ravi2"}}

	// A stale head, or a handle someone else holds, changes nothing.
	stale := m
	stale.PrevSeq = 3
	if err := v1.Chains().Migrate(ctx, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale head: %v", err)
	}
	taken := m
	taken.Handle = "eve.test"
	if err := v1.Chains().Migrate(ctx, taken); !errors.Is(err, store.ErrHandleTaken) {
		t.Fatalf("taken handle: %v", err)
	}
	if id, _ := v1.Chains().ByHandle(ctx, "kat.test"); id != "kat1" {
		t.Fatalf("handle moved on a failed migration: %s", id)
	}
	if err := v2.Chains().Migrate(ctx, m); err == nil {
		t.Fatal("migrated on the version 2 view")
	}

	if err := v1.Chains().Migrate(ctx, m); err != nil {
		t.Fatal(err)
	}
	if e, err := v1.Chains().Entries(ctx, "kat1", -1); err != nil || len(e) != 2 || string(e[1]) != "migrate" {
		t.Fatalf("version 1 chain: %q %v", e, err)
	}
	if e, err := v2.Chains().Entries(ctx, "kat2", -1); err != nil || len(e) != 1 {
		t.Fatalf("version 2 chain: %q %v", e, err)
	}
	if _, err := v1.Chains().Entries(ctx, "kat2", -1); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the version 1 view sees the version 2 chain")
	}
	if id, _ := v2.Chains().ByHandle(ctx, "kat.test"); id != "kat2" {
		t.Fatalf("handle: %s", id)
	}
	list, _, err := s.Contacts().List(ctx, "kat2", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range list {
		got[c.ID] = c.State
		if c.Request != nil || c.Since != 7 {
			t.Fatalf("%s: request %q, since %d", c.ID, c.Request, c.Since)
		}
	}
	if len(got) != 3 || got["ravi2"] != store.StateContact || got["sam1"] != store.StateContact || got["mal1"] != store.StateBlocked {
		t.Fatalf("kat2's contacts: %v", got)
	}
	if ok, _ := s.Contacts().GroupAllowed(ctx, "kat2", []byte("g")); !ok {
		t.Fatal("groups allowlist")
	}
	if c, err := s.Contacts().Get(ctx, "ravi2", "kat2"); err != nil || c.State != store.StateContact {
		t.Fatalf("ravi2's entry: %+v %v", c, err)
	}
	if _, err := s.Contacts().Get(ctx, "ravi2", "kat1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("ravi2 still lists kat1")
	}
	if _, err := s.Contacts().Get(ctx, "eve1", "kat1"); err != nil {
		t.Fatal("eve1's version 1 entry was rewritten")
	}
	// Done once: the version 2 identity exists now.
	m.PrevSeq = 1
	if err := v1.Chains().Migrate(ctx, m); !errors.Is(err, store.ErrExists) {
		t.Fatalf("again: %v", err)
	}

	// Later, sam1 migrates elsewhere, and its version 2 identity takes its place in kat2's list.
	owners, err := s.Contacts().RewriteMigrated(ctx, "sam1", "sam2")
	if err != nil || !slices.Equal(owners, []string{"kat2"}) {
		t.Fatalf("rewrite: %v %v", owners, err)
	}
	if c, err := s.Contacts().Get(ctx, "kat2", "sam2"); err != nil || c.State != store.StateContact {
		t.Fatalf("kat2's sam2: %+v %v", c, err)
	}
	if owners, err := s.Contacts().RewriteMigrated(ctx, "sam1", "sam2"); err != nil || len(owners) != 0 {
		t.Fatalf("rewrite again: %v %v", owners, err)
	}
}

// A failure anywhere in a migration leaves everything as it was.
func TestWireMigrationRollback(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"chains", "contacts", "groups_allowed", "handles"} {
		t.Run(table, func(t *testing.T) {
			s, err := OpenTemp()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Chains().Create(ctx, "kat1", []byte("g1"), "kat.test"); err != nil {
				t.Fatal(err)
			}
			s.Contacts().Put(ctx, "kat1", store.Contact{ID: "ravi1", State: store.StateContact})
			s.Contacts().AllowGroup(ctx, "kat1", []byte("g"))
			if _, err := s.db.Exec("CREATE TRIGGER fail BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("CREATE TRIGGER fail_u BEFORE UPDATE ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
				t.Fatal(err)
			}
			m := store.Migration{From: "kat1", To: "kat2", Entry: []byte("migrate"), Genesis: []byte("g2"), Handle: "kat2.test"}
			if err := s.Chains().Migrate(ctx, m); err == nil {
				t.Fatal("injected failure succeeded")
			}
			for q, want := range map[string]int{
				"SELECT count(*) FROM chains":                        1,
				"SELECT count(*) FROM handles WHERE id = 'kat1'":     1,
				"SELECT count(*) FROM contacts WHERE owner = 'kat2'": 0,
				"SELECT count(*) FROM groups_allowed":                1,
			} {
				var n int
				if err := s.db.QueryRow(q).Scan(&n); err != nil || n != want {
					t.Fatalf("%s: %d, %v", q, n, err)
				}
			}
		})
	}
}
