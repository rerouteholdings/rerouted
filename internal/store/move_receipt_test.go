package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

func TestMoveSemanticReceiptCompatibility(t *testing.T) {
	for _, oldFormat := range []bool{false, true} {
		name := "intent"
		if oldFormat {
			name = "original-signed-receipt"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.db")
			s, err := sqlite.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			intent := store.MoveIntent{ID: "kat", Server: "b.test", Head: wire.Bytes{1}, Contacts: []string{"ravi"}, Groups: []wire.Bytes{{2}}}
			op, err := intent.Encode()
			if err != nil {
				t.Fatal(err)
			}
			stored := op
			if oldFormat {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				sig, err := wire.Sign("move", map[string]any{"id": intent.ID, "server": intent.Server, "head": intent.Head, "ts": 1, "contacts": intent.Contacts, "groups": intent.Groups}, key)
				if err != nil {
					t.Fatal(err)
				}
				stored, err = sig.Encode()
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			m := store.MoveRegistration{ID: "kat", Handle: "kat.b.test", Operation: stored, Entries: [][]byte{[]byte("genesis"), []byte("arrival")}, Contacts: []store.Contact{{ID: "ravi", State: store.StateContact}}, Groups: [][]byte{{2}}}
			if committed, err := s.Chains().RegisterMove(ctx, m); err != nil || !committed {
				t.Fatalf("initial: %v %v", committed, err)
			}
			if err := s.Contacts().Delete(ctx, "kat", "ravi"); err != nil {
				t.Fatal(err)
			}
			if err := s.Contacts().DisallowGroup(ctx, "kat", []byte{2}); err != nil {
				t.Fatal(err)
			}
			if err := s.Chains().Append(ctx, "kat", 1, []byte("away")); err != nil {
				t.Fatal(err)
			}
			s.Close()
			s, err = sqlite.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			m.Operation = op
			for _, probe := range []bool{true, false} {
				m.Probe = probe
				if committed, err := s.Chains().RegisterMove(ctx, m); err != nil || committed {
					t.Fatalf("semantic retry: %v %v", committed, err)
				}
			}
			got, _ := s.Chains().Entries(ctx, "kat", -1)
			if len(got) != 3 {
				t.Fatal("retry changed chain")
			}
			if _, err := s.Contacts().Get(ctx, "kat", "ravi"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("retry restored contact")
			}
			if ok, _ := s.Contacts().GroupAllowed(ctx, "kat", []byte{2}); ok {
				t.Fatal("retry restored group")
			}
			intent.Contacts = []string{"noor"}
			m.Operation, err = intent.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if committed, err := s.Chains().RegisterMove(ctx, m); !errors.Is(err, store.ErrConflict) || committed {
				t.Fatalf("different intent: %v %v", committed, err)
			}
		})
	}
}
