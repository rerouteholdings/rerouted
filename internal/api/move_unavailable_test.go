package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// A store whose move registration fails, as a full disk or a locked database would.
type failingMoveStore struct{ store.Store }
type failingMoveChains struct{ store.Chains }

func (s failingMoveStore) Chains() store.Chains { return failingMoveChains{s.Store.Chains()} }
func (failingMoveChains) RegisterMove(context.Context, store.MoveRegistration) (bool, error) {
	return false, errors.New("disk full")
}

// SPEC §6.6: a storage failure during registration leaves the previous state and answers
// 503 unavailable, so the client retries; it isn't a 500.
func TestMoveRegistrationStorageFailureIsUnavailable(t *testing.T) {
	a, b, _, _ := twoServersWithStore(t, func() store.Store { return failingMoveStore{newStore(t)} })
	kat := newUserOn(t, a, "kat", "a.test")
	entries := kat.chainOf(a)
	entry := kat.moveEntry(entries, "b.test", "kat.b.test")
	// With registration failing, b.test can't issue a reservation either: the move stops
	// before the old home changes anything.
	head := sha256.Sum256(entry) // the chain the client is about to have ends with the move
	req := map[string]any{"chain": append(entries, entry), "invite": testRegCode, "check": true,
		"move": signed(t, "move", map[string]any{"id": kat.id, "server": "b.test", "head": head[:], "ts": time.Now().Unix(), "contacts": []string{}, "groups": []wire.Bytes{}}, kat.dev)}
	var e wire.Error
	if c := call(t, b, "POST", "register", "", req, &e); c != 503 || e.Code != wire.ErrCodeUnavailable {
		t.Fatalf("got %d %q, want 503 unavailable", c, e.Code)
	}
}
