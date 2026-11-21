package serverkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

const day = 24 * time.Hour

func kids(p []Published) []string {
	var out []string
	for _, k := range p {
		out = append(out, k.KID)
	}
	return out
}

// A key rotates on its own: a successor is published 300 days in, signs a week later, and
// the key it replaced stays published until its exp. Reopening the files at any point gives
// the same keys.
func TestRotation(t *testing.T) {
	for _, composite := range []bool{false, true} {
		dir := t.TempDir()
		s, err := OpenSlot(dir, "k.json", composite)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Unix(s.current().created, 0)
		first := s.current().kid
		if err := s.Maintain(start.Add(RotateAfter - day)); err != nil || len(s.Published(start)) != 1 {
			t.Fatalf("rotated early: %v %v", err, kids(s.Published(start)))
		}
		// Day 300: the successor is published, and the first key still signs.
		at := start.Add(RotateAfter)
		if err := s.Maintain(at); err != nil {
			t.Fatal(err)
		}
		pub := s.Published(at)
		if len(pub) != 2 || pub[0].KID != first || s.current().kid != first {
			t.Fatalf("day 300: %v", kids(pub))
		}
		second := pub[1].KID
		if pub[1].NBF != at.Unix() || pub[1].EXP-pub[1].NBF != int64(Lifetime/time.Second) {
			t.Fatalf("the successor's times: %+v", pub[1])
		}
		// A week later, it signs; the first key stays listed until its exp.
		at = at.Add(SwitchAfter)
		if err := s.Maintain(at); err != nil {
			t.Fatal(err)
		}
		if s.current().kid != second || len(s.Published(at)) != 2 {
			t.Fatalf("after the switch: signs %s, lists %v", s.current().kid, kids(s.Published(at)))
		}
		again, err := OpenSlot(dir, "k.json", composite)
		if err != nil || again.current().kid != second || len(again.Published(at)) != 2 {
			t.Fatalf("reopened: %v", err)
		}
		// Past the first key's exp, it's gone.
		at = start.Add(Lifetime + time.Second)
		if err := s.Maintain(at); err != nil {
			t.Fatal(err)
		}
		if got := kids(s.Published(at)); len(got) != 1 || got[0] != second {
			t.Fatalf("past exp: %v", got)
		}
		for _, p := range s.Published(at) {
			if p.EXP-p.NBF > int64(MaxLifetime/time.Second) {
				t.Fatal("a key over the 400-day cap")
			}
		}
	}
}

// A server set up before rotation has only server-key.json, as it always had, and maybe a
// key already late in its life. It rotates from it, and its invite key stays what it was.
func TestRotationFromAnOldServer(t *testing.T) {
	dir := t.TempDir()
	created := time.Now().Add(-364 * day)
	seed := bytes.Repeat([]byte{7}, 32)
	b, _ := wire.Marshal(file{Seed: seed, Created: created.Unix()})
	os.WriteFile(filepath.Join(dir, "server-key.json"), b, 0o600)
	keys, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := keys.Current()
	if !bytes.Equal(old.Priv.Seed(), seed) {
		t.Fatal("not the existing key")
	}
	// The invite key is the one api derived from server-key.json before.
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("tieroute invite codes"))
	if !bytes.Equal(keys.InviteKey(), mac.Sum(nil)) {
		t.Fatal("the invite key isn't the one derived from server-key.json")
	}
	invite := keys.InviteKey()
	// One day from its exp: the successor signs at once, rather than after a week.
	if err := keys.Maintain(time.Now()); err != nil {
		t.Fatal(err)
	}
	now := keys.Current()
	if now.KID == old.KID {
		t.Fatal("a key one day from its exp still signs")
	}
	if got := kids(keys.V1.Published(time.Now())); len(got) != 2 || got[0] != now.KID || got[1] != old.KID {
		t.Fatalf("published: %v", got)
	}
	reopened, err := LoadOrCreate(dir)
	if err != nil || !bytes.Equal(reopened.InviteKey(), invite) {
		t.Fatalf("the invite key changed with the rotation: %v", err)
	}
	if !ed25519.PublicKey(reopened.Current().Public()).Equal(now.Public()) {
		t.Fatal("reopened with another key")
	}
}

// An emergency rotation signs with a new key at once, and marks the old one revoked.
func TestRotateRevoked(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSlot(dir, "k.json", true)
	if err != nil {
		t.Fatal(err)
	}
	first := s.current().kid
	now := time.Now()
	if err := s.Rotate(now, now.Unix()); err != nil {
		t.Fatal(err)
	}
	pub := s.Published(now)
	if s.current().kid == first || len(pub) != 2 || pub[1].KID != first || pub[1].Revoked != now.Unix() || pub[0].Revoked != 0 {
		t.Fatalf("after revoking: %+v", pub)
	}
	// A rotation by another process reaches this one at its next Maintain.
	other, err := OpenSlot(dir, "k.json", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Rotate(now, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(now); err != nil || s.current().kid != other.current().kid {
		t.Fatalf("didn't pick up the other rotation: %v", err)
	}
}
