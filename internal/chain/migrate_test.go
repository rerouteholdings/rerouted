package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// migrate.json, both sides (SPEC §6.8): each case is a version 1 chain, validated by
// version 1's rules, and a version 2 genesis, and the pair is accepted only if the chain
// validates, ends in a migrate naming the genesis's hash, and the genesis names the
// version 1 identifier.
func TestVectorMigrate(t *testing.T) {
	var v struct {
		V1ID  string `json:"v1_identity_id"`
		V2ID  string `json:"v2_identity_id"`
		Cases []struct {
			Name     string   `json:"name"`
			Accepted bool     `json:"accepted"`
			V1Chain  []string `json:"v1_chain"`
			Genesis  string   `json:"v2_genesis"`
		} `json:"cases"`
	}
	readV2(t, "migrate.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var raw []wire.Signed
			for _, e := range c.V1Chain {
				s, err := wire.DecodeSigned([]byte(e))
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, s)
			}
			v1, err1 := ValidateFor(wire.V1, raw)
			g, err := wire.DecodeSignedV2([]byte(c.Genesis))
			if err != nil {
				t.Fatal(err)
			}
			v2, _, err2 := GenesisFor(wire.V2, g)
			got := err1 == nil && err2 == nil && Linked(v1, v2)
			if got != c.Accepted {
				t.Fatalf("accepted %v, want %v (v1: %v, v2: %v)", got, c.Accepted, err1, err2)
			}
			if got && (v1.MigratedID() != v2.ID || v2.ID != v.V2ID || v1.ID != v.V1ID) {
				t.Fatalf("ids: %s -> %s, want %s -> %s", v1.ID, v1.MigratedID(), v.V1ID, v.V2ID)
			}
		})
	}
}

// v1World builds wire version 1 chains with fresh keys.
type v1World struct {
	t    *testing.T
	dev  ed25519.PrivateKey
	rec  []ed25519.PrivateKey
	raw  []wire.Signed
	enc  [][]byte
	head []byte
	ts   uint64
}

func newV1World(t *testing.T) *v1World {
	t.Helper()
	w := &v1World{t: t, ts: 1_800_000_000}
	_, w.dev, _ = ed25519.GenerateKey(rand.Reader)
	for range 2 {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		w.rec = append(w.rec, k)
	}
	w.add(w.sign(w.dev, map[string]any{"seq": 0, "ts": w.ts, "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(w.dev.Public().(ed25519.PublicKey))},
		map[string]any{"op": "set-home", "home": "chat.example"},
		map[string]any{"op": "set-handle", "handle": "kat.chat.example"},
		map[string]any{"op": "set-recovery", "next": w.commit(0)},
	}}))
	return w
}

func (w *v1World) commit(i int) []byte {
	sum := sha256.Sum256(w.rec[i].Public().(ed25519.PublicKey))
	return sum[:]
}

func (w *v1World) sign(k ed25519.PrivateKey, body map[string]any) wire.Signed {
	w.t.Helper()
	s, err := wire.Sign(wire.TypeChainEntry, body, k)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *v1World) add(s wire.Signed) {
	enc, _ := s.Encode()
	sum := sha256.Sum256(enc)
	w.raw, w.enc, w.head = append(w.raw, s), append(w.enc, enc), sum[:]
}

func (w *v1World) id() string { return wire.IdentityID(w.enc[0]) }

// next signs the entry after the head, at seq, with ops.
func (w *v1World) next(k ed25519.PrivateKey, seq int, prev []byte, ops ...any) wire.Signed {
	w.ts += 60
	return w.sign(k, map[string]any{"id": w.id(), "seq": seq, "prev": prev, "ts": w.ts, "ops": ops})
}

func TestMigrateClosesTheChain(t *testing.T) {
	w := newV1World(t)
	to := make([]byte, 32)
	rand.Read(to)
	migrate := map[string]any{"op": "migrate", "to": to}

	// Migrate isn't allowed in genesis, needs a 32-byte hash, and comes once.
	g := w.sign(w.dev, map[string]any{"seq": 0, "ts": 1, "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(w.dev.Public().(ed25519.PublicKey))},
		map[string]any{"op": "set-home", "home": "chat.example"},
		map[string]any{"op": "set-handle", "handle": "kat.chat.example"},
		map[string]any{"op": "set-recovery", "next": w.commit(0)},
		migrate,
	}})
	if _, _, err := Genesis(g); err == nil {
		t.Fatal("migrate in genesis")
	}
	st, err := ValidateFor(wire.V1, w.raw)
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]wire.Signed{
		"short hash":   w.next(w.dev, 1, w.head, map[string]any{"op": "migrate", "to": to[:16]}),
		"two migrates": w.next(w.dev, 1, w.head, migrate, migrate),
		"extra member": w.next(w.dev, 1, w.head, map[string]any{"op": "migrate", "to": to, "home": "x.example"}),
	} {
		if _, err := st.Clone().Apply(e); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A device's migrate closes the chain, and is an alarm.
	m := w.next(w.dev, 1, w.head, migrate)
	a, err := st.Apply(m)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Closed() || st.MigratedID() != wire.IdentityIDFromHash(to) || Alert(a) != AlertAlarm {
		t.Fatalf("closed %v, id %s, alert %v", st.Closed(), st.MigratedID(), Alert(a))
	}
	w.add(m)
	// Nothing follows it, from a device or the recovery code.
	if _, err := st.Clone().Apply(w.next(w.dev, 2, w.head, map[string]any{"op": "set-handle", "handle": "x.chat.example"})); err == nil {
		t.Fatal("a device entry after migrate")
	}
	rec := w.next(w.rec[0], 2, w.head, map[string]any{"op": "set-recovery", "next": w.commit(1)})
	if _, err := st.Clone().Apply(rec); err == nil {
		t.Fatal("a recovery entry after migrate")
	}
	// And the recovery code can't fork it away either: a migrate is final.
	sum := sha256.Sum256(w.enc[0])
	fork := w.next(w.rec[0], 1, sum[:], map[string]any{"op": "set-recovery", "next": w.commit(1)})
	fenc, _ := fork.Encode()
	if _, _, _, err := ResolveFor(wire.V1, w.enc, [][]byte{w.enc[0], fenc}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "migrates the identity") {
		t.Fatalf("a recovery fork over migrate: %v", err)
	}
	// Version 2 doesn't know migrate.
	st2 := &State{V: wire.V2, Devices: map[string]string{}, Pubs: map[string]*wire.CompositePublicKey{}}
	if err := st2.applyOp(wire.Op{Op: wire.OpMigrate, To: to}, false); !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("version 2 migrate: %v", err)
	}
	if err := (wire.Op{Op: wire.OpMigrate, To: to}).CheckV2(); err == nil {
		t.Fatal("version 2 took a member named to")
	}
	if err := (wire.Op{Op: wire.OpSetHome, Home: "x", To: to}).Check(); err == nil {
		t.Fatal("version 1 set-home took a member named to")
	}
}

// A recovery-signed migrate is fine too: the recovery key can sign any op, and commits to
// the next key as usual (SPEC §6.4 rule 3).
func TestMigrateByRecovery(t *testing.T) {
	w := newV1World(t)
	to := make([]byte, 32)
	rand.Read(to)
	st, err := ValidateFor(wire.V1, w.raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Clone().Apply(w.next(w.rec[0], 1, w.head, map[string]any{"op": "migrate", "to": to})); err == nil {
		t.Fatal("a recovery-signed migrate without set-recovery")
	}
	a, err := st.Apply(w.next(w.rec[0], 1, w.head, map[string]any{"op": "migrate", "to": to}, map[string]any{"op": "set-recovery", "next": w.commit(1)}))
	if err != nil || a.Signer != SignerRecovery || !st.Closed() {
		t.Fatalf("recovery-signed migrate: %v", err)
	}
}
