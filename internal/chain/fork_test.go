package chain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// forkWorld is a small identity for fork-rule tests: a laptop, a phone, a thief's
// device, and the first two recovery keys.
type forkWorld struct {
	t                    *testing.T
	laptop, phone, thief ed25519.PrivateKey
	rec1, rec2           ed25519.PrivateKey
	genesis              []byte
	id                   string
}

func key(seed byte) ed25519.PrivateKey {
	s := make([]byte, 32)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s)
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func commit(k ed25519.PrivateKey) []byte {
	h := sha256.Sum256(pub(k))
	return h[:]
}

func newForkWorld(t *testing.T) *forkWorld {
	w := &forkWorld{t: t, laptop: key(1), phone: key(2), thief: key(3), rec1: key(10), rec2: key(11)}
	handle := "kat.home.example"
	g := wire.ChainEntry{Seq: 0, TS: 1_000_000, Ops: []wire.Op{
		{Op: wire.OpAddDevice, Key: pub(w.laptop), Name: "Laptop"},
		{Op: wire.OpSetHome, Home: "home.example"},
		{Op: wire.OpSetHandle, Handle: &handle},
		{Op: wire.OpSetRecovery, Next: commit(w.rec1)},
	}}
	w.genesis = w.enc(g, w.laptop)
	w.id = wire.IdentityID(w.genesis)
	return w
}

func (w *forkWorld) enc(e wire.ChainEntry, k ed25519.PrivateKey) []byte {
	s, err := wire.Sign(wire.TypeChainEntry, e, k)
	if err != nil {
		w.t.Fatal(err)
	}
	b, err := s.Encode()
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// next signs an entry on top of chain.
func (w *forkWorld) next(chain [][]byte, ts uint64, k ed25519.PrivateKey, ops ...wire.Op) [][]byte {
	st, _, _, err := Resolve(nil, chain)
	if err != nil {
		w.t.Fatal(err)
	}
	e := wire.ChainEntry{ID: w.id, Seq: st.Seq + 1, Prev: st.Head, TS: ts, Ops: ops}
	return append(append([][]byte(nil), chain...), w.enc(e, k))
}

func TestResolve(t *testing.T) {
	w := newForkWorld(t)
	const hour = 3600
	t0 := uint64(1_000_000)
	base := w.next([][]byte{w.genesis}, t0+10, w.laptop, wire.Op{Op: wire.OpAddDevice, Key: pub(w.phone), Name: "Phone"})

	// The laptop is stolen: the thief adds a device, then moves the account and removes the phone.
	stolen := w.next(base, t0+20*hour, w.laptop, wire.Op{Op: wire.OpAddDevice, Key: pub(w.thief)})
	stolen = w.next(stolen, t0+21*hour, w.thief,
		wire.Op{Op: wire.OpSetHome, Home: "evil.example"},
		wire.Op{Op: wire.OpRemoveDevice, Key: pub(w.phone)})

	// Kat's fix, forking from before the theft.
	recoverAt := func(ts uint64) [][]byte {
		return w.next(base, ts, w.rec1,
			wire.Op{Op: wire.OpRemoveDevice, Key: pub(w.laptop)},
			wire.Op{Op: wire.OpSetRecovery, Next: commit(w.rec2)})
	}
	fixed := recoverAt(t0 + 30*hour)

	t.Run("extends", func(t *testing.T) {
		if _, out, _, err := Resolve(base, stolen); err != nil || out != Extends {
			t.Fatalf("got %v, %v", out, err)
		}
	})
	t.Run("same or older", func(t *testing.T) {
		st, out, _, err := Resolve(stolen, base)
		if err != nil || out != Same || st.Seq != 3 {
			t.Fatalf("got %v, %v (seq %v)", out, err, st)
		}
	})
	t.Run("recovery fork wins, even though it's shorter", func(t *testing.T) {
		st, out, at, err := Resolve(stolen, fixed)
		if err != nil || out != Fork || at != 2 {
			t.Fatalf("got %v at %d, %v", out, at, err)
		}
		if st.Home != "home.example" || st.HasDevice(pub(w.thief)) || !st.HasDevice(pub(w.phone)) {
			t.Fatalf("wrong state after the fork: %+v", st)
		}
	})
	t.Run("the overridden branch can't come back", func(t *testing.T) {
		if _, _, _, err := Resolve(fixed, stolen); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
	t.Run("more than 72 hours is too late", func(t *testing.T) {
		late := recoverAt(t0 + 20*hour + ForkWindow + 1)
		if _, _, _, err := Resolve(stolen, late); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
	t.Run("a device-signed fork is rejected", func(t *testing.T) {
		other := w.next(base, t0+22*hour, w.phone, wire.Op{Op: wire.OpRemoveDevice, Key: pub(w.laptop)})
		if _, _, _, err := Resolve(stolen, other); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
	t.Run("two recovery branches: keep the first", func(t *testing.T) {
		second := w.next(base, t0+31*hour, w.rec1,
			wire.Op{Op: wire.OpRemoveDevice, Key: pub(w.phone)},
			wire.Op{Op: wire.OpSetRecovery, Next: commit(w.rec2)})
		if _, _, _, err := Resolve(fixed, second); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
	t.Run("different genesis", func(t *testing.T) {
		other := newForkWorld(t)
		other.laptop = key(9)
		handle := "kat.home.example"
		g := other.enc(wire.ChainEntry{TS: t0, Ops: []wire.Op{
			{Op: wire.OpAddDevice, Key: pub(other.laptop)},
			{Op: wire.OpSetHome, Home: "home.example"},
			{Op: wire.OpSetHandle, Handle: &handle},
			{Op: wire.OpSetRecovery, Next: commit(w.rec1)},
		}}, other.laptop)
		if _, _, _, err := Resolve(base, [][]byte{g}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v, want ErrInvalid", err)
		}
	})
}

// TestVectorFork checks Resolve against spec/vectors/fork.json.
func TestVectorFork(t *testing.T) {
	v := load[struct {
		Cases []struct {
			Name      string   `json:"name"`
			Cached    []string `json:"cached"`
			Candidate []string `json:"candidate"`
			Outcome   string   `json:"outcome"`
			ForkAt    uint64   `json:"fork_at"`
			Final     *struct {
				Devices    []string `json:"devices"`
				Home       string   `json:"home"`
				HeadSeq    uint64   `json:"head_seq"`
				HeadSHA256 string   `json:"head_sha256"`
			} `json:"final_state"`
		} `json:"cases"`
	}](t, "fork.json")
	raw := func(xs []string) [][]byte {
		out := make([][]byte, len(xs))
		for i, x := range xs {
			out[i] = []byte(x)
		}
		return out
	}
	names := map[Outcome]string{Same: "same", Extends: "extends", Fork: "fork"}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			st, out, at, err := Resolve(raw(c.Cached), raw(c.Candidate))
			got := names[out]
			if err != nil {
				got = "reject"
			}
			if got != c.Outcome {
				t.Fatalf("outcome %s (%v), want %s", got, err, c.Outcome)
			}
			if c.Outcome == "fork" && at != c.ForkAt {
				t.Fatalf("fork at %d, want %d", at, c.ForkAt)
			}
			if f := c.Final; f != nil {
				if st.Home != f.Home || st.Seq != f.HeadSeq || hex.EncodeToString(st.Head) != f.HeadSHA256 || len(st.Devices) != len(f.Devices) || !st.HasDevice(unhex(t, f.Devices[0])) {
					t.Fatalf("final state %+v doesn't match %+v", st, f)
				}
			}
		})
	}
}
