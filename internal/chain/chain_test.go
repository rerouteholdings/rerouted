package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Vectors are copied from the Tieroute spec repo (spec/vectors) into testdata,
// so this module stays self-contained.

type vecSigned struct {
	SignedJCS    string `json:"signed"`
	SignedSHA256 string `json:"signed_sha256"`
}

type chainVectors struct {
	Keys struct {
		Device1 struct {
			SeedHex string `json:"seed_hex"`
		} `json:"device_1"`
		Device2 struct {
			SeedHex   string `json:"seed_hex"`
			PublicHex string `json:"public_hex"`
		} `json:"device_2"`
	} `json:"keys"`
	IdentityID string `json:"identity_id"`
	Entries    []struct {
		Signed vecSigned `json:"signed"`
	} `json:"entries"`
	Final struct {
		Devices            []string `json:"devices"`
		Home               string   `json:"home"`
		Handle             string   `json:"handle"`
		RecoveryCommitment string   `json:"recovery_commitment"`
		HeadSeq            uint64   `json:"head_seq"`
		HeadSHA256         string   `json:"head_sha256"`
	} `json:"final_state"`
}

type recoveryVectors struct {
	Key2 struct {
		SeedHex string `json:"seed_hex"`
	} `json:"recovery_key_2"`
}

func load[T any](t *testing.T, name string) T {
	t.Helper()
	b, err := os.ReadFile("../../testdata/vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func entries(t *testing.T, v chainVectors) []wire.Signed {
	t.Helper()
	var out []wire.Signed
	for i, e := range v.Entries {
		s, err := wire.DecodeSigned([]byte(e.Signed.SignedJCS))
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		out = append(out, s)
	}
	return out
}

func TestVectorChainValidates(t *testing.T) {
	v := load[chainVectors](t, "chain.json")
	es := entries(t, v)

	// Each entry re-encodes to exactly the vector text (JCS).
	for i, s := range es {
		enc, err := s.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if string(enc) != v.Entries[i].Signed.SignedJCS {
			t.Fatalf("entry %d doesn't round-trip", i)
		}
	}

	st, err := Validate(es)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if st.ID != v.IdentityID {
		t.Errorf("ID = %s, want %s", st.ID, v.IdentityID)
	}
	if st.Seq != v.Final.HeadSeq || hex.EncodeToString(st.Head) != v.Final.HeadSHA256 {
		t.Errorf("head = %d %x, want %d %s", st.Seq, st.Head, v.Final.HeadSeq, v.Final.HeadSHA256)
	}
	if st.Home != v.Final.Home || st.Handle != v.Final.Handle {
		t.Errorf("home/handle = %s %s", st.Home, st.Handle)
	}
	if hex.EncodeToString(st.RecoveryCommit) != v.Final.RecoveryCommitment {
		t.Errorf("recovery commitment = %x", st.RecoveryCommit)
	}
	if len(st.Devices) != len(v.Final.Devices) || !st.HasDevice(unhex(t, v.Final.Devices[0])) {
		t.Errorf("devices = %v, want %v", st.Devices, v.Final.Devices)
	}
}

func TestVectorAlerts(t *testing.T) {
	v := load[chainVectors](t, "chain.json")
	es := entries(t, v)
	st, first, err := Genesis(es[0])
	if err != nil {
		t.Fatal(err)
	}
	want := []AlertLevel{AlertNone, AlertNotice, AlertNone, AlertNotice} // genesis, add, recovery remove, self-rotation
	got := []AlertLevel{Alert(first)}
	for _, s := range es[1:] {
		a, err := st.Apply(s)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, Alert(a))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d alert = %v, want %v", i, got[i], want[i])
		}
	}
}

// build signs a chain entry for negative tests.
func build(t *testing.T, e wire.ChainEntry, priv ed25519.PrivateKey) wire.Signed {
	t.Helper()
	s, err := wire.Sign(wire.TypeChainEntry, e, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRejections(t *testing.T) {
	v := load[chainVectors](t, "chain.json")
	rv := load[recoveryVectors](t, "recovery.json")
	es := entries(t, v)
	dev1 := ed25519.NewKeyFromSeed(unhex(t, v.Keys.Device1.SeedHex))
	rec2 := ed25519.NewKeyFromSeed(unhex(t, rv.Key2.SeedHex))

	fresh := func() *State {
		st, _, err := Genesis(es[0])
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	next := func(st *State, ops ...wire.Op) wire.ChainEntry {
		return wire.ChainEntry{ID: st.ID, Seq: st.Seq + 1, Prev: st.Head, TS: st.HeadTS + 1, Ops: ops}
	}
	dev2 := unhex(t, v.Keys.Device2.PublicHex)
	handle := "evil.example"

	cases := []struct {
		name string
		make func(st *State) wire.Signed
	}{
		{"tampered signature", func(st *State) wire.Signed {
			s := build(t, next(st, wire.Op{Op: wire.OpAddDevice, Key: dev2}), dev1)
			s.S[0] ^= 1
			return s
		}},
		{"wrong prev", func(st *State) wire.Signed {
			e := next(st, wire.Op{Op: wire.OpAddDevice, Key: dev2})
			e.Prev = make([]byte, 32)
			return build(t, e, dev1)
		}},
		{"wrong seq", func(st *State) wire.Signed {
			e := next(st, wire.Op{Op: wire.OpAddDevice, Key: dev2})
			e.Seq = 5
			return build(t, e, dev1)
		}},
		{"device signs set-recovery", func(st *State) wire.Signed {
			return build(t, next(st, wire.Op{Op: wire.OpSetRecovery, Next: make([]byte, 32)}), dev1)
		}},
		{"uncommitted recovery key", func(st *State) wire.Signed {
			// recovery key 2 isn't authorized yet: genesis commits to key 1.
			return build(t, next(st, wire.Op{Op: wire.OpSetHandle, Handle: &handle}, wire.Op{Op: wire.OpSetRecovery, Next: make([]byte, 32)}), rec2)
		}},
		{"removes last device", func(st *State) wire.Signed {
			return build(t, next(st, wire.Op{Op: wire.OpRemoveDevice, Key: wire.Bytes(dev1.Public().(ed25519.PublicKey))}), dev1)
		}},
		{"ts goes backwards", func(st *State) wire.Signed {
			e := next(st, wire.Op{Op: wire.OpAddDevice, Key: dev2})
			e.TS = st.HeadTS - 1
			return build(t, e, dev1)
		}},
		{"unknown op", func(st *State) wire.Signed {
			return build(t, next(st, wire.Op{Op: "set-everything"}), dev1)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := fresh()
			before := st.Seq
			_, err := st.Apply(c.make(st))
			if c.name == "unknown op" && !errors.Is(err, ErrUnknownOp) {
				t.Fatalf("got %v, want ErrUnknownOp", err)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			if st.Seq != before {
				t.Fatal("state changed after a rejected entry")
			}
		})
	}
}

func TestCheckClock(t *testing.T) {
	now := uint64(1_800_000_000)
	if CheckClock(now+MaxSkew+1, now, false) == nil {
		t.Error("future entry accepted downstream")
	}
	if CheckClock(now-86400*3, now, false) != nil {
		t.Error("late honest entry rejected downstream")
	}
	if CheckClock(now-MaxSkew-1, now, true) == nil {
		t.Error("backdated append accepted")
	}
}
