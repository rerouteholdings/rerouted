package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// FuzzApply appends one entry, with any body, to the vectors' genesis, signed by a key the
// chain knows (device 1 or recovery key 1) or one it doesn't (device 2). An entry Apply
// refuses leaves the state as it was; one it accepts validates as part of the whole chain,
// to the same state. Run it with go test -fuzz=FuzzApply ./internal/chain.
func FuzzApply(f *testing.F) {
	raw, err := os.ReadFile("../../testdata/vectors/chain.json")
	if err != nil {
		f.Fatal(err)
	}
	var v chainVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	rraw, err := os.ReadFile("../../testdata/vectors/recovery.json")
	if err != nil {
		f.Fatal(err)
	}
	var rv struct {
		Key1 struct {
			SeedHex string `json:"seed_hex"`
		} `json:"recovery_key_1"`
	}
	if err := json.Unmarshal(rraw, &rv); err != nil {
		f.Fatal(err)
	}
	seed := func(s string) ed25519.PrivateKey {
		b, err := hex.DecodeString(s)
		if err != nil {
			f.Fatal(err)
		}
		return ed25519.NewKeyFromSeed(b)
	}
	signers := []ed25519.PrivateKey{seed(v.Keys.Device1.SeedHex), seed(rv.Key1.SeedHex), seed(v.Keys.Device2.SeedHex)}
	var es []wire.Signed
	for _, e := range v.Entries {
		s, err := wire.DecodeSigned([]byte(e.Signed.SignedJCS))
		if err != nil {
			f.Fatal(err)
		}
		es = append(es, s)
	}
	genesis, _, err := Genesis(es[0])
	if err != nil {
		f.Fatal(err)
	}
	// Seeds: the vectors' later entries, and well-formed next entries with each op.
	for i, e := range es[1:] {
		f.Add([]byte(e.B), uint8(i%2))
	}
	dev2, _ := hex.DecodeString(v.Keys.Device2.PublicHex)
	handle, home := "kat.example.org", "example.org"
	f.Add([]byte(`{"ops":[]}`), uint8(2))
	for _, ops := range [][]wire.Op{
		{{Op: wire.OpAddDevice, Key: dev2, Name: "phone"}},
		{{Op: wire.OpRemoveDevice, Key: wire.Bytes(signers[0].Public().(ed25519.PublicKey))}},
		{{Op: wire.OpSetHandle, Handle: &handle}},
		{{Op: wire.OpSetHome, Home: home}},
		{{Op: wire.OpSetRecovery, Next: make([]byte, 32)}},
	} {
		b, err := wire.Marshal(wire.ChainEntry{ID: genesis.ID, Seq: 1, Prev: genesis.Head, TS: genesis.HeadTS + 1, Ops: ops})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, uint8(0))
		f.Add(b, uint8(1))
	}
	f.Fuzz(func(t *testing.T, body []byte, by uint8) {
		s, err := wire.Sign(wire.TypeChainEntry, wire.Raw(body), signers[int(by)%len(signers)])
		if err != nil {
			return // not JSON
		}
		st := genesis.Clone()
		_, err = st.Apply(s)
		if err != nil {
			if !reflect.DeepEqual(st, genesis.Clone()) {
				t.Fatalf("Apply refused %s (%v), but changed the state", s.B, err)
			}
			return
		}
		whole, err := Validate([]wire.Signed{es[0], s})
		if err != nil {
			t.Fatalf("Apply accepted %s, but the chain doesn't validate: %v", s.B, err)
		}
		if !reflect.DeepEqual(whole, st) {
			t.Fatalf("Apply and Validate disagree on %s:\n%+v\n%+v", s.B, st, whole)
		}
		// Encoded and decoded again, as a stored entry is, it's still accepted.
		enc, _ := s.Encode()
		back, err := wire.DecodeSigned(enc)
		if err != nil {
			t.Fatalf("an accepted entry doesn't decode: %v", err)
		}
		if _, err := genesis.Clone().Apply(back); err != nil {
			t.Fatalf("an accepted entry, stored and read back, is refused: %v", err)
		}
	})
}
