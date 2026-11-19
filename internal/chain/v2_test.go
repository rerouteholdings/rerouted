package chain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Wire version 2 chains (SPEC §6.2 to §6.4.1): the spec's vectors in testdata/vectors/v2,
// then the rules the vectors don't reach.

func readV2(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors/v2/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

type v2Signed struct {
	Signed string `json:"signed"`
}

type v2State struct {
	Devices  []string `json:"devices"`
	Handle   string   `json:"handle"`
	HeadSeq  uint64   `json:"head_seq"`
	HeadHash string   `json:"head_sha256"`
	Home     string   `json:"home"`
	Recovery string   `json:"recovery_commitment"`
}

func canonV2(t *testing.T, text string) []byte {
	t.Helper()
	b, err := wire.CanonicalSignedFor(wire.V2, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkState(t *testing.T, name string, st *State, want v2State) {
	t.Helper()
	var devs []string
	for k := range st.Devices {
		devs = append(devs, k)
	}
	slices.Sort(devs)
	wantDevs := slices.Clone(want.Devices)
	slices.Sort(wantDevs)
	switch {
	case !slices.Equal(devs, wantDevs):
		t.Fatalf("%s: devices %v, want %v", name, devs, wantDevs)
	case st.Seq != want.HeadSeq || hex.EncodeToString(st.Head) != want.HeadHash:
		t.Fatalf("%s: head %d %x, want %d %s", name, st.Seq, st.Head, want.HeadSeq, want.HeadHash)
	case st.Home != want.Home || hex.EncodeToString(st.RecoveryCommit) != want.Recovery:
		t.Fatalf("%s: home or recovery commitment differs", name)
	case want.Handle != "" && st.Handle != want.Handle:
		t.Fatalf("%s: handle %q, want %q", name, st.Handle, want.Handle)
	}
	for k := range st.Devices {
		if pub := st.DevicePub(unhexT(t, k)); pub == nil || hex.EncodeToString(pub.Ed25519()) != k {
			t.Fatalf("%s: device %s has no composite key", name, k)
		}
	}
}

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// chain.json: a four-entry chain with a recovery-signed entry and a self-rotation.
func TestVectorChainV2(t *testing.T) {
	var v struct {
		Entries []struct {
			Signed v2Signed `json:"signed"`
			Signer string   `json:"signer"`
		} `json:"entries"`
		Final v2State `json:"final_state"`
		ID    string  `json:"identity_id"`
	}
	readV2(t, "chain.json", &v)
	var entries []wire.Signed
	for _, e := range v.Entries {
		s, err := wire.DecodeSignedV2([]byte(e.Signed.Signed))
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, s)
	}
	st, err := ValidateFor(wire.V2, entries)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != v.ID || st.V != wire.V2 {
		t.Fatalf("identifier %s, want %s", st.ID, v.ID)
	}
	checkState(t, "chain.json", st, v.Final)

	// Replaying entry by entry gives each signer, and the alert each would raise.
	st, _, err = GenesisFor(wire.V2, entries[0])
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range entries[1:] {
		a, err := st.Apply(s)
		if err != nil {
			t.Fatal(err)
		}
		recovery := strings.HasPrefix(v.Entries[i+1].Signer, "recovery_key_")
		if (a.Signer == SignerRecovery) != recovery {
			t.Fatalf("entry %d: signer %v, vector says %s", i+1, a.Signer, v.Entries[i+1].Signer)
		}
	}
	if !IsSelfRotation(&Applied{Entry: mustOpen(t, entries[3]), Key: ed25519.PublicKey(entries[3].K), Signer: SignerDevice}) {
		t.Fatal("entry 3 is a self-rotation")
	}

	// The same chain under wire version 1's rules doesn't validate: its signatures and
	// keys are composite.
	if _, err := Validate(entries); err == nil {
		t.Fatal("wire version 1 validated a version 2 chain")
	}
}

func mustOpen(t *testing.T, s wire.Signed) wire.ChainEntry {
	t.Helper()
	var e wire.ChainEntry
	if err := s.Open(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

// fork.json: the fork rule with no time limit, each case both ways round where it says.
func TestVectorForkV2(t *testing.T) {
	var v struct {
		Cases []struct {
			Name      string   `json:"name"`
			Cached    []string `json:"cached"`
			Candidate []string `json:"candidate"`
			Outcome   string   `json:"outcome"`
			ForkAt    uint64   `json:"fork_at"`
			Final     *v2State `json:"final_state"`
		} `json:"cases"`
		Entries map[string]struct {
			Signed v2Signed `json:"signed"`
		} `json:"entries"`
	}
	readV2(t, "fork.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no cases")
	}
	list := func(names []string) [][]byte {
		var out [][]byte
		for _, n := range names {
			e, ok := v.Entries[n]
			if !ok {
				t.Fatalf("no entry %q", n)
			}
			out = append(out, canonV2(t, e.Signed.Signed))
		}
		return out
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			st, out, at, err := ResolveFor(wire.V2, list(c.Cached), list(c.Candidate))
			switch c.Outcome {
			case "reject":
				if err == nil {
					t.Fatalf("accepted (outcome %v)", out)
				}
				return
			case "extends":
				if err != nil || out != Extends {
					t.Fatalf("got %v, %v; want extends", out, err)
				}
			case "same":
				if err != nil || out != Same {
					t.Fatalf("got %v, %v; want same", out, err)
				}
			case "fork":
				if err != nil || out != Fork || at != c.ForkAt {
					t.Fatalf("got %v at %d, %v; want fork at %d", out, at, err, c.ForkAt)
				}
			default:
				t.Fatalf("unknown outcome %q", c.Outcome)
			}
			if c.Final != nil {
				checkState(t, c.Name, st, *c.Final)
			}
		})
	}
}

// migrate.json, the version 2 side: a genesis that names its version 1 identity in
// migrated-from validates, and says so. Whether the version 1 chain's migrate links back
// is the migration's check (SPEC §6.8), not chain validation's.
func TestVectorMigratedFromGenesis(t *testing.T) {
	var v struct {
		Genesis v2Signed `json:"v2_genesis"`
		V1ID    string   `json:"v1_identity_id"`
		V2ID    string   `json:"v2_identity_id"`
	}
	readV2(t, "migrate.json", &v)
	s, err := wire.DecodeSignedV2([]byte(v.Genesis.Signed))
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := GenesisFor(wire.V2, s)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != v.V2ID || st.MigratedFrom != v.V1ID {
		t.Fatalf("got %s from %q, want %s from %s", st.ID, st.MigratedFrom, v.V2ID, v.V1ID)
	}
}

// v2World builds wire version 2 chains with fresh keys, for the rules the vectors don't reach.
type v2World struct {
	t    *testing.T
	devs []*wire.CompositePrivateKey
	rec  []*wire.CompositePrivateKey
	raw  [][]byte
	st   *State
}

func compKey(t *testing.T, seed byte) *wire.CompositePrivateKey {
	t.Helper()
	ml, ed := make([]byte, 32), make([]byte, 32)
	ml[0], ed[0], ed[1] = seed, seed, 1
	k, err := wire.NewCompositeKey(ml, ed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ed is a device's key: its composite key's Ed25519 component.
func ed(k *wire.CompositePrivateKey) wire.Bytes { return wire.Bytes(k.Public().Ed25519()) }

func commitTo(k *wire.CompositePrivateKey) []byte { return k.Public().Hash() }

func addOp(k *wire.CompositePrivateKey, name string) wire.Op {
	return wire.Op{Op: wire.OpAddDevice, Key: ed(k), Pub: k.Public().Bytes(), Name: name}
}

func newV2World(t *testing.T, extra ...wire.Op) *v2World {
	w := &v2World{t: t}
	for i := range 12 {
		w.devs = append(w.devs, compKey(t, byte(1+i)))
	}
	w.rec = []*wire.CompositePrivateKey{compKey(t, 100), compKey(t, 101)}
	handle := "kat.chat.example"
	ops := append([]wire.Op{
		addOp(w.devs[0], "Laptop"),
		{Op: wire.OpSetHome, Home: "chat.example"},
		{Op: wire.OpSetHandle, Handle: &handle},
		{Op: wire.OpSetRecovery, Next: commitTo(w.rec[0])},
	}, extra...)
	g := w.sign(wire.ChainEntry{TS: 1000, Ops: ops}, w.devs[0], false)
	st, _, err := GenesisFor(wire.V2, g)
	if err != nil {
		t.Fatal(err)
	}
	w.st = st
	w.raw = [][]byte{w.enc(g)}
	return w
}

func (w *v2World) sign(e wire.ChainEntry, k *wire.CompositePrivateKey, full bool) wire.Signed {
	w.t.Helper()
	var s wire.Signed
	var err error
	if full {
		s, err = wire.SignCompositeFull(wire.TypeChainEntry, e, k)
	} else {
		s, err = wire.SignComposite(wire.TypeChainEntry, e, k)
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *v2World) enc(s wire.Signed) []byte {
	b, err := s.Encode()
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// next builds the entry after the head, signed by k (with its whole key in k when full).
func (w *v2World) next(k *wire.CompositePrivateKey, full bool, ops ...wire.Op) wire.Signed {
	return w.sign(wire.ChainEntry{ID: w.st.ID, Seq: w.st.Seq + 1, Prev: w.st.Head, TS: w.st.HeadTS + 1, Ops: ops}, k, full)
}

// apply appends an entry that must be valid.
func (w *v2World) apply(s wire.Signed) {
	w.t.Helper()
	if _, err := w.st.Apply(s); err != nil {
		w.t.Fatal(err)
	}
	w.raw = append(w.raw, w.enc(s))
}

func TestV2DeviceCeiling(t *testing.T) {
	w := newV2World(t)
	for i := 1; i < MaxDevices; i++ {
		w.apply(w.next(w.devs[0], false, addOp(w.devs[i], "")))
	}
	if len(w.st.Devices) != MaxDevices {
		t.Fatalf("%d devices", len(w.st.Devices))
	}
	// An eleventh is invalid, from a device or from the recovery key.
	if _, err := w.st.Clone().Apply(w.next(w.devs[0], false, addOp(w.devs[10], ""))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("eleventh device: %v", err)
	}
	if _, err := w.st.Clone().Apply(w.next(w.rec[0], true, addOp(w.devs[10], ""), wire.Op{Op: wire.OpSetRecovery, Next: commitTo(w.rec[1])})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("eleventh device by recovery: %v", err)
	}
	// Ops apply in order: adding before removing goes over, removing first doesn't.
	if _, err := w.st.Clone().Apply(w.next(w.devs[1], false, addOp(w.devs[10], ""), wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[1])})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("add before remove: %v", err)
	}
	w.apply(w.next(w.devs[1], false, wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[1])}, addOp(w.devs[10], "")))
	// Re-adding a current device is invalid, even below the ceiling.
	if _, err := w.st.Clone().Apply(w.next(w.devs[0], false, addOp(w.devs[2], "renamed"))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("re-added device: %v", err)
	}
	w.apply(w.next(w.devs[0], false, wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[3])}))
	if _, err := w.st.Clone().Apply(w.next(w.devs[0], false, addOp(w.devs[2], "again"))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("re-added device below the ceiling: %v", err)
	}
	// The ceiling holds in genesis too.
	var extra []wire.Op
	for i := 1; i <= MaxDevices; i++ {
		extra = append(extra, addOp(compKey(t, byte(200+i)), ""))
	}
	g := newV2World(t)
	handle := "kat.chat.example"
	ops := append([]wire.Op{addOp(g.devs[0], ""), {Op: wire.OpSetHome, Home: "chat.example"}, {Op: wire.OpSetHandle, Handle: &handle}, {Op: wire.OpSetRecovery, Next: commitTo(g.rec[0])}}, extra...)
	if _, _, err := GenesisFor(wire.V2, g.sign(wire.ChainEntry{TS: 1, Ops: ops}, g.devs[0], false)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("genesis with 11 devices: %v", err)
	}
}

func TestV2EntryRules(t *testing.T) {
	w := newV2World(t)
	rot := wire.Op{Op: wire.OpSetRecovery, Next: commitTo(w.rec[1])}
	bad := func(name string, s wire.Signed) {
		t.Helper()
		if _, err := w.st.Clone().Apply(s); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// add-device's key has to be pub's Ed25519 component.
	mismatch := addOp(w.devs[1], "")
	mismatch.Key = ed(w.devs[2])
	bad("key doesn't match pub", w.next(w.devs[0], false, mismatch))
	noPub := addOp(w.devs[1], "")
	noPub.Pub = nil
	bad("add-device without pub", w.next(w.devs[0], false, noPub))
	// A device signs with its composite key, named by its component; not with its whole
	// key in k, and not as a stranger.
	bad("device with its whole key in k", w.next(w.devs[0], true, addOp(w.devs[1], "")))
	bad("stranger", w.next(w.devs[5], false, addOp(w.devs[1], "")))
	// The recovery key reveals its whole key, which has to match the commitment.
	bad("recovery named by its component", w.next(w.rec[0], false, rot))
	bad("uncommitted recovery key", w.next(w.rec[1], true, wire.Op{Op: wire.OpSetRecovery, Next: commitTo(w.rec[0])}))
	bad("recovery without a new commitment", w.next(w.rec[0], true, addOp(w.devs[1], "")))
	bad("set-recovery by a device", w.next(w.devs[0], false, rot))
	bad("recovery recommits to the key it spends", w.next(w.rec[0], true, wire.Op{Op: wire.OpSetRecovery, Next: commitTo(w.rec[0])}))
	bad("recovery commits to the key it spends, then a new one", w.next(w.rec[0], true, wire.Op{Op: wire.OpSetRecovery, Next: commitTo(w.rec[0])}, rot))
	// add-device's key has to be a valid Ed25519 public key under SPEC §4.3 (§6.4 rule 6):
	// canonical, and not of small order, even with the sign bit set.
	for name, key := range invalidEd25519Keys() {
		bad("add-device of a "+name+" key", w.next(w.devs[0], false, withEd25519(w.devs[1], key)))
		g := newV2World(t)
		handle := "kat.chat.example"
		ops := []wire.Op{addOp(g.devs[0], ""), withEd25519(g.devs[1], key), {Op: wire.OpSetHome, Home: "chat.example"}, {Op: wire.OpSetHandle, Handle: &handle}, {Op: wire.OpSetRecovery, Next: commitTo(g.rec[0])}}
		if _, _, err := GenesisFor(wire.V2, g.sign(wire.ChainEntry{TS: 1, Ops: ops}, g.devs[0], false)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("genesis adding a %s key: %v", name, err)
		}
	}
	// migrated-from appears only in genesis.
	v1 := "tr:aaaaaaaaaaaaaaaaaaaaaaaa"
	bad("migrated-from after genesis", w.next(w.devs[0], false, wire.Op{Op: wire.OpMigratedFrom, ID: &v1}))
	// An Ed25519 signature alone, even by the device's own component, isn't a chain entry's.
	edOnly := w.next(w.devs[0], false, addOp(w.devs[1], ""))
	edOnly.S = make([]byte, 64)
	bad("Ed25519-only signature", edOnly)
	// Closed ops (SPEC §20.2): pub belongs only to add-device, id only to migrated-from.
	stray := wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[0]), Pub: w.devs[0].Public().Bytes()}
	bad("pub on remove-device", w.next(w.devs[0], false, addOp(w.devs[1], ""), stray))

	// What's valid: a recovery entry adds a device and recommits.
	w.apply(w.next(w.rec[0], true, addOp(w.devs[1], "Phone"), rot))
	if !w.st.HasDevice(ed(w.devs[1])) || hex.EncodeToString(w.st.RecoveryCommit) != hex.EncodeToString(commitTo(w.rec[1])) {
		t.Fatal("recovery entry didn't apply")
	}
	// A removed device loses its composite key with its place.
	w.apply(w.next(w.devs[1], false, wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[0])}))
	if w.st.DevicePub(ed(w.devs[0])) != nil {
		t.Fatal("removed device kept its composite key")
	}
	bad("removed device", w.next(w.devs[0], false, addOp(w.devs[2], "")))
}

// invalidEd25519Keys are 32-byte encodings no Ed25519 public key may have (SPEC §4.3).
func invalidEd25519Keys() map[string][]byte {
	identity := make([]byte, 32)
	identity[0] = 1
	signed := bytes.Clone(identity)
	signed[31] = 0x80
	yIsP := bytes.Repeat([]byte{0xff}, 32)
	yIsP[0], yIsP[31] = 0xed, 0x7f
	return map[string][]byte{"small-order": identity, "small-order, sign bit set,": signed, "non-canonical": yIsP, "zero": make([]byte, 32)}
}

// withEd25519 is an add-device of k's composite key with its Ed25519 component replaced by
// key, and key matching it.
func withEd25519(k *wire.CompositePrivateKey, key []byte) wire.Op {
	pub := k.Public().Bytes()
	copy(pub[len(pub)-32:], key)
	return wire.Op{Op: wire.OpAddDevice, Key: wire.Bytes(key), Pub: pub}
}

func TestV2Genesis(t *testing.T) {
	w := newV2World(t)
	handle := "kat.chat.example"
	base := func() []wire.Op {
		return []wire.Op{addOp(w.devs[0], ""), {Op: wire.OpSetHome, Home: "chat.example"}, {Op: wire.OpSetHandle, Handle: &handle}, {Op: wire.OpSetRecovery, Next: commitTo(w.rec[0])}}
	}
	gen := func(ops []wire.Op, k *wire.CompositePrivateKey, full bool) error {
		_, _, err := GenesisFor(wire.V2, w.sign(wire.ChainEntry{TS: 1, Ops: ops}, k, full))
		return err
	}
	if err := gen(base(), w.devs[1], false); err == nil {
		t.Fatal("genesis signed by a device it doesn't add")
	}
	if err := gen(base(), w.devs[0], true); err == nil {
		t.Fatal("genesis with the whole key in k")
	}
	if err := gen(base()[:3], w.devs[0], false); err == nil {
		t.Fatal("genesis without set-recovery")
	}
	// A genesis carries no remove-device, even of a device it adds, its signer or another.
	for i := range 2 {
		ops := append(base(), addOp(w.devs[1], ""), wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[i])})
		if err := gen(ops, w.devs[0], false); !errors.Is(err, ErrInvalid) {
			t.Fatalf("genesis removing device %d: %v", i, err)
		}
	}
	v1 := "tr:aaaaaaaaaaaaaaaaaaaaaaaa"
	if err := gen(append(base(), wire.Op{Op: wire.OpMigratedFrom, ID: &v1}), w.devs[0], false); err != nil {
		t.Fatalf("genesis with migrated-from: %v", err)
	}
	if err := gen(append(base(), wire.Op{Op: wire.OpMigratedFrom, ID: &v1}, wire.Op{Op: wire.OpMigratedFrom, ID: &v1}), w.devs[0], false); err == nil {
		t.Fatal("genesis with two migrated-from")
	}
	bad := "tr:short"
	if err := gen(append(base(), wire.Op{Op: wire.OpMigratedFrom, ID: &bad}), w.devs[0], false); err == nil {
		t.Fatal("migrated-from without a valid identifier")
	}
	// Wire version 1 doesn't know migrated-from, or pub.
	if err := (wire.Op{Op: wire.OpAddDevice, Key: ed(w.devs[0]), Pub: w.devs[0].Public().Bytes()}).Check(); err == nil {
		t.Fatal("version 1 took pub")
	}
	st := &State{V: wire.V1, Devices: map[string]string{}}
	if err := st.applyOp(wire.Op{Op: wire.OpMigratedFrom, ID: &v1}, true); !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("version 1 migrated-from: %v", err)
	}
}

// The fork rule's other half, with entries the vectors don't have: a recovery fork
// replaces a device branch however old it is, from either side, and never a branch with
// a recovery-signed entry in it.
func TestV2ForkAnyAge(t *testing.T) {
	w := newV2World(t)
	w.apply(w.next(w.devs[0], false, addOp(w.devs[1], "Phone")))
	base := slices.Clone(w.raw)
	baseSt := w.st.Clone()

	// A thief's branch, followed years later by the owner's recovery fork.
	theft := w.next(w.devs[1], false, wire.Op{Op: wire.OpSetHome, Home: "evil.example"}, wire.Op{Op: wire.OpRemoveDevice, Key: ed(w.devs[0])})
	w.apply(theft)
	devBranch := slices.Clone(w.raw)

	w.st, w.raw = baseSt.Clone(), slices.Clone(base)
	r := w.sign(wire.ChainEntry{ID: w.st.ID, Seq: w.st.Seq + 1, Prev: w.st.Head, TS: w.st.HeadTS + 5*365*24*3600, Ops: []wire.Op{{Op: wire.OpRemoveDevice, Key: ed(w.devs[1])}, {Op: wire.OpSetRecovery, Next: commitTo(w.rec[1])}}}, w.rec[0], true)
	w.apply(r)
	recBranch := slices.Clone(w.raw)

	st, out, at, err := ResolveFor(wire.V2, devBranch, recBranch)
	if err != nil || out != Fork || at != 2 || st.HasDevice(ed(w.devs[1])) {
		t.Fatalf("recovery fork: %v at %d, %v", out, at, err)
	}
	if _, _, _, err := ResolveFor(wire.V2, recBranch, devBranch); err == nil {
		t.Fatal("the overridden device branch came back")
	}
	// Version 1's rules don't take version 2 chains at all.
	if _, _, _, err := Resolve(devBranch, recBranch); err == nil {
		t.Fatal("version 1 rules accepted a version 2 chain")
	}
}
