// Package chain validates identity chains (SPEC §6.2 to §6.4).
//
// Validate checks one linear chain. Resolve decides between a cached chain and a
// new one, including recovery forks (the fork rule, SPEC §6.4.1). Both speak wire
// version 1; ValidateFor and ResolveFor take the wire version, and version 2 chains
// (composite keys, the 10-device ceiling, recovery forks of any age) follow its rules.
//
// A version 1 chain can end in `migrate`, which names the version 2 identity it became
// (SPEC §6.8): nothing can follow it, and Linked checks the pair. A recovery-signed fork
// from the migrate's position or before overrides a device-signed migrate.
package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ErrInvalid wraps every validation failure. Callers map it to "invalid-chain".
var ErrInvalid = errors.New("invalid chain")

// ErrUnknownOp is an op this version doesn't know. It also matches ErrInvalid.
// Callers map it to "unknown-kind" (SPEC §20.2).
var ErrUnknownOp = errors.New("unknown op")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// State is an identity's current state after applying its chain.
type State struct {
	V              int // wire version: wire.V1 or wire.V2
	ID             string
	Seq            uint64 // seq of the head
	Head           []byte // SHA-256 of the encoded head envelope
	HeadTS         uint64
	Devices        map[string]string // hex(device key) -> name
	Home           string
	Handle         string // "" if cleared
	RecoveryCommit []byte // SHA-256 of the next recovery public key
	// Wire version 2: each current device's composite public key, by hex(device key),
	// which is the key's Ed25519 component (SPEC §6.3).
	Pubs map[string]*wire.CompositePublicKey
	// Wire version 2: the version 1 identity this one migrated from, named in genesis
	// (SPEC §6.8), or "". Whether the version 1 side links back is Linked's question.
	MigratedFrom string
	// Wire version 1: the hash of the version 2 genesis a `migrate` named, or nil. A chain
	// with one is closed: no entry can follow it (SPEC §6.8).
	MigratedTo []byte
	// GenesisHash is the hash of the genesis entry (SPEC §4.3), which a `migrate` names.
	GenesisHash []byte
}

// Closed reports whether a wire version 1 chain ended in `migrate` (SPEC §6.8).
func (st *State) Closed() bool { return st.MigratedTo != nil }

// MigratedID is the version 2 identifier a closed version 1 chain migrated to, or "".
func (st *State) MigratedID() string {
	if st.MigratedTo == nil {
		return ""
	}
	return wire.IdentityIDFromHash(st.MigratedTo)
}

// Linked reports whether a wire version 1 identity and a version 2 one are the same person
// (SPEC §6.8): the version 1 chain ends in a `migrate` naming the version 2 genesis's hash,
// and that genesis names the version 1 identifier in `migrated-from`. Both chains have to
// have validated, each under its own version's rules, to give these states.
func Linked(v1, v2 *State) bool {
	return v1 != nil && v2 != nil && v1.V == wire.V1 && v2.V == wire.V2 &&
		v1.MigratedTo != nil && bytes.Equal(v1.MigratedTo, v2.GenesisHash) && v2.MigratedFrom == v1.ID
}

// MaxDevices is how many current devices a wire version 2 identity may have (SPEC §6.4 rule 4).
const MaxDevices = 10

// DevicePub returns a current device's composite public key (wire version 2), or nil.
func (st *State) DevicePub(key []byte) *wire.CompositePublicKey {
	return st.Pubs[hex.EncodeToString(key)]
}

// HasDevice reports whether key is a current device.
func (st *State) HasDevice(key []byte) bool {
	_, ok := st.Devices[hex.EncodeToString(key)]
	return ok
}

// Signer says what authorized an entry.
type Signer int

const (
	SignerDevice Signer = iota
	SignerRecovery
)

// Applied describes one successfully applied entry.
type Applied struct {
	Entry wire.ChainEntry
	// Key is the signer's key as the envelope's k names it: a device key (in wire version 2,
	// its Ed25519 component), or a recovery key (in version 2, the whole composite key).
	Key    ed25519.PublicKey
	Signer Signer
}

// openEntry decodes a chain entry as a closed schema: unknown members, in the entry or
// in any op, are rejected, so every implementation computes the same state (SPEC §20.2).
func openEntry(v int, s wire.Signed) (wire.ChainEntry, error) {
	var e wire.ChainEntry
	if err := s.OpenClosed(&e); err != nil {
		return e, err
	}
	for _, op := range e.Ops {
		check := op.Check
		if v == wire.V2 {
			check = op.CheckV2
		}
		if err := check(); err != nil {
			return e, err
		}
	}
	if v == wire.V2 {
		if err := checkHandlesV2(s, e); err != nil {
			return e, err
		}
	}
	return e, nil
}

// checkHandlesV2 enforces that a set-handle's handle is a non-empty string or null: an
// empty or missing handle is invalid (SPEC §6.4 rule 6). Op decodes a missing handle and
// null alike, so this looks at the members themselves.
func checkHandlesV2(s wire.Signed, e wire.ChainEntry) error {
	var raw struct {
		Ops []map[string]json.RawMessage `json:"ops"`
	}
	if err := json.Unmarshal([]byte(s.B), &raw); err != nil || len(raw.Ops) != len(e.Ops) {
		return errors.New("ops don't decode")
	}
	for i, op := range e.Ops {
		if op.Op != wire.OpSetHandle {
			continue
		}
		if _, ok := raw.Ops[i]["handle"]; !ok {
			return errors.New("set-handle without handle")
		}
		if op.Handle != nil && *op.Handle == "" {
			return errors.New("set-handle with an empty handle")
		}
	}
	return nil
}

// GenesisFor is Genesis under wire version v's rules.
func GenesisFor(v int, s wire.Signed) (*State, *Applied, error) {
	if v == wire.V2 {
		return genesisV2(s)
	}
	return Genesis(s)
}

// genesisV2 validates a wire version 2 genesis (SPEC §6.2, §6.4 rule 1): k is the Ed25519
// component of a device that genesis adds, and the composite key in that add-device signs.
func genesisV2(s wire.Signed) (*State, *Applied, error) {
	if s.KID != "" || len(s.K) != ed25519.PublicKeySize {
		return nil, nil, invalid("genesis must be signed by the device key it adds")
	}
	e, err := openEntry(wire.V2, s)
	if err != nil {
		return nil, nil, invalid("genesis body: %v", err)
	}
	if e.Seq != 0 || e.ID != "" || e.Prev != nil {
		return nil, nil, invalid("genesis must have seq 0 and no id or prev")
	}
	enc, err := s.Encode()
	if err != nil {
		return nil, nil, err
	}
	st := &State{V: wire.V2, ID: wire.IdentityID(enc), Devices: map[string]string{}, Pubs: map[string]*wire.CompositePublicKey{}}
	var sawDevice, sawHome, sawHandle, sawRecovery, sawMigrated bool
	for _, op := range e.Ops {
		switch op.Op {
		case wire.OpAddDevice:
			sawDevice = true
		case wire.OpSetHome:
			sawHome = true
		case wire.OpSetHandle:
			sawHandle = true
		case wire.OpSetRecovery:
			sawRecovery = true
		case wire.OpRemoveDevice:
			// Nothing comes before genesis to remove, and removing a device it adds could
			// leave out its signer, or every device (SPEC §6.4 rule 6).
			return nil, nil, invalid("genesis can't carry remove-device")
		case wire.OpMigratedFrom:
			// One version 1 identity at most: two would make the pair ambiguous (SPEC §6.8).
			if sawMigrated {
				return nil, nil, invalid("genesis names more than one migrated-from identity")
			}
			sawMigrated = true
		}
		if err := st.applyOp(op, true); err != nil {
			return nil, nil, err
		}
	}
	if !sawDevice || !sawHome || !sawHandle || !sawRecovery {
		return nil, nil, invalid("genesis needs add-device, set-home, set-handle, and set-recovery")
	}
	pub := st.DevicePub(s.K)
	if pub == nil {
		return nil, nil, invalid("genesis must be signed by the device it adds")
	}
	if err := s.VerifyComposite(wire.TypeChainEntry, pub); err != nil {
		return nil, nil, invalid("genesis signature: %v", err)
	}
	st.finish(e, enc)
	return st, &Applied{Entry: e, Key: ed25519.PublicKey(s.K), Signer: SignerDevice}, nil
}

// Genesis validates a wire version 1 genesis envelope and returns the starting state
// (SPEC §6.2, §6.4 rule 1).
func Genesis(s wire.Signed) (*State, *Applied, error) {
	key, err := s.VerifySelf(wire.TypeChainEntry)
	if err != nil {
		return nil, nil, invalid("genesis signature: %v", err)
	}
	e, err := openEntry(wire.V1, s)
	if err != nil {
		return nil, nil, invalid("genesis body: %v", err)
	}
	if e.Seq != 0 || e.ID != "" || e.Prev != nil {
		return nil, nil, invalid("genesis must have seq 0 and no id or prev")
	}
	enc, err := s.Encode()
	if err != nil {
		return nil, nil, err
	}
	st := &State{V: wire.V1, ID: wire.IdentityID(enc), Devices: map[string]string{}}

	var sawDevice, sawHome, sawHandle, sawRecovery, signerAdded bool
	for _, op := range e.Ops {
		switch op.Op {
		case wire.OpAddDevice:
			sawDevice = true
			if bytes.Equal(op.Key, key) {
				signerAdded = true
			}
		case wire.OpSetHome:
			sawHome = true
		case wire.OpSetHandle:
			sawHandle = true
		case wire.OpSetRecovery:
			sawRecovery = true
		}
		if err := st.applyOp(op, true); err != nil {
			return nil, nil, err
		}
	}
	if !sawDevice || !sawHome || !sawHandle || !sawRecovery {
		return nil, nil, invalid("genesis needs add-device, set-home, set-handle, and set-recovery")
	}
	if !signerAdded {
		return nil, nil, invalid("genesis must be signed by the device it adds")
	}
	st.finish(e, enc)
	return st, &Applied{Entry: e, Key: key, Signer: SignerDevice}, nil
}

// Apply validates s as the next entry and applies it (SPEC §6.4 rules 2 to 5,
// except the clock checks, which depend on context: see CheckClock), under the rules of
// the chain's wire version. On error, st is unchanged.
func (st *State) Apply(s wire.Signed) (*Applied, error) {
	if st.V == wire.V2 {
		return st.applyV2(s)
	}
	if st.Closed() {
		return nil, invalid("seq %d follows migrate, which closes the chain", st.Seq+1)
	}
	key, err := s.VerifySelf(wire.TypeChainEntry)
	if err != nil {
		return nil, invalid("seq %d signature: %v", st.Seq+1, err)
	}
	e, err := openEntry(wire.V1, s)
	if err != nil {
		return nil, invalid("body: %v", err)
	}
	if err := st.checkLink(e); err != nil {
		return nil, err
	}
	signer := SignerDevice
	recovery := sha256.Sum256(key)
	switch {
	case bytes.Equal(recovery[:], st.RecoveryCommit):
		signer = SignerRecovery
	case st.HasDevice(key):
		// fine
	default:
		return nil, invalid("signer is neither a current device nor the committed recovery key")
	}
	if err := checkMigrateAlone(e, signer); err != nil {
		return nil, err
	}
	return st.applyEntry(s, e, key, signer)
}

// checkMigrateAlone enforces that an entry with `migrate` carries no other op, except the
// `set-recovery` a recovery-signed entry has to carry (SPEC §6.8).
func checkMigrateAlone(e wire.ChainEntry, signer Signer) error {
	has := false
	for _, op := range e.Ops {
		has = has || op.Op == wire.OpMigrate
	}
	if !has {
		return nil
	}
	for _, op := range e.Ops {
		if op.Op != wire.OpMigrate && (op.Op != wire.OpSetRecovery || signer != SignerRecovery) {
			return invalid("seq %d: an entry with migrate carries no other op, except a recovery-signed entry's set-recovery", e.Seq)
		}
	}
	return nil
}

// applyV2 is Apply for wire version 2 (SPEC §3.2.2, §6.3): a device names itself in k by
// its 32-byte Ed25519 component, and signs with the composite key the chain holds for it;
// the recovery key reveals its whole composite key in k, whose hash is the commitment.
func (st *State) applyV2(s wire.Signed) (*Applied, error) {
	if s.KID != "" {
		return nil, invalid("seq %d is signed with a server key", st.Seq+1)
	}
	e, err := openEntry(wire.V2, s)
	if err != nil {
		return nil, invalid("body: %v", err)
	}
	if err := st.checkLink(e); err != nil {
		return nil, err
	}
	var signer Signer
	switch len(s.K) {
	case ed25519.PublicKeySize:
		pub := st.DevicePub(s.K)
		if pub == nil {
			return nil, invalid("signer is neither a current device nor the committed recovery key")
		}
		if err := s.VerifyComposite(wire.TypeChainEntry, pub); err != nil {
			return nil, invalid("seq %d signature: %v", e.Seq, err)
		}
		signer = SignerDevice
	case wire.CompositePublicKeySize:
		commit := sha256.Sum256(s.K)
		if !bytes.Equal(commit[:], st.RecoveryCommit) {
			return nil, invalid("signer is neither a current device nor the committed recovery key")
		}
		if _, err := s.VerifyCompositeSelf(wire.TypeChainEntry); err != nil {
			return nil, invalid("seq %d signature: %v", e.Seq, err)
		}
		// The key is spent once it's revealed (SPEC §6.3): committing to it again would
		// authorize a public key.
		for _, op := range e.Ops {
			if op.Op == wire.OpSetRecovery && bytes.Equal(op.Next, commit[:]) {
				return nil, invalid("a recovery entry can't commit to the key it spends")
			}
		}
		signer = SignerRecovery
	default:
		return nil, invalid("signer is neither a current device nor the committed recovery key")
	}
	return st.applyEntry(s, e, ed25519.PublicKey(s.K), signer)
}

// checkLink checks an entry's place after the head (SPEC §6.4 rule 2, and the ordering half
// of rule 5).
func (st *State) checkLink(e wire.ChainEntry) error {
	switch {
	case e.ID != st.ID:
		return invalid("id %q doesn't match %q", e.ID, st.ID)
	case e.Seq != st.Seq+1:
		return invalid("seq %d, want %d", e.Seq, st.Seq+1)
	case !bytes.Equal(e.Prev, st.Head):
		return invalid("prev doesn't match the head")
	case e.TS < st.HeadTS:
		return invalid("ts goes backwards")
	case len(e.Ops) == 0:
		return invalid("no ops")
	}
	return nil
}

// applyEntry applies an entry whose signer has been checked (SPEC §6.4 rules 3 and 4).
func (st *State) applyEntry(s wire.Signed, e wire.ChainEntry, key ed25519.PublicKey, signer Signer) (*Applied, error) {
	next := st.clone()
	sawRecovery := false
	for _, op := range e.Ops {
		if op.Op == wire.OpSetRecovery {
			sawRecovery = true
			if signer != SignerRecovery {
				return nil, invalid("set-recovery must be signed by the recovery key")
			}
		}
		if err := next.applyOp(op, false); err != nil {
			return nil, err
		}
	}
	if signer == SignerRecovery && !sawRecovery {
		return nil, invalid("a recovery-signed entry must commit to the next recovery key")
	}
	if len(next.Devices) == 0 {
		return nil, invalid("no devices left")
	}
	enc, err := s.Encode()
	if err != nil {
		return nil, err
	}
	next.finish(e, enc)
	*st = *next
	return &Applied{Entry: e, Key: key, Signer: signer}, nil
}

// Validate applies a whole wire version 1 chain, genesis first.
func Validate(entries []wire.Signed) (*State, error) { return ValidateFor(wire.V1, entries) }

// ValidateFor applies a whole chain, genesis first, under wire version v's rules.
func ValidateFor(v int, entries []wire.Signed) (*State, error) {
	if len(entries) == 0 {
		return nil, invalid("empty chain")
	}
	st, _, err := GenesisFor(v, entries[0])
	if err != nil {
		return nil, err
	}
	for _, s := range entries[1:] {
		if _, err := st.Apply(s); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// applyOp applies one op. genesis says whether it's in the genesis entry.
func (st *State) applyOp(op wire.Op, genesis bool) error {
	switch op.Op {
	case wire.OpAddDevice:
		if len(op.Key) != ed25519.PublicKeySize {
			return invalid("add-device key size")
		}
		k := hex.EncodeToString(op.Key)
		if st.V == wire.V2 {
			// pub is the composite key, and key its Ed25519 component (SPEC §6.3).
			pub, err := wire.ParseCompositePublicKey(op.Pub)
			if err != nil || !bytes.Equal(pub.Ed25519(), op.Key) {
				return invalid("add-device key doesn't match its pub")
			}
			// And it's a valid Ed25519 public key under SPEC §4.3, canonical and not of
			// small order (§6.4 rule 6): no signature could ever verify under anything else.
			if !wire.Canonical25519(op.Key) || wire.SmallOrder(op.Key) {
				return invalid("add-device key isn't a valid Ed25519 public key")
			}
			// A key that's already a device can't be added again: that would swap its
			// composite key under the same name. Then the 10-device ceiling, op by op
			// (SPEC §6.4 rule 4).
			if _, ok := st.Devices[k]; ok {
				return invalid("add-device of a key that's already a current device")
			}
			if len(st.Devices) >= MaxDevices {
				return invalid("add-device would make more than %d current devices", MaxDevices)
			}
			st.Pubs[k] = pub
		}
		st.Devices[k] = op.Name
	case wire.OpRemoveDevice:
		k := hex.EncodeToString(op.Key)
		if _, ok := st.Devices[k]; !ok {
			return invalid("remove-device of a device that isn't current")
		}
		delete(st.Devices, k)
		delete(st.Pubs, k)
	case wire.OpSetHome:
		if op.Home == "" {
			return invalid("set-home without home")
		}
		st.Home = op.Home
	case wire.OpSetHandle:
		if op.Handle == nil {
			st.Handle = ""
		} else {
			st.Handle = *op.Handle
		}
	case wire.OpSetRecovery:
		if len(op.Next) != sha256.Size {
			return invalid("set-recovery commitment size")
		}
		st.RecoveryCommit = append([]byte(nil), op.Next...)
	case wire.OpMigrate:
		// Wire version 1, never in genesis, at most once, and last: the chain is closed
		// after it (SPEC §6.8).
		if st.V != wire.V1 {
			return fmt.Errorf("%w: %w %q", ErrInvalid, ErrUnknownOp, op.Op)
		}
		if genesis {
			return invalid("migrate can't be in genesis")
		}
		if st.Closed() {
			return invalid("more than one migrate")
		}
		if len(op.To) != sha256.Size {
			return invalid("migrate needs the hash of a version 2 genesis")
		}
		st.MigratedTo = append([]byte(nil), op.To...)
	case wire.OpMigratedFrom:
		// Wire version 2, and only in genesis (SPEC §6.4 rule 4, §6.8).
		if st.V != wire.V2 {
			return fmt.Errorf("%w: %w %q", ErrInvalid, ErrUnknownOp, op.Op)
		}
		if !genesis {
			return invalid("migrated-from appears only in genesis")
		}
		if op.ID == nil || !wire.ValidIdentityID(*op.ID) {
			return invalid("migrated-from needs a version 1 identifier")
		}
		st.MigratedFrom = *op.ID
	default:
		return fmt.Errorf("%w: %w %q", ErrInvalid, ErrUnknownOp, op.Op)
	}
	return nil
}

func (st *State) finish(e wire.ChainEntry, enc []byte) {
	sum := sha256.Sum256(enc)
	st.Seq, st.Head, st.HeadTS = e.Seq, sum[:], e.TS
	if e.Seq == 0 {
		st.GenesisHash = st.Head
	}
}

// Clone returns a deep copy of st.
func (st *State) Clone() *State { return st.clone() }

func (st *State) clone() *State {
	c := *st
	c.Devices = make(map[string]string, len(st.Devices))
	for k, v := range st.Devices {
		c.Devices[k] = v
	}
	c.Head = append([]byte(nil), st.Head...)
	c.RecoveryCommit = append([]byte(nil), st.RecoveryCommit...)
	c.MigratedTo = bytes.Clone(st.MigratedTo)
	if st.Pubs != nil {
		c.Pubs = make(map[string]*wire.CompositePublicKey, len(st.Pubs))
		for k, v := range st.Pubs {
			c.Pubs[k] = v // immutable
		}
	}
	return &c
}

// MaxSkew is the allowed clock difference for chain entries (SPEC §6.4 rule 5).
const MaxSkew = 600 // seconds

// CheckClock applies SPEC §6.4 rule 5. Everyone rejects entries too far in the
// future. Only the homeserver accepting an append (appending = true) also
// rejects entries too far in the past.
func CheckClock(ts, now uint64, appending bool) error {
	if ts > now+MaxSkew {
		return invalid("ts more than 10 minutes in the future")
	}
	if appending && ts+MaxSkew < now {
		return invalid("ts more than 10 minutes in the past")
	}
	return nil
}

// AlertLevel says what a just-applied entry should trigger (SPEC §6.4.1).
type AlertLevel int

const (
	AlertNone AlertLevel = iota
	AlertNotice
	AlertAlarm
)

// Alert classifies an applied entry. Device-signed set-home, remove-device, or migrate
// (SPEC §6.8, which hands the identity to a version 2 one) is an alarm, except a self-rotation (remove own key + add one new key, nothing
// else, signed by the removed key), which is a calm notice. A device-signed
// add-device is also a notice, so a device slipped in by a phished approval
// doesn't go unnoticed (spec/api/client-stage3.md).
func Alert(a *Applied) AlertLevel {
	// Genesis sets a home and handle, but there's nobody to warn yet.
	if a.Entry.Seq == 0 || a.Signer != SignerDevice {
		return AlertNone
	}
	risky, added := false, false
	for _, op := range a.Entry.Ops {
		switch op.Op {
		case wire.OpSetHome, wire.OpRemoveDevice, wire.OpMigrate:
			risky = true
		case wire.OpAddDevice:
			added = true
		}
	}
	switch {
	case risky && !IsSelfRotation(a):
		return AlertAlarm
	case risky, added:
		return AlertNotice
	}
	return AlertNone
}

// IsSelfRotation reports whether an entry is exactly [remove-device K, add-device K'] signed by K.
func IsSelfRotation(a *Applied) bool {
	ops := a.Entry.Ops
	if a.Signer != SignerDevice || len(ops) != 2 {
		return false
	}
	var removed, added bool
	for _, op := range ops {
		switch op.Op {
		case wire.OpRemoveDevice:
			removed = bytes.Equal(op.Key, a.Key)
		case wire.OpAddDevice:
			added = !bytes.Equal(op.Key, a.Key)
		}
	}
	return removed && added
}

// ForkWindow is how far back a recovery-signed entry can override device changes in wire
// version 1. Wire version 2 has no limit: a recovery-signed entry overrides device-signed
// entries of any age (SPEC §6.4.1).
const ForkWindow = 72 * 3600 // seconds

// Outcome says how a candidate chain relates to the cached one.
type Outcome int

const (
	Same    Outcome = iota // the candidate adds nothing: equal to, or a prefix of, the cache
	Extends                // the candidate extends the cache
	Fork                   // the candidate is a valid recovery fork that replaces part of the cache
)

// Resolve checks a candidate chain against a cached one (SPEC §6.5, §6.4.1).
// Both are encoded `signed` envelopes, genesis first. An empty cache accepts any
// valid candidate. The candidate is accepted if it extends the cache, or if it
// forks from it with a recovery-signed entry R where every cached entry R overrides
// is device-signed and at most ForkWindow older than R. Anything else is ErrInvalid,
// including a stale fork trying to replace a recovery branch.
//
// st is the state of the chain to keep. For Fork, at is the first replaced seq.
//
// That's wire version 1's rule. ResolveFor takes the wire version.
func Resolve(cached, candidate [][]byte) (st *State, out Outcome, at uint64, err error) {
	return ResolveFor(wire.V1, cached, candidate)
}

// ResolveFor is Resolve under wire version v's rules. In version 2, the fork rule has no
// time limit (SPEC §6.4.1): a recovery-signed entry overrides device-signed entries of any
// age, whichever branch arrived first, and never a recovery-signed one (two recovery-signed
// branches keep the first seen).
func ResolveFor(v int, cached, candidate [][]byte) (st *State, out Outcome, at uint64, err error) {
	cand, err := decodeAll(v, candidate)
	if err != nil {
		return nil, 0, 0, err
	}
	candSt, err := ValidateFor(v, cand)
	if err != nil {
		return nil, 0, 0, err
	}
	if len(cached) == 0 {
		return candSt, Extends, 0, nil
	}
	p := 0
	for p < len(cached) && p < len(candidate) && bytes.Equal(cached[p], candidate[p]) {
		p++
	}
	switch {
	case p == 0:
		return nil, 0, 0, invalid("different genesis")
	case p == len(candidate):
		old, err := decodeAll(v, cached)
		if err != nil {
			return nil, 0, 0, err
		}
		cachedSt, err := ValidateFor(v, old)
		return cachedSt, Same, 0, err
	case p == len(cached):
		return candSt, Extends, 0, nil
	}

	// A fork at seq p. The candidate's entry p must be recovery-signed...
	base, err := ValidateFor(v, cand[:p])
	if err != nil {
		return nil, 0, 0, err
	}
	r := base.clone()
	ra, err := r.Apply(cand[p])
	if err != nil {
		return nil, 0, 0, err
	}
	old, err := decodeAll(v, cached[p:])
	if err != nil {
		return nil, 0, 0, err
	}
	if ra.Signer != SignerRecovery && v == wire.V2 {
		// The cache holds the other branch. A device-signed branch never overrides anything,
		// and a recovery-signed entry in the cache stands against it, whatever its age.
		return nil, 0, 0, invalid("conflicting entry at seq %d isn't recovery-signed", p)
	}
	if ra.Signer != SignerRecovery {
		// The other way round: the cache holds the recovery fork, and the candidate is the
		// device branch it would override. Which one stands doesn't depend on which arrived
		// first: if the recovery entry couldn't have overridden these device
		// entries, they're final, and the recovery entry was made on a copy that missed them.
		if err := overrides(base, old[0], cand[p:], true); err == nil {
			return nil, 0, 0, invalid("seq %d: the cached recovery entry overrides this branch", p)
		} else if !errors.Is(err, errTooOld) {
			return nil, 0, 0, invalid("conflicting entry at seq %d isn't recovery-signed", p)
		}
		return candSt, Fork, uint64(p), nil
	}
	// ...and everything it overrides must be device changes: recent ones, in version 1.
	if err := overrides(base, cand[p], old, v != wire.V2); err != nil {
		return nil, 0, 0, err
	}
	return candSt, Fork, uint64(p), nil
}

var errTooOld = invalid("the device branch is more than 72 hours older than the recovery entry")

// overrides checks the fork rule (SPEC §6.4.1) for a recovery-signed entry r forking from
// base over branch: every entry in branch has to be device-signed, and with window, at most
// ForkWindow older than r (wire version 1). A device-signed migrate is overridden whatever
// its age (SPEC §6.8): the recovery code outranks it, whichever branch came first. It
// returns errTooOld when the only problem is age, which makes the branch final; any other
// error means r isn't a recovery entry, or branch holds one (a leaked code).
func overrides(base *State, r wire.Signed, branch []wire.Signed, window bool) error {
	rs := base.clone()
	ra, err := rs.Apply(r)
	if err != nil {
		return err
	}
	if ra.Signer != SignerRecovery {
		return invalid("conflicting entry at seq %d isn't recovery-signed", ra.Entry.Seq)
	}
	o := base.clone()
	tooOld := false
	for _, s := range branch {
		a, err := o.Apply(s)
		if err != nil {
			return err
		}
		if a.Signer != SignerDevice {
			return invalid("seq %d is recovery-signed and can't be overridden (has the recovery code leaked?)", a.Entry.Seq)
		}
		if window && !o.Closed() && a.Entry.TS+ForkWindow < ra.Entry.TS {
			tooOld = true
		}
	}
	if tooOld {
		return errTooOld
	}
	return nil
}

func decodeAll(v int, raw [][]byte) ([]wire.Signed, error) {
	out := make([]wire.Signed, len(raw))
	for i, b := range raw {
		var err error
		if out[i], err = wire.DecodeSignedFor(v, b); err != nil {
			return nil, invalid("entry %d: %v", i, err)
		}
	}
	return out, nil
}
