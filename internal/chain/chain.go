// Package chain validates identity chains (SPEC §6.2 to §6.4).
//
// Validate checks one linear chain. Resolve decides between a cached chain and a
// new one, including recovery forks (the fork rule, SPEC §6.4.1).
package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	ID             string
	Seq            uint64 // seq of the head
	Head           []byte // SHA-256 of the encoded head envelope
	HeadTS         uint64
	Devices        map[string]string // hex(device key) -> name
	Home           string
	Handle         string // "" if cleared
	RecoveryCommit []byte // SHA-256 of the next recovery public key
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
	Entry  wire.ChainEntry
	Key    ed25519.PublicKey
	Signer Signer
}

// openEntry decodes a chain entry as a closed schema: unknown members, in the entry or
// in any op, are rejected, so every implementation computes the same state (SPEC §20.2).
func openEntry(s wire.Signed) (wire.ChainEntry, error) {
	var e wire.ChainEntry
	if err := s.OpenClosed(&e); err != nil {
		return e, err
	}
	for _, op := range e.Ops {
		if err := op.Check(); err != nil {
			return e, err
		}
	}
	return e, nil
}

// Genesis validates a genesis envelope and returns the starting state (SPEC §6.2, §6.4 rule 1).
func Genesis(s wire.Signed) (*State, *Applied, error) {
	key, err := s.VerifySelf(wire.TypeChainEntry)
	if err != nil {
		return nil, nil, invalid("genesis signature: %v", err)
	}
	e, err := openEntry(s)
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
	st := &State{ID: wire.IdentityID(enc), Devices: map[string]string{}}

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
		if err := st.applyOp(op); err != nil {
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
// except the clock checks, which depend on context: see CheckClock).
// On error, st is unchanged.
func (st *State) Apply(s wire.Signed) (*Applied, error) {
	key, err := s.VerifySelf(wire.TypeChainEntry)
	if err != nil {
		return nil, invalid("seq %d signature: %v", st.Seq+1, err)
	}
	e, err := openEntry(s)
	if err != nil {
		return nil, invalid("body: %v", err)
	}
	switch {
	case e.ID != st.ID:
		return nil, invalid("id %q doesn't match %q", e.ID, st.ID)
	case e.Seq != st.Seq+1:
		return nil, invalid("seq %d, want %d", e.Seq, st.Seq+1)
	case !bytes.Equal(e.Prev, st.Head):
		return nil, invalid("prev doesn't match the head")
	case e.TS < st.HeadTS:
		return nil, invalid("ts goes backwards")
	case len(e.Ops) == 0:
		return nil, invalid("no ops")
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

	next := st.clone()
	sawRecovery := false
	for _, op := range e.Ops {
		if op.Op == wire.OpSetRecovery {
			sawRecovery = true
			if signer != SignerRecovery {
				return nil, invalid("set-recovery must be signed by the recovery key")
			}
		}
		if err := next.applyOp(op); err != nil {
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

// Validate applies a whole chain, genesis first.
func Validate(entries []wire.Signed) (*State, error) {
	if len(entries) == 0 {
		return nil, invalid("empty chain")
	}
	st, _, err := Genesis(entries[0])
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

func (st *State) applyOp(op wire.Op) error {
	switch op.Op {
	case wire.OpAddDevice:
		if len(op.Key) != ed25519.PublicKeySize {
			return invalid("add-device key size")
		}
		st.Devices[hex.EncodeToString(op.Key)] = op.Name
	case wire.OpRemoveDevice:
		k := hex.EncodeToString(op.Key)
		if _, ok := st.Devices[k]; !ok {
			return invalid("remove-device of a device that isn't current")
		}
		delete(st.Devices, k)
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
	default:
		return fmt.Errorf("%w: %w %q", ErrInvalid, ErrUnknownOp, op.Op)
	}
	return nil
}

func (st *State) finish(e wire.ChainEntry, enc []byte) {
	sum := sha256.Sum256(enc)
	st.Seq, st.Head, st.HeadTS = e.Seq, sum[:], e.TS
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

// Alert classifies an applied entry. Device-signed set-home or remove-device is
// an alarm, except a self-rotation (remove own key + add one new key, nothing
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
		case wire.OpSetHome, wire.OpRemoveDevice:
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

// ForkWindow is how far back a recovery-signed entry can override device changes (SPEC §6.4.1).
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
func Resolve(cached, candidate [][]byte) (st *State, out Outcome, at uint64, err error) {
	cand, err := decodeAll(candidate)
	if err != nil {
		return nil, 0, 0, err
	}
	candSt, err := Validate(cand)
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
		old, err := decodeAll(cached)
		if err != nil {
			return nil, 0, 0, err
		}
		cachedSt, err := Validate(old)
		return cachedSt, Same, 0, err
	case p == len(cached):
		return candSt, Extends, 0, nil
	}

	// A fork at seq p. The candidate's entry p must be recovery-signed...
	base, err := Validate(cand[:p])
	if err != nil {
		return nil, 0, 0, err
	}
	r := base.clone()
	ra, err := r.Apply(cand[p])
	if err != nil {
		return nil, 0, 0, err
	}
	old, err := decodeAll(cached[p:])
	if err != nil {
		return nil, 0, 0, err
	}
	if ra.Signer != SignerRecovery {
		// The other way round: the cache holds the recovery fork, and the candidate is the
		// device branch it would override. Which one stands doesn't depend on which arrived
		// first: if the recovery entry couldn't have overridden these device
		// entries, they're final, and the recovery entry was made on a copy that missed them.
		if err := overrides(base, old[0], cand[p:]); err == nil {
			return nil, 0, 0, invalid("seq %d: the cached recovery entry overrides this branch", p)
		} else if !errors.Is(err, errTooOld) {
			return nil, 0, 0, invalid("conflicting entry at seq %d isn't recovery-signed", p)
		}
		return candSt, Fork, uint64(p), nil
	}
	// ...and everything it overrides must be recent device changes.
	if err := overrides(base, cand[p], old); err != nil {
		return nil, 0, 0, err
	}
	return candSt, Fork, uint64(p), nil
}

var errTooOld = invalid("the device branch is more than 72 hours older than the recovery entry")

// overrides checks the fork rule (SPEC §6.4.1) for a recovery-signed entry r forking from
// base over branch: every entry in branch has to be device-signed and at most ForkWindow
// older than r. It returns errTooOld when the only problem is age, which makes the branch
// final; any other error means r isn't a recovery entry, or branch holds one (a leaked code).
func overrides(base *State, r wire.Signed, branch []wire.Signed) error {
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
		if a.Entry.TS+ForkWindow < ra.Entry.TS {
			tooOld = true
		}
	}
	if tooOld {
		return errTooOld
	}
	return nil
}

func decodeAll(raw [][]byte) ([]wire.Signed, error) {
	out := make([]wire.Signed, len(raw))
	for i, b := range raw {
		var err error
		if out[i], err = wire.DecodeSigned(b); err != nil {
			return nil, invalid("entry %d: %v", i, err)
		}
	}
	return out, nil
}
