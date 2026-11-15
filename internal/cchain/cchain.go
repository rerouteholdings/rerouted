// Package cchain validates community chains (SPEC §16.2): the signed, append-only log of a
// community's settings, roles, channels, codes, bans, and timeouts. It checks each entry
// in the order §16.2.2 lists, and answers with the error the table there gives for the
// first check that fails, as a community server accepting an append must.
//
// The structure is readable to the community server; channel and role names are sealed,
// and nothing here opens them (§16.2.4).
package cchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Perms is a set of the four permissions (SPEC §16.3).
type Perms uint8

const (
	Talk Perms = 1 << iota
	Invite
	Moderate
	Administrate
)

// All is every permission: the owner's.
const All = Talk | Invite | Moderate | Administrate

// TypeEntry is the signed type of a community chain entry.
const TypeEntry = "community-entry"

// Limits (SPEC §16.1, §16.2.3).
const (
	MaxOps       = 256
	MaxRoles     = 20
	MaxChannels  = 100
	MaxCodeUses  = 1000
	MaxTimeout   = 7 * 24 * 3600
	MaxVoice     = 64
	MaxCast      = 4
	ClockSkew    = 600 // seconds, either way (§16.2.2 check 4)
	everyoneRole = 0
)

// Error is a refusal, with the status and error code of the first check that failed
// (SPEC §16.2.2).
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return e.Code
	}
	return e.Code + ": " + e.Msg
}

func invalid(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: wire.ErrCodeInvalidChain, Msg: msg}
}

func notAllowed(msg string) *Error {
	return &Error{Status: http.StatusForbidden, Code: wire.ErrCodeNotAllowed, Msg: msg}
}

// ErrNotDevice is what Keys returns when k isn't a current device of by: 403 not-allowed.
var ErrNotDevice = errors.New("cchain: k isn't a current device of by")

// Signer is what the verifier knows about an entry's signer from its identity chain.
type Signer struct {
	Pub  *wire.CompositePublicKey // the composite key k names
	Home string                   // by's homeserver, for domain bans
}

// Keys finds the composite key that k names among by's devices. ErrNotDevice if it isn't
// one; any other error is passed back as it is, so the caller can answer 503.
type Keys func(by string, k []byte) (Signer, error)

// Mode says which checks apply.
type Mode int

const (
	// Append is a community server accepting a new entry: ts within 10 minutes of now in
	// both directions, and k a current device of by.
	Append Mode = iota
	// Replay is entries already checked and stored: no signatures, keys, or clock, but every
	// other rule, so the state comes out as it did.
	Replay
	// Import is a whole chain arriving with a move (§16.2.3 set-home): signatures checked
	// through Keys, and no ts more than 10 minutes ahead of now.
	Import
)

// Role is a role in the state. Its name and color are sealed.
type Role struct {
	ID       uint64
	Rank     int
	Perms    Perms
	HasName  bool
	HasColor bool
}

// Channel is a channel in the state. Its name and topic are sealed.
type Channel struct {
	ID       uint64
	Kind     string // "text" or "voice"
	See      []uint64
	Write    []uint64
	History  bool // text
	Slow     int  // text: seconds between one member's messages
	Max      int  // voice: people
	Cast     int  // voice: people casting at once
	HasTopic bool
}

// Code is a join code in the state (§16.6).
type Code struct {
	Key     []byte // composite public key
	Hash    []byte // SHA-256 of Key: the code's name
	Exp     int64  // 0: doesn't expire
	Uses    int    // 0: no use limit
	Public  bool
	Creator string
	Seq     uint64 // the entry that added it
}

// MaxIconSize is the largest icon, in bytes (§16.2.3).
const MaxIconSize = 262144

// Icon is a community's icon, named by hash (§16.2.3). It's readable, like the name.
type Icon struct {
	Mime string
	Hash []byte // SHA-256 of the bytes
	Size int
}

// IconMime reports whether t is an icon type the spec allows.
func IconMime(t string) bool {
	return t == "image/png" || t == "image/jpeg" || t == "image/webp"
}

// State is a community's state after its chain's head (§16.2.1).
type State struct {
	ID       []byte // the community's identifier
	Seq      uint64 // the head's seq
	Head     []byte // the head's hash
	TS       int64  // the head's ts
	Name     string
	Desc     string
	Icon     *Icon // nil: no icon
	Public   bool
	Approval bool
	Owner    string
	Server   string
	Everyone Perms

	Roles    map[uint64]*Role
	LastRole uint64
	Assigned map[string][]uint64

	Channels    map[uint64]*Channel
	Order       []uint64
	LastChannel uint64

	Codes    map[string]*Code
	UsedKeys map[string]bool

	BannedIDs     map[string]bool
	BannedDomains map[string]bool
	Timeouts      map[string]int64
}

// Op is what an applied op did, for the server to act on.
type Op struct {
	Op     string
	ID     uint64 // role or channel
	Member string // assign-roles, ban, unban, timeout
	Domain string // ban, unban
	To     string // transfer-ownership
	Server string // create, set-home
	Until  int64  // timeout
	Key    []byte // add-code: the composite public key
	Code   []byte // add-code, revoke-code: the code's hash
	Roles  []uint64
	See    []uint64 // add-channel, edit-channel
	SeeSet bool     // edit-channel: see changed
	Public bool     // add-code: a public code; create and set-settings: the setting
}

// Applied is an entry that was accepted.
type Applied struct {
	Seq  uint64
	Hash []byte // SHA-256(JCS(signed))
	Enc  []byte // JCS(signed)
	By   string
	TS   int64
	Ops  []Op
}

func newState() *State {
	return &State{
		Roles: map[uint64]*Role{}, Assigned: map[string][]uint64{}, Channels: map[uint64]*Channel{},
		Codes: map[string]*Code{}, UsedKeys: map[string]bool{}, BannedIDs: map[string]bool{},
		BannedDomains: map[string]bool{}, Timeouts: map[string]int64{},
	}
}

// Clone is a deep copy.
func (st *State) Clone() *State {
	c := *st
	c.ID, c.Head = bytes.Clone(st.ID), bytes.Clone(st.Head)
	if st.Icon != nil {
		ic := *st.Icon
		ic.Hash = bytes.Clone(st.Icon.Hash)
		c.Icon = &ic
	}
	c.Roles = make(map[uint64]*Role, len(st.Roles))
	for k, r := range st.Roles {
		rr := *r
		c.Roles[k] = &rr
	}
	c.Assigned = make(map[string][]uint64, len(st.Assigned))
	for k, v := range st.Assigned {
		c.Assigned[k] = slices.Clone(v)
	}
	c.Channels = make(map[uint64]*Channel, len(st.Channels))
	for k, ch := range st.Channels {
		cc := *ch
		cc.See, cc.Write = slices.Clone(ch.See), slices.Clone(ch.Write)
		c.Channels[k] = &cc
	}
	c.Order = slices.Clone(st.Order)
	c.Codes = make(map[string]*Code, len(st.Codes))
	for k, cd := range st.Codes {
		cc := *cd
		cc.Key, cc.Hash = bytes.Clone(cd.Key), bytes.Clone(cd.Hash)
		c.Codes[k] = &cc
	}
	c.UsedKeys = cloneSet(st.UsedKeys)
	c.BannedIDs = cloneSet(st.BannedIDs)
	c.BannedDomains = cloneSet(st.BannedDomains)
	c.Timeouts = make(map[string]int64, len(st.Timeouts))
	for k, v := range st.Timeouts {
		c.Timeouts[k] = v
	}
	return &c
}

func cloneSet(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// PermsOf is the union of the perms of id's roles, everyone's included. The owner has all.
func (st *State) PermsOf(id string) Perms {
	if id == st.Owner {
		return All
	}
	p := st.Everyone
	for _, r := range st.Assigned[id] {
		if role := st.Roles[r]; role != nil {
			p |= role.Perms
		}
	}
	return p
}

// Level is the highest rank among id's roles, 0 with none, and above every rank for the
// owner (§16.2.1).
func (st *State) Level(id string) int {
	if id == st.Owner {
		return math.MaxInt
	}
	l := 0
	for _, r := range st.Assigned[id] {
		if role := st.Roles[r]; role != nil && role.Rank > l {
			l = role.Rank
		}
	}
	return l
}

// Has reports whether id has every permission in p.
func (st *State) Has(id string, p Perms) bool { return st.PermsOf(id)&p == p }

// holdsAny reports whether id holds a role in list; everyone holds role 0.
func (st *State) holdsAny(id string, list []uint64) bool {
	for _, r := range list {
		if r == everyoneRole || slices.Contains(st.Assigned[id], r) {
			return true
		}
	}
	return false
}

// CanSee reports whether id has a role in the channel's see list (§16.3).
func (st *State) CanSee(id string, ch *Channel) bool { return ch != nil && st.holdsAny(id, ch.See) }

// CanWrite reports whether id has a role in the channel's write list and the talk
// permission (§16.3). Timeouts are separate (TimedOut).
func (st *State) CanWrite(id string, ch *Channel) bool {
	return ch != nil && st.holdsAny(id, ch.Write) && st.Has(id, Talk)
}

// Restricted reports whether a channel's see list isn't [0] (§16.2.3).
func (st *State) Restricted(ch *Channel) bool {
	return !(len(ch.See) == 1 && ch.See[0] == everyoneRole)
}

// TimedOut reports whether id is timed out at now: its until is in the future (§16.2.3).
func (st *State) TimedOut(id string, now int64) bool {
	u, ok := st.Timeouts[id]
	return ok && u > now
}

// Banned reports whether id is banned, or, unless it's the owner, a domain ban covers
// home: home is the domain, or ends in "." followed by it (§16.2.3).
func (st *State) Banned(id, home string) bool {
	if st.BannedIDs[id] {
		return true
	}
	return id != st.Owner && st.domainBanned(home)
}

func (st *State) domainBanned(home string) bool {
	if home == "" {
		return false
	}
	for d := range st.BannedDomains {
		if home == d || strings.HasSuffix(home, "."+d) {
			return true
		}
	}
	return false
}

// Live returns the code named by hash if it's in the state, its exp hasn't passed, and its
// creator isn't banned by identifier. Its uses, and whether its creator is still a member,
// are for the caller (§16.2.3).
func (st *State) Live(hash []byte, now int64) *Code {
	c := st.Codes[hex.EncodeToString(hash)]
	if c == nil || (c.Exp != 0 && now >= c.Exp) || st.BannedIDs[c.Creator] {
		return nil
	}
	return c
}

// SeeKey is the canonical name of a see list: its role IDs in order, joined by commas.
func SeeKey(see []uint64) string {
	parts := make([]string, len(see))
	for i, r := range see {
		parts[i] = strconv.FormatUint(r, 10)
	}
	return strings.Join(parts, ",")
}

// Create checks a community's create entry (§16.2.1) and returns the community's first
// state. In Append mode, create's server must be `server`.
func Create(raw []byte, server string, keys Keys, now int64, mode Mode) (*State, *Applied, error) {
	return step(nil, raw, server, keys, now, mode)
}

// Apply checks the entry that follows st's head, and returns the state after it. st is
// left as it was.
func (st *State) Apply(raw []byte, keys Keys, now int64, mode Mode) (*State, *Applied, error) {
	if st == nil {
		return nil, nil, invalid("no community to append to")
	}
	return step(st, raw, "", keys, now, mode)
}

// ReplayChain checks a whole chain, from its create entry. (The name Replay is the Mode.)
func ReplayChain(raws [][]byte, server string, keys Keys, now int64, mode Mode) (*State, error) {
	if len(raws) == 0 {
		return nil, invalid("empty chain")
	}
	st, _, err := Create(raws[0], server, keys, now, mode)
	if err != nil {
		return nil, err
	}
	for _, raw := range raws[1:] {
		if st, _, err = st.Apply(raw, keys, now, mode); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// step checks one entry against prev (nil for the create entry), in §16.2.2's order.
func step(prev *State, raw []byte, server string, keys Keys, now int64, mode Mode) (*State, *Applied, error) {
	// 1. Form.
	sig, err := wire.DecodeSignedV2(raw)
	if err != nil {
		return nil, nil, badRequest("signed object: " + err.Error())
	}
	if sig.T != TypeEntry {
		return nil, nil, badRequest("t must be " + TypeEntry)
	}
	if sig.KID != "" || len(sig.K) != 32 || len(sig.S) != wire.CompositeSignatureSize {
		return nil, nil, badRequest("k must name a device by its 32-byte key, with a composite signature")
	}
	body, e := decodeBody(sig.B)
	if e != nil {
		return nil, nil, e
	}
	enc, err := sig.Encode()
	if err != nil {
		return nil, nil, badRequest(err.Error())
	}
	sum := sha256.Sum256(enc)

	// 2. Place.
	if prev == nil {
		if body.Seq != 0 || body.hasCommunity || body.hasPrev || len(body.Ops) != 1 || body.Ops[0].Op != "create" {
			return nil, nil, invalid("the create entry has seq 0, no community or prev, and exactly one op, create")
		}
	} else {
		switch {
		case !body.hasCommunity || !bytes.Equal(body.Community, prev.ID):
			return nil, nil, invalid("community must be this community's identifier")
		case !body.hasPrev:
			return nil, nil, invalid("prev is required after the create entry")
		case !bytes.Equal(body.Prev, prev.Head):
			return nil, nil, &Error{Status: http.StatusConflict, Code: wire.ErrCodeStaleHead, Msg: "prev isn't the current head"}
		case body.Seq != prev.Seq+1:
			return nil, nil, invalid("seq must follow the head's")
		}
		for _, o := range body.Ops {
			if o.Op == "create" {
				return nil, nil, invalid("create appears only in the create entry")
			}
		}
	}

	// 3. Signature.
	var signer Signer
	if mode != Replay {
		if keys == nil {
			return nil, nil, errors.New("cchain: no key lookup")
		}
		signer, err = keys(body.By, sig.K)
		if errors.Is(err, ErrNotDevice) {
			return nil, nil, notAllowed("k isn't a current device of by")
		}
		if err != nil {
			return nil, nil, err
		}
		if sig.VerifyComposite(TypeEntry, signer.Pub) != nil {
			return nil, nil, &Error{Status: http.StatusBadRequest, Code: wire.ErrCodeBadSignature, Msg: ""}
		}
	}

	// 4. Time.
	skew := func(msg string) *Error {
		return &Error{Status: http.StatusBadRequest, Code: wire.ErrCodeClockSkew, Msg: msg}
	}
	if prev != nil && body.TS < prev.TS {
		return nil, nil, skew("ts is before the previous entry's")
	}
	switch mode {
	case Append:
		if body.TS > now+ClockSkew || body.TS < now-ClockSkew {
			return nil, nil, skew("ts is more than 10 minutes from the server's clock")
		}
	case Import:
		if body.TS > now+ClockSkew {
			return nil, nil, skew("ts is more than 10 minutes ahead of the server's clock")
		}
	}

	// 5 and 6. Authority, limits, and op rules.
	var cur *State
	if prev == nil {
		cur = newState()
	} else {
		cur = prev.Clone()
	}
	a := &applier{before: prev, cur: cur, by: body.By, ts: body.TS, seq: body.Seq, home: signer.Home}
	if prev != nil {
		if e := a.authority(body.Ops); e != nil {
			return nil, nil, e
		}
	}
	ops := make([]Op, 0, len(body.Ops))
	for i := range body.Ops {
		o := &body.Ops[i]
		out, e := a.apply(o, server, mode)
		if e != nil {
			return nil, nil, e
		}
		ops = append(ops, out)
	}
	if prev == nil {
		cur.ID = sum[:]
	}
	cur.Seq, cur.Head, cur.TS = body.Seq, sum[:], body.TS
	return cur, &Applied{Seq: body.Seq, Hash: sum[:], Enc: enc, By: body.By, TS: body.TS, Ops: ops}, nil
}
