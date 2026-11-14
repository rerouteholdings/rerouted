package wire

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var identityIDRe = regexp.MustCompile(`^tr:[a-z2-7]{24}$`)

// IdentityID derives an identifier from the JCS-encoded genesis envelope (SPEC §6.2):
// "tr:" + lowercase base32 of the first 15 bytes of its SHA-256.
func IdentityID(encodedGenesis []byte) string {
	sum := sha256.Sum256(encodedGenesis)
	return "tr:" + strings.ToLower(b32.EncodeToString(sum[:15]))
}

// ValidIdentityID reports whether s is syntactically an identity ID.
func ValidIdentityID(s string) bool { return identityIDRe.MatchString(s) }

// ChainEntry is the body of a "chain-entry" signed object (SPEC §6.3).
type ChainEntry struct {
	ID   string `json:"id,omitempty"`
	Seq  uint64 `json:"seq"`
	Prev Bytes  `json:"prev,omitempty"`
	TS   uint64 `json:"ts"`
	Ops  []Op   `json:"ops"`
}

// Op is one chain operation. Which fields apply depends on Op.Op, and on the wire version:
// Pub and ID are wire version 2's (SPEC §6.3).
type Op struct {
	Op     string  `json:"op"`
	Key    Bytes   `json:"key,omitempty"`    // add-device, remove-device
	Pub    Bytes   `json:"pub,omitempty"`    // add-device, wire version 2: the composite public key
	Name   string  `json:"name,omitempty"`   // add-device
	Home   string  `json:"home,omitempty"`   // set-home
	Handle *string `json:"handle,omitempty"` // set-handle (nil = clear)
	Next   Bytes   `json:"next,omitempty"`   // set-recovery: SHA-256 of the next recovery public key
	ID     *string `json:"id,omitempty"`     // migrated-from, wire version 2: the version 1 identifier
}

// Chain op names.
const (
	OpAddDevice    = "add-device"
	OpRemoveDevice = "remove-device"
	OpSetHome      = "set-home"
	OpSetHandle    = "set-handle"
	OpSetRecovery  = "set-recovery"
	// OpMigratedFrom names the wire version 1 identity a version 2 genesis migrates from
	// (SPEC §6.8). Wire version 2 only, and only in genesis.
	OpMigratedFrom = "migrated-from"
)

// TypeChainEntry is the signed type tag for chain entries.
const TypeChainEntry = "chain-entry"

// HexBytes renders b as lowercase hex.
func HexBytes(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = digits[c>>4], digits[c&15]
	}
	return out
}

// Check rejects members that don't belong to the op in wire version 1 (SPEC §20.2: chain
// ops are closed). Version 2's members, pub and id, don't belong to any version 1 op.
func (o Op) Check() error {
	if o.Pub != nil || o.ID != nil {
		return fmt.Errorf("wire: %s op has members that don't belong to it", o.Op)
	}
	return o.check()
}

// CheckV2 is Check for wire version 2 (SPEC §6.3): add-device also carries pub, and
// migrated-from carries only id.
func (o Op) CheckV2() error {
	extra := false
	switch o.Op {
	case OpAddDevice:
		extra = o.ID != nil
	case OpMigratedFrom:
		extra = o.Key != nil || o.Pub != nil || o.Name != "" || o.Home != "" || o.Handle != nil || o.Next != nil
	default:
		extra = o.Pub != nil || o.ID != nil
	}
	if extra {
		return fmt.Errorf("wire: %s op has members that don't belong to it", o.Op)
	}
	return o.check()
}

func (o Op) check() error {
	extra := false
	switch o.Op {
	case OpAddDevice:
		extra = o.Home != "" || o.Handle != nil || o.Next != nil
	case OpRemoveDevice:
		extra = o.Name != "" || o.Home != "" || o.Handle != nil || o.Next != nil
	case OpSetHome:
		extra = o.Key != nil || o.Name != "" || o.Handle != nil || o.Next != nil
	case OpSetHandle:
		extra = o.Key != nil || o.Name != "" || o.Home != "" || o.Next != nil
	case OpSetRecovery:
		extra = o.Key != nil || o.Name != "" || o.Home != "" || o.Handle != nil
	}
	if extra {
		return fmt.Errorf("wire: %s op has members that don't belong to it", o.Op)
	}
	return nil
}
