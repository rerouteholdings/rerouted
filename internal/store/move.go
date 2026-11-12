package store

import (
	"bytes"
	"slices"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// MoveIntent excludes signing time and signer, but retains all signed list
// members (including ones not imported). Lists are sets, not iteration order.
type MoveIntent struct {
	ID       string       `json:"id"`
	Server   string       `json:"server"`
	Head     wire.Bytes   `json:"head"`
	Contacts []string     `json:"contacts"`
	Groups   []wire.Bytes `json:"groups"`
}

func (m MoveIntent) Encode() ([]byte, error) {
	// Sorted, deduplicated copies, never nil: an empty list encodes as [].
	m.Contacts = append([]string{}, m.Contacts...)
	slices.Sort(m.Contacts)
	m.Contacts = slices.Compact(m.Contacts)
	m.Groups = append([]wire.Bytes{}, m.Groups...)
	slices.SortFunc(m.Groups, func(a, b wire.Bytes) int { return bytes.Compare(a, b) })
	m.Groups = slices.CompactFunc(m.Groups, func(a, b wire.Bytes) bool { return bytes.Equal(a, b) })
	return wire.Marshal(m)
}

// NormalizeMoveReceipt also reads the original schema-5 signed-operation
// receipts. They already prove atomic acceptance, so no inferred receipt or
// schema migration is needed to recognize a freshly signed retry of them.
func NormalizeMoveReceipt(raw []byte) (MoveIntent, []byte, error) {
	var m MoveIntent
	if sig, err := wire.DecodeSigned(raw); err == nil && sig.T == "move" {
		var body struct {
			MoveIntent
			TS int64 `json:"ts"`
		}
		if err := sig.OpenClosed(&body); err != nil {
			return m, nil, err
		}
		m = body.MoveIntent
	} else if err := wire.Unmarshal(raw, &m); err != nil {
		return m, nil, err
	}
	canonical, err := m.Encode()
	return m, canonical, err
}

// MatchMoveReceipt distinguishes a semantic retry from changed intent at the
// same migration head. The direct comparison also supports opaque storage tests.
func MatchMoveReceipt(receipt, operation []byte) (same, conflict bool) {
	if bytes.Equal(receipt, operation) {
		return true, false
	}
	a, ac, ae := NormalizeMoveReceipt(receipt)
	b, bc, be := NormalizeMoveReceipt(operation)
	if ae != nil || be != nil || len(a.Head) == 0 || len(b.Head) == 0 {
		return false, false
	}
	if a.ID != b.ID || a.Server != b.Server || !bytes.Equal(a.Head, b.Head) {
		return false, false
	}
	same = bytes.Equal(ac, bc)
	return same, !same
}
