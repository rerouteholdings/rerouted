// Package keyd keeps the server keys out of rerouted's main process. rerouted-keyd holds
// them and signs on request over a unix socket; rerouted asks it (REROUTED_KEYD) instead
// of reading the keys itself. A compromised rerouted can then sign only while it runs, and
// only what a server signs with its own key: S2S requests from itself, with the current
// time, commit receipts it gives as a hub, and move reservations for its own name
// (SPEC §4.3). It can't take the keys away.
//
// The protocol: each message is a 4-byte big-endian length and that many bytes of JSON.
// The client sends a request and reads one response, and may send another on the same
// connection.
package keyd

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"slices"

	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// maxMessage bounds a request or response: an S2S body can carry a community's ratchet
// tree, which may be 32 MiB.
const maxMessage = 64 << 20

type request struct {
	Op  string `json:"op"` // "keys" or "sign"
	KID string `json:"kid,omitempty"`
	T   string `json:"t,omitempty"`
	B   string `json:"b,omitempty"`
}

type response struct {
	Err    string     `json:"err,omitempty"`
	S      wire.Bytes `json:"s,omitempty"`
	Keys   []pubKey   `json:"keys,omitempty"`
	Invite wire.Bytes `json:"invite,omitempty"`
}

// pubKey describes one key rerouted-keyd holds.
type pubKey struct {
	Name    string     `json:"name"` // the server name it signs as
	V       int        `json:"v"`    // its wire version: 1 is Ed25519, 2 composite
	KID     string     `json:"kid"`
	Pub     wire.Bytes `json:"pub"`
	Created int64      `json:"created"`
}

func writeMsg(w io.Writer, v any) error { return ipc.Write(w, v, maxMessage) }

func readMsg(r io.Reader, v any) error { return ipc.Read(r, v, maxMessage) }

// held is one private key, and the server name it signs as.
type held struct {
	name string
	v1   ed25519.PrivateKey
	v2   *wire.CompositePrivateKey
}

// Keys are the keys rerouted-keyd holds: a server's two, and its community names' own.
type Keys struct {
	byKID  map[string]held
	pubs   []pubKey
	invite []byte
}

// NewKeys gathers a server's keys, with those of the community server names other than its
// own (by name).
func NewKeys(name string, k serverkey.Key, communities map[string]serverkey.CompositeKey) *Keys {
	ks := &Keys{byKID: map[string]held{}, invite: k.InviteKey}
	ks.byKID[k.KID] = held{name: name, v1: k.Priv}
	ks.pubs = append(ks.pubs, pubKey{Name: name, V: wire.V1, KID: k.KID, Pub: wire.Bytes(k.Public()), Created: k.Created.Unix()})
	add := func(name string, c serverkey.CompositeKey) {
		ks.byKID[c.KID] = held{name: name, v2: c.Priv}
		ks.pubs = append(ks.pubs, pubKey{Name: name, V: wire.V2, KID: c.KID, Pub: wire.Bytes(c.Public().Bytes()), Created: c.Created.Unix()})
	}
	add(name, k.V2)
	names := make([]string, 0, len(communities))
	for n := range communities {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		add(n, communities[n])
	}
	return ks
}

// Files lists the key files a server named name needs, with community server names cms.
func Files(name string, cms []string) []string {
	files := []string{serverkey.FileV1, serverkey.FileV2}
	for _, c := range cms {
		if c != name {
			files = append(files, serverkey.CommunityFile(c))
		}
	}
	return files
}

// LoadDir reads a server's keys from dir, creating any that don't exist, as rerouted does
// in its data directory.
func LoadDir(dir, name string, cms []string) (*Keys, error) {
	k, err := serverkey.LoadOrCreate(dir)
	if err != nil {
		return nil, err
	}
	comm := map[string]serverkey.CompositeKey{}
	for _, c := range cms {
		if c == name {
			continue
		}
		if comm[c], err = serverkey.LoadOrCreateComposite(dir, serverkey.CommunityFile(c)); err != nil {
			return nil, err
		}
	}
	return NewKeys(name, k, comm), nil
}

// A bundle is every key file of a server in one JSON object, by file name: what
// rerouted-keyd keeps encrypted with systemd-creds.
type bundle map[string]wire.Raw

// LoadBundle reads a server's keys from a bundle, which must hold all of them.
func LoadBundle(b []byte, name string, cms []string) (*Keys, error) {
	var bd bundle
	if err := wire.Unmarshal(b, &bd); err != nil {
		return nil, fmt.Errorf("keyd: unreadable key bundle: %w", err)
	}
	for _, f := range Files(name, cms) {
		if bd[f] == nil {
			return nil, fmt.Errorf("keyd: the key bundle has no %s: run rerouted-keyd bundle first", f)
		}
	}
	k, err := serverkey.ParseV1(bd[serverkey.FileV1])
	if err != nil {
		return nil, fmt.Errorf("keyd: %s: %w", serverkey.FileV1, err)
	}
	if k.V2, err = serverkey.ParseComposite(bd[serverkey.FileV2]); err != nil {
		return nil, fmt.Errorf("keyd: %s: %w", serverkey.FileV2, err)
	}
	comm := map[string]serverkey.CompositeKey{}
	for _, c := range cms {
		if c == name {
			continue
		}
		f := serverkey.CommunityFile(c)
		if comm[c], err = serverkey.ParseComposite(bd[f]); err != nil {
			return nil, fmt.Errorf("keyd: %s: %w", f, err)
		}
	}
	return NewKeys(name, k, comm), nil
}
