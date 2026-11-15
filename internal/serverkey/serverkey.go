// Package serverkey loads or creates this server's signing keys (SPEC §5.1): an Ed25519 key
// for wire version 1, and a composite ML-DSA-65 + Ed25519 key for wire version 2 (SPEC §3.2.2).
//
// The keys are held in this process (Priv) or by rerouted-keyd (Remote), which signs on
// request; either way, SignKID signs and Public answers the public key.
package serverkey

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Lifetime is how long a server key is published as valid.
const Lifetime = 365 * 24 * time.Hour

// The key files, in a data directory or in rerouted-keyd's bundle.
const (
	FileV1 = "server-key.json"
	FileV2 = "server-key-v2.json"
)

// CommunityFile is the key file of a community server name other than the homeserver's
// own (SPEC §16.1): each has its own key.
func CommunityFile(name string) string { return "community-key-" + name + ".json" }

// Signer signs with a key held elsewhere (rerouted-keyd), named by its key ID: s is the
// signature over the signature input for t and b, for that key's wire version (SPEC §4.3).
type Signer interface {
	Sign(kid, t, b string) (s []byte, err error)
}

// Key is the server's current signing key for wire version 1, with its key for version 2.
type Key struct {
	Priv    ed25519.PrivateKey // nil when Remote holds it
	Pub     ed25519.PublicKey
	KID     string
	Created time.Time
	Remote  Signer
	// V2 signs S2S requests, receipts, and move reservations in wire version 2. Its
	// components are its own: a composite key never reuses another key's material (RFC 10073).
	V2 CompositeKey
	// InviteKey is what invite codes are hashed with, derived from the version 1 key.
	InviteKey []byte
	// Communities holds the keys of community server names, when rerouted-keyd has them.
	// Nil: each is read from (or created in) the data directory (LoadOrCreateComposite).
	Communities map[string]CompositeKey
}

// CompositeKey is a composite server key (SPEC §3.2.2, §5.1).
type CompositeKey struct {
	Priv    *wire.CompositePrivateKey // nil when Remote holds it
	Pub     *wire.CompositePublicKey
	KID     string
	Created time.Time
	Remote  Signer
}

func (k Key) Public() ed25519.PublicKey {
	if k.Pub == nil && k.Priv != nil {
		return k.Priv.Public().(ed25519.PublicKey)
	}
	return k.Pub
}

func (k CompositeKey) Public() *wire.CompositePublicKey {
	if k.Pub == nil && k.Priv != nil {
		return k.Priv.Public()
	}
	return k.Pub
}

// SignKID signs an object with the version 1 key, naming it by key ID (SPEC §4.3).
func (k Key) SignKID(t string, body any) (wire.Signed, error) {
	if k.Remote == nil {
		if k.Priv == nil {
			return wire.Signed{}, errors.New("serverkey: no server key")
		}
		return wire.SignKID(t, body, k.Priv, k.KID)
	}
	s, err := remote(k.Remote, k.KID, t, body)
	if err != nil {
		return wire.Signed{}, err
	}
	if s.Verify(t, k.Pub) != nil {
		return wire.Signed{}, errors.New("serverkey: rerouted-keyd's signature doesn't verify")
	}
	return s, nil
}

// SignKID signs an object with the composite key, naming it by key ID (SPEC §5.1).
func (k CompositeKey) SignKID(t string, body any) (wire.Signed, error) {
	if k.Remote == nil {
		if k.Priv == nil {
			return wire.Signed{}, errors.New("serverkey: no wire version 2 server key")
		}
		return wire.SignCompositeKID(t, body, k.Priv, k.KID)
	}
	s, err := remote(k.Remote, k.KID, t, body)
	if err != nil {
		return wire.Signed{}, err
	}
	if s.VerifyComposite(t, k.Pub) != nil {
		return wire.Signed{}, errors.New("serverkey: rerouted-keyd's signature doesn't verify")
	}
	return s, nil
}

func remote(r Signer, kid, t string, body any) (wire.Signed, error) {
	b, err := wire.Marshal(body)
	if err != nil {
		return wire.Signed{}, err
	}
	sig, err := r.Sign(kid, t, string(b))
	if err != nil {
		return wire.Signed{}, err
	}
	return wire.Signed{T: t, B: string(b), KID: kid, S: sig}, nil
}

// file is a version 1 key file.
type file struct {
	Seed    wire.Bytes `json:"seed"`
	Created int64      `json:"created"`
}

// fileV2 holds a composite key's two 32-byte seeds.
type fileV2 struct {
	MLDSA   wire.Bytes `json:"mldsa"`
	Ed25519 wire.Bytes `json:"ed25519"`
	Created int64      `json:"created"`
}

// LoadOrCreate reads dataDir/server-key.json and dataDir/server-key-v2.json, creating
// either if it doesn't exist. Rotation isn't implemented yet.
func LoadOrCreate(dataDir string) (Key, error) {
	b, err := readOrCreate(dataDir, FileV1)
	if err != nil {
		return Key{}, err
	}
	k, err := ParseV1(b)
	if err != nil {
		return Key{}, fmt.Errorf("%s: %w", filepath.Join(dataDir, FileV1), err)
	}
	if k.V2, err = LoadOrCreateComposite(dataDir, FileV2); err != nil {
		return Key{}, err
	}
	return k, nil
}

// LoadOrCreateComposite reads a composite key from dataDir/file, creating it if it
// doesn't exist: each community server name has its own (SPEC §16.1).
func LoadOrCreateComposite(dataDir, file string) (CompositeKey, error) {
	b, err := readOrCreate(dataDir, file)
	if err != nil {
		return CompositeKey{}, err
	}
	k, err := ParseComposite(b)
	if err != nil {
		return CompositeKey{}, fmt.Errorf("%s: %w", filepath.Join(dataDir, file), err)
	}
	return k, nil
}

func readOrCreate(dataDir, name string) ([]byte, error) {
	path := filepath.Join(dataDir, name)
	b, err := os.ReadFile(path)
	if !errors.Is(err, os.ErrNotExist) {
		return b, err
	}
	if b, err = Generate(name); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	return b, os.WriteFile(path, b, 0o600)
}

var errUnreadable = errors.New("unreadable server key")

// Generate makes the contents of a new key file: version 1 for FileV1, composite otherwise.
func Generate(name string) ([]byte, error) {
	now := time.Now().Unix()
	if name == FileV1 {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		return wire.Marshal(file{Seed: seed, Created: now})
	}
	f := fileV2{MLDSA: make([]byte, 32), Ed25519: make([]byte, ed25519.SeedSize), Created: now}
	if _, err := rand.Read(f.MLDSA); err != nil {
		return nil, err
	}
	if _, err := rand.Read(f.Ed25519); err != nil {
		return nil, err
	}
	return wire.Marshal(f)
}

// ParseV1 reads a version 1 key file. The result has no V2 key.
func ParseV1(b []byte) (Key, error) {
	var f file
	if err := wire.Unmarshal(b, &f); err != nil || len(f.Seed) != ed25519.SeedSize {
		return Key{}, errUnreadable
	}
	priv := ed25519.NewKeyFromSeed(f.Seed)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	ik := hmac.New(sha256.New, f.Seed)
	ik.Write([]byte("tieroute invite codes"))
	return Key{Priv: priv, Pub: pub, KID: hex.EncodeToString(sum[:8]), Created: time.Unix(f.Created, 0), InviteKey: ik.Sum(nil)}, nil
}

// ParseComposite reads a composite key file.
func ParseComposite(b []byte) (CompositeKey, error) {
	var f fileV2
	if err := wire.Unmarshal(b, &f); err != nil {
		return CompositeKey{}, errUnreadable
	}
	priv, err := wire.NewCompositeKey(f.MLDSA, f.Ed25519)
	if err != nil {
		return CompositeKey{}, errUnreadable
	}
	sum := sha256.Sum256(priv.Public().Bytes())
	return CompositeKey{Priv: priv, Pub: priv.Public(), KID: hex.EncodeToString(sum[:8]), Created: time.Unix(f.Created, 0)}, nil
}
