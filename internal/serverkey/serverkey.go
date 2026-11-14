// Package serverkey loads or creates this server's signing keys (SPEC §5.1): an Ed25519 key
// for wire version 1, and a composite ML-DSA-65 + Ed25519 key for wire version 2 (SPEC §3.2.2).
package serverkey

import (
	"crypto/ed25519"
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

// Key is the server's current signing key for wire version 1, with its key for version 2.
type Key struct {
	Priv    ed25519.PrivateKey
	KID     string
	Created time.Time
	// V2 signs S2S requests, receipts, and move reservations in wire version 2. Its
	// components are its own: a composite key never reuses another key's material (RFC 10073).
	V2 CompositeKey
}

// CompositeKey is a composite server key (SPEC §3.2.2, §5.1).
type CompositeKey struct {
	Priv    *wire.CompositePrivateKey
	KID     string
	Created time.Time
}

func (k Key) Public() ed25519.PublicKey { return k.Priv.Public().(ed25519.PublicKey) }

type file struct {
	Seed    wire.Bytes `json:"seed"`
	Created int64      `json:"created"`
}

// LoadOrCreate reads dataDir/server-key.json and dataDir/server-key-v2.json, creating
// either if it doesn't exist. Rotation isn't implemented yet.
func LoadOrCreate(dataDir string) (Key, error) {
	path := filepath.Join(dataDir, "server-key.json")
	b, err := os.ReadFile(path)
	var k Key
	switch {
	case errors.Is(err, os.ErrNotExist):
		if k, err = create(dataDir, path); err != nil {
			return Key{}, err
		}
	case err != nil:
		return Key{}, err
	default:
		var f file
		if err := wire.Unmarshal(b, &f); err != nil || len(f.Seed) != ed25519.SeedSize {
			return Key{}, fmt.Errorf("%s: unreadable server key", path)
		}
		k = fromFile(f)
	}
	if k.V2, err = loadOrCreateV2(dataDir); err != nil {
		return Key{}, err
	}
	return k, nil
}

// fileV2 holds a composite key's two 32-byte seeds.
type fileV2 struct {
	MLDSA   wire.Bytes `json:"mldsa"`
	Ed25519 wire.Bytes `json:"ed25519"`
	Created int64      `json:"created"`
}

func loadOrCreateV2(dataDir string) (CompositeKey, error) {
	path := filepath.Join(dataDir, "server-key-v2.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		f := fileV2{MLDSA: make([]byte, 32), Ed25519: make([]byte, ed25519.SeedSize), Created: time.Now().Unix()}
		rand.Read(f.MLDSA)
		rand.Read(f.Ed25519)
		if b, err = wire.Marshal(f); err != nil {
			return CompositeKey{}, err
		}
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return CompositeKey{}, err
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return CompositeKey{}, err
		}
	} else if err != nil {
		return CompositeKey{}, err
	}
	var f fileV2
	if err := wire.Unmarshal(b, &f); err != nil {
		return CompositeKey{}, fmt.Errorf("%s: unreadable server key", path)
	}
	priv, err := wire.NewCompositeKey(f.MLDSA, f.Ed25519)
	if err != nil {
		return CompositeKey{}, fmt.Errorf("%s: unreadable server key", path)
	}
	sum := sha256.Sum256(priv.Public().Bytes())
	return CompositeKey{Priv: priv, KID: hex.EncodeToString(sum[:8]), Created: time.Unix(f.Created, 0)}, nil
}

func create(dataDir, path string) (Key, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return Key{}, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return Key{}, err
	}
	f := file{Seed: seed, Created: time.Now().Unix()}
	b, err := wire.Marshal(f)
	if err != nil {
		return Key{}, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return Key{}, err
	}
	return fromFile(f), nil
}

func fromFile(f file) Key {
	priv := ed25519.NewKeyFromSeed(f.Seed)
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return Key{Priv: priv, KID: hex.EncodeToString(sum[:8]), Created: time.Unix(f.Created, 0)}
}
