// Package serverkey loads or creates this server's Ed25519 signing key (SPEC §5.1).
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

// Key is the server's current signing key.
type Key struct {
	Priv    ed25519.PrivateKey
	KID     string
	Created time.Time
}

func (k Key) Public() ed25519.PublicKey { return k.Priv.Public().(ed25519.PublicKey) }

type file struct {
	Seed    wire.Bytes `json:"seed"`
	Created int64      `json:"created"`
}

// LoadOrCreate reads dataDir/server-key.json, creating it if it doesn't exist.
// Rotation isn't implemented yet.
func LoadOrCreate(dataDir string) (Key, error) {
	path := filepath.Join(dataDir, "server-key.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return create(dataDir, path)
	}
	if err != nil {
		return Key{}, err
	}
	var f file
	if err := wire.Unmarshal(b, &f); err != nil || len(f.Seed) != ed25519.SeedSize {
		return Key{}, fmt.Errorf("%s: unreadable server key", path)
	}
	return fromFile(f), nil
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
