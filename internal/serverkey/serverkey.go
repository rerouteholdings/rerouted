// Package serverkey loads, creates, and rotates this server's signing keys (SPEC §5.1): an
// Ed25519 key for wire version 1, and a composite ML-DSA-65 + Ed25519 key for wire version 2
// (SPEC §3.2.2).
//
// Each key lives in its own file in the data directory, as it always has: server-key.json,
// server-key-v2.json, and community-key-NAME.json. That file always holds the key the server
// signs with. Rotation adds two files beside it:
//
//   - NAME-next.json, the key that signs next. It's published from the moment it's made,
//     and signs once it has been published for SwitchAfter, so that every reader's cached
//     copy of the server document has it by then (SPEC §5.1 caps that cache at 24 hours).
//   - NAME-old.json, the public halves of the keys it replaced. Each stays published until
//     its exp, so receipts and reservations signed shortly before a rotation still verify.
//
// A server that was set up before rotation has only the first file, and rotates from it.
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

const (
	// Lifetime is how long a server key is published as valid, from its nbf to its exp.
	Lifetime = 365 * 24 * time.Hour
	// MaxLifetime is the most SPEC §5.1 allows. A reader ignores a key that claims longer.
	MaxLifetime = 400 * 24 * time.Hour
	// RotateAfter is the age at which a key gets a successor. It leaves the old key's last
	// signatures, made SwitchAfter later, valid for 58 days: longer than the 30 days a hub
	// keeps commits and their receipts (SPEC §11.6).
	RotateAfter = 300 * 24 * time.Hour
	// SwitchAfter is how long a successor is published before it signs.
	SwitchAfter = 7 * 24 * time.Hour
	// switchMargin: a successor signs early if the current key is this close to its exp,
	// as on a server that was stopped, or upgraded, late in its key's life.
	switchMargin = 2 * 24 * time.Hour
)

// Key is the server's current signing key for wire version 1, with its key for version 2.
// It's a snapshot: Keys.Current gives the one in use now.
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

// Published is a key as the server document lists it (SPEC §5.1).
type Published struct {
	KID     string     `json:"kid"`
	Pub     wire.Bytes `json:"pub"`
	NBF     int64      `json:"nbf"`
	EXP     int64      `json:"exp"`
	Revoked int64      `json:"revoked,omitempty"`
}

// Keys is a server name's two rotating keys: V1 (Ed25519) and V2 (composite). A name that's
// only a community server shares its homeserver's V1 slot, and publishes only V2.
type Keys struct {
	V1, V2 *Slot
	invite []byte
}

// LoadOrCreate opens dataDir's server keys, creating any that don't exist yet.
func LoadOrCreate(dataDir string) (*Keys, error) {
	v1, err := OpenSlot(dataDir, "server-key.json", false)
	if err != nil {
		return nil, err
	}
	v2, err := OpenSlot(dataDir, "server-key-v2.json", true)
	if err != nil {
		return nil, err
	}
	k := &Keys{V1: v1, V2: v2}
	if k.invite, err = loadInviteKey(dataDir, v1); err != nil {
		return nil, err
	}
	return k, nil
}

// WithV2 is these keys with another composite slot: a community server name's own.
func (k *Keys) WithV2(v2 *Slot) *Keys { return &Keys{V1: k.V1, V2: v2, invite: k.invite} }

// Current is the keys the server signs with now.
func (k *Keys) Current() Key {
	if k == nil {
		return Key{}
	}
	var out Key
	if k.V1 != nil {
		c := k.V1.current()
		out.Priv, out.KID, out.Created = c.ed, c.kid, time.Unix(c.created, 0)
	}
	if k.V2 != nil {
		c := k.V2.current()
		out.V2 = CompositeKey{Priv: c.comp, KID: c.kid, Created: time.Unix(c.created, 0)}
	}
	return out
}

// InviteKey keys the hashes of invite codes (SPEC §9.1). It was derived from the first
// version 1 key, and is kept in its own file, so rotating that key doesn't break codes.
func (k *Keys) InviteKey() []byte { return k.invite }

// Maintain rotates both slots as their keys age (Slot.Maintain).
func (k *Keys) Maintain(now time.Time) error {
	return errors.Join(k.V1.Maintain(now), k.V2.Maintain(now))
}

// loadInviteKey reads invite-key.json, or makes it from the current version 1 key, as the
// invite key always was: HMAC-SHA256 keyed by that key's seed, of "tieroute invite codes".
func loadInviteKey(dataDir string, v1 *Slot) ([]byte, error) {
	path := filepath.Join(dataDir, "invite-key.json")
	var f struct {
		Key wire.Bytes `json:"key"`
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := wire.Unmarshal(b, &f); err != nil || len(f.Key) != sha256.Size {
			return nil, fmt.Errorf("%s: unreadable invite key", path)
		}
		return f.Key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	mac := hmac.New(sha256.New, v1.current().ed.Seed())
	mac.Write([]byte("tieroute invite codes"))
	f.Key = mac.Sum(nil)
	if b, err = wire.Marshal(f); err != nil {
		return nil, err
	}
	return f.Key, writeFile(path, b)
}

// ---- one rotating key ----

// Slot is one rotating key and its files (see the package comment).
type Slot struct {
	mu        sync.Mutex
	dir, file string
	composite bool
	cur, next *slotKey
	old       []Published
}

type slotKey struct {
	ed      ed25519.PrivateKey        // a version 1 key
	comp    *wire.CompositePrivateKey // a composite key
	kid     string
	created int64
	enc     []byte // the file, for a key newKey made
}

func (k *slotKey) published() Published {
	var pub []byte
	if k.comp != nil {
		pub = k.comp.Public().Bytes()
	} else {
		pub = k.ed.Public().(ed25519.PublicKey)
	}
	return Published{KID: k.kid, Pub: pub, NBF: k.created, EXP: k.created + int64(Lifetime/time.Second)}
}

// file is a version 1 key's file.
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

type oldFile struct {
	Keys []Published `json:"keys"`
}

// LoadOrCreateComposite opens a composite key slot, creating its key if it doesn't exist:
// each community server name has its own (SPEC §16.1).
func LoadOrCreateComposite(dataDir, file string) (*Slot, error) {
	return OpenSlot(dataDir, file, true)
}

// OpenSlot opens the key in dataDir/file, creating it if it doesn't exist, with its
// successor and the keys it replaced.
func OpenSlot(dataDir, file string, composite bool) (*Slot, error) {
	s := &Slot{dir: dataDir, file: file, composite: composite}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(time.Now()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Slot) path(suffix string) string {
	return filepath.Join(s.dir, strings.TrimSuffix(s.file, ".json")+suffix+".json")
}

// load reads the slot's files, creating the current key if there's none.
func (s *Slot) load(now time.Time) error {
	cur, err := s.readKey(s.path(""))
	if errors.Is(err, os.ErrNotExist) {
		if cur, err = s.newKey(now); err != nil {
			return err
		}
		if err := s.writeKey(s.path(""), cur); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	next, err := s.readKey(s.path("-next"))
	if errors.Is(err, os.ErrNotExist) {
		next = nil
	} else if err != nil {
		return err
	}
	var old oldFile
	if b, err := os.ReadFile(s.path("-old")); err == nil {
		if err := wire.Unmarshal(b, &old); err != nil {
			return fmt.Errorf("%s: unreadable", s.path("-old"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if next != nil && next.kid == cur.kid {
		next = nil // a switch that stopped after promoting the successor
	}
	s.cur, s.next = cur, next
	s.old = slices.DeleteFunc(old.Keys, func(p Published) bool { return p.KID == cur.kid })
	return nil
}

func (s *Slot) current() *slotKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Published lists the slot's keys for the server document at time now: the current key,
// its successor if there is one, and the replaced keys that haven't expired.
func (s *Slot) Published(now time.Time) []Published {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Published{s.cur.published()}
	if s.next != nil {
		out = append(out, s.next.published())
	}
	for _, p := range s.old {
		if p.EXP >= now.Unix() {
			out = append(out, p)
		}
	}
	return out
}

// Maintain reads the slot's files again, so a rotation by `rerouted keys` reaches a running
// server, and then moves the slot along as its key ages: at RotateAfter it makes and
// publishes a successor; SwitchAfter later, or once the key is close to its exp, the
// successor signs, and the key it replaces stays published until its exp. Keys past their
// exp are dropped.
func (s *Slot) Maintain(now time.Time) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(now); err != nil {
		return err
	}
	t := now.Unix()
	if s.next == nil && t >= s.cur.created+int64(RotateAfter/time.Second) {
		next, err := s.newKey(now)
		if err != nil {
			return err
		}
		if err := s.writeKey(s.path("-next"), next); err != nil {
			return err
		}
		s.next = next
	}
	if s.next != nil && (t >= s.next.created+int64(SwitchAfter/time.Second) || t >= s.cur.published().EXP-int64(switchMargin/time.Second)) {
		if err := s.promote(0); err != nil {
			return err
		}
	}
	if n := len(s.old); n > 0 {
		s.old = slices.DeleteFunc(s.old, func(p Published) bool { return p.EXP < t })
		if len(s.old) != n {
			return s.writeOld()
		}
	}
	return nil
}

// Rotate replaces the current key at once, without the usual wait, with a new key or the
// published successor if there is one. revoked, if not zero, marks the replaced key
// revoked from that time (SPEC §5.1): for a key that may have leaked. A revoked key's
// successor is always new, since whoever took the key may have taken its successor too.
func (s *Slot) Rotate(now time.Time, revoked int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(now); err != nil {
		return err
	}
	if s.next == nil || revoked != 0 {
		next, err := s.newKey(now)
		if err != nil {
			return err
		}
		if err := s.writeKey(s.path("-next"), next); err != nil {
			return err
		}
		s.next = next
	}
	return s.promote(revoked)
}

// promote makes the successor the current key. The replaced key goes into the old list
// first, so a crash between the two steps leaves both keys published.
func (s *Slot) promote(revoked int64) error {
	p := s.cur.published()
	p.Revoked = revoked
	s.old = append(slices.DeleteFunc(s.old, func(o Published) bool { return o.KID == p.KID }), p)
	if err := s.writeOld(); err != nil {
		return err
	}
	if err := os.Rename(s.path("-next"), s.path("")); err != nil {
		return err
	}
	s.cur, s.next = s.next, nil
	return nil
}

func (s *Slot) writeOld() error {
	b, err := wire.Marshal(oldFile{Keys: s.old})
	if err != nil {
		return err
	}
	return writeFile(s.path("-old"), b)
}

func (s *Slot) newKey(now time.Time) (*slotKey, error) {
	var (
		k   *slotKey
		f   any
		err error
	)
	if s.composite {
		f2 := fileV2{MLDSA: make([]byte, 32), Ed25519: make([]byte, ed25519.SeedSize), Created: now.Unix()}
		rand.Read(f2.MLDSA)
		rand.Read(f2.Ed25519)
		if k, err = fromFileV2(f2); err != nil {
			return nil, err
		}
		f = f2
	} else {
		f1 := file{Seed: make([]byte, ed25519.SeedSize), Created: now.Unix()}
		rand.Read(f1.Seed)
		k, f = fromFile(f1), f1
	}
	if k.enc, err = wire.Marshal(f); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Slot) readKey(path string) (*slotKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if s.composite {
		var f fileV2
		if err := wire.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: unreadable server key", path)
		}
		k, err := fromFileV2(f)
		if err != nil {
			return nil, fmt.Errorf("%s: unreadable server key", path)
		}
		return k, nil
	}
	var f file
	if err := wire.Unmarshal(b, &f); err != nil || len(f.Seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: unreadable server key", path)
	}
	return fromFile(f), nil
}

func (s *Slot) writeKey(path string, k *slotKey) error { return writeFile(path, k.enc) }

// writeFile writes a private file in one step: a reader never sees half of it.
func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fromFile(f file) *slotKey {
	priv := ed25519.NewKeyFromSeed(f.Seed)
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	return &slotKey{ed: priv, kid: hex.EncodeToString(sum[:8]), created: f.Created}
}

func fromFileV2(f fileV2) (*slotKey, error) {
	priv, err := wire.NewCompositeKey(f.MLDSA, f.Ed25519)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(priv.Public().Bytes())
	return &slotKey{comp: priv, kid: hex.EncodeToString(sum[:8]), created: f.Created}, nil
}
