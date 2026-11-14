package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

// Composite signatures for wire version 2: ML-DSA-65 + Ed25519, MLDSA65-Ed25519-SHA512,
// exactly as RFC 10073 defines it (SPEC §3.2.1). Tieroute's application context is empty.

const (
	// CompositePublicKeySize is the ML-DSA-65 public key followed by the Ed25519 one.
	CompositePublicKeySize = mldsa.MLDSA65PublicKeySize + ed25519.PublicKeySize // 1,984
	// CompositeSignatureSize is the ML-DSA-65 signature followed by the Ed25519 one.
	CompositeSignatureSize = mldsa.MLDSA65SignatureSize + ed25519.SignatureSize // 3,373

	compositePrefix = "CompositeAlgorithmSignatures2025"
	compositeLabel  = "COMPSIG-MLDSA65-Ed25519-SHA512" // also ML-DSA's own context string
)

var errComposite = errors.New("wire: bad composite key")

// compositeMessage is RFC 10073's message representative,
// M' = Prefix || Label || len(ctx) || ctx || SHA-512(M). Both components sign M'.
func compositeMessage(msg, ctx []byte) []byte {
	ph := sha512.Sum512(msg)
	m := make([]byte, 0, len(compositePrefix)+len(compositeLabel)+1+len(ctx)+len(ph))
	m = append(m, compositePrefix...)
	m = append(m, compositeLabel...)
	m = append(m, byte(len(ctx)))
	m = append(m, ctx...)
	return append(m, ph[:]...)
}

// CompositePublicKey is a composite ML-DSA-65 + Ed25519 public key (SPEC §3.2.1).
type CompositePublicKey struct {
	raw []byte
	ml  *mldsa.PublicKey
}

// ParseCompositePublicKey decodes the 1,984-byte encoding. It doesn't check the Ed25519
// component's form: verification does that, as SPEC §4.3 requires for every signature.
func ParseCompositePublicKey(b []byte) (*CompositePublicKey, error) {
	if len(b) != CompositePublicKeySize {
		return nil, errComposite
	}
	ml, err := mldsa.NewPublicKey(mldsa.MLDSA65(), b[:mldsa.MLDSA65PublicKeySize])
	if err != nil {
		return nil, errComposite
	}
	return &CompositePublicKey{raw: bytes.Clone(b), ml: ml}, nil
}

// Bytes returns the 1,984-byte encoding.
func (k *CompositePublicKey) Bytes() []byte { return bytes.Clone(k.raw) }

// Ed25519 returns the Ed25519 component, the last 32 bytes. A device key's component is
// also its device key, which names it in chains and in a signed envelope's k (SPEC §3.2.2).
func (k *CompositePublicKey) Ed25519() ed25519.PublicKey {
	return bytes.Clone(k.raw[mldsa.MLDSA65PublicKeySize:])
}

// Hash is SHA-256 of the encoding: a recovery key's pre-rotation commitment (SPEC §6.3),
// and a msg-key's dev (SPEC §3.2.3).
func (k *CompositePublicKey) Hash() []byte {
	sum := sha256.Sum256(k.raw)
	return sum[:]
}

// Equal reports whether two keys have the same encoding.
func (k *CompositePublicKey) Equal(o *CompositePublicKey) bool {
	return k != nil && o != nil && bytes.Equal(k.raw, o.raw)
}

// Verify is Composite-ML-DSA.Verify with Tieroute's empty application context: both
// components must verify (SPEC §3.2.1), the Ed25519 one by every rule of SPEC §4.3.
func (k *CompositePublicKey) Verify(msg, sig []byte) bool { return k.verify(msg, sig, nil) }

func (k *CompositePublicKey) verify(msg, sig, ctx []byte) bool {
	if len(sig) != CompositeSignatureSize || len(ctx) > 255 {
		return false
	}
	m := compositeMessage(msg, ctx)
	if mldsa.Verify(k.ml, m, sig[:mldsa.MLDSA65SignatureSize], &mldsa.Options{Context: compositeLabel}) != nil {
		return false
	}
	return VerifyStrict(k.raw[mldsa.MLDSA65PublicKeySize:], m, sig[mldsa.MLDSA65SignatureSize:])
}

// CompositePrivateKey is a composite key pair, held as its two 32-byte seeds: ML-DSA-65's
// key generation seed, and the Ed25519 seed.
type CompositePrivateKey struct {
	ml  *mldsa.PrivateKey
	ed  ed25519.PrivateKey
	pub *CompositePublicKey
}

// NewCompositeKey builds a composite key pair from its two seeds (SPEC §3.2.2, §6.1).
func NewCompositeKey(mldsaSeed, ed25519Seed []byte) (*CompositePrivateKey, error) {
	if len(mldsaSeed) != mldsa.PrivateKeySize || len(ed25519Seed) != ed25519.SeedSize {
		return nil, errComposite
	}
	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mldsaSeed)
	if err != nil {
		return nil, err
	}
	ed := ed25519.NewKeyFromSeed(ed25519Seed)
	raw := append(ml.PublicKey().Bytes(), ed.Public().(ed25519.PublicKey)...)
	pub, err := ParseCompositePublicKey(raw)
	if err != nil {
		return nil, err
	}
	return &CompositePrivateKey{ml: ml, ed: ed, pub: pub}, nil
}

// GenerateCompositeKey makes a new random composite key pair.
func GenerateCompositeKey() (*CompositePrivateKey, error) {
	ml, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	_, ed, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return NewCompositeKey(ml.Bytes(), ed.Seed())
}

// Public returns the composite public key.
func (k *CompositePrivateKey) Public() *CompositePublicKey { return k.pub }

// Sign is Composite-ML-DSA.Sign with an empty application context. ML-DSA signs hedged,
// so signatures differ from the deterministic ones in the test vectors but verify the same.
func (k *CompositePrivateKey) Sign(msg []byte) ([]byte, error) { return k.sign(msg, false) }

func (k *CompositePrivateKey) sign(msg []byte, deterministic bool) ([]byte, error) {
	m := compositeMessage(msg, nil)
	opts := &mldsa.Options{Context: compositeLabel}
	var ms []byte
	var err error
	if deterministic {
		ms, err = k.ml.SignDeterministic(m, opts)
	} else {
		ms, err = k.ml.Sign(nil, m, opts)
	}
	if err != nil {
		return nil, err
	}
	return append(ms, ed25519.Sign(k.ed, m)...), nil
}

// RecoveryKey derives composite recovery key i (i = 1, 2, ...) from the 16 bytes of a
// recovery code (SPEC §6.1): Ed25519 from recovery_seed_i, ML-DSA-65 from the
// "signing-mldsa" seed. Devices must not keep it, or anything it's derived from.
func RecoveryKey(code []byte, i uint32) (*CompositePrivateKey, error) {
	prk, err := hkdf.Extract(sha256.New, code, []byte("tieroute recovery"))
	if err != nil {
		return nil, err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], i)
	edSeed, err := hkdf.Expand(sha256.New, prk, "signing"+string(n[:]), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	mlSeed, err := hkdf.Expand(sha256.New, prk, "signing-mldsa"+string(n[:]), mldsa.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	return NewCompositeKey(mlSeed, edSeed)
}
