package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Wire version 2's signed envelope (SPEC §3.2.2, §4.3). The envelope's shape is version 1's,
// so it's the same Signed type, but the signature input's context is "tieroute/v2", s is a
// composite signature (or Ed25519 from a message key), and k holds a device key's Ed25519
// component or a whole composite key. Nothing here changes how version 1 objects verify.

// SigContextV2 is the first element of every wire version 2 signature input (SPEC §4.3).
const SigContextV2 = "tieroute/v2"

// Signed types that wire version 2 adds (SPEC §3.2.2, §3.2.3).
const (
	TypeMsgKey    = "msg-key"
	TypeKPBinding = "kp-binding"
)

// SigInputV2 is JCS(["tieroute/v2", t, b]), the bytes a wire version 2 signature covers.
func SigInputV2(t, b string) ([]byte, error) {
	return Marshal([]any{SigContextV2, t, b})
}

// DecodeSignedV2 decodes a wire version 2 envelope from any valid I-JSON, and checks its
// shape: closed, exactly one of k and kid, k of 32 bytes (a device key's Ed25519 component
// or a message key) or 1,984 (a composite key), and s composite, or Ed25519 only with a
// 32-byte k, since only message keys sign with Ed25519 alone (SPEC §3.2.2, §4.3).
func DecodeSignedV2(data []byte) (Signed, error) {
	var s Signed
	if err := UnmarshalClosed(data, &s); err != nil {
		return Signed{}, err
	}
	if s.T == "" || (len(s.K) == 0) == (s.KID == "") {
		return Signed{}, errors.New("wire: malformed signed object")
	}
	switch len(s.K) {
	case 0, ed25519.PublicKeySize, CompositePublicKeySize:
	default:
		return Signed{}, errors.New("wire: signer key must be 32 or 1,984 bytes")
	}
	switch len(s.S) {
	case CompositeSignatureSize:
	case ed25519.SignatureSize:
		if len(s.K) != ed25519.PublicKeySize {
			return Signed{}, errors.New("wire: only a message key signs with Ed25519 alone")
		}
	default:
		return Signed{}, errors.New("wire: signature must be 3,373 or 64 bytes")
	}
	if err := CheckIJSON([]byte(s.B)); err != nil {
		return Signed{}, fmt.Errorf("signed body: %w", err)
	}
	return s, nil
}

// SignComposite builds a wire version 2 envelope signed by a device key, which names
// itself in k by its Ed25519 component; verifiers find the composite key in the chain.
func SignComposite(t string, body any, priv *CompositePrivateKey) (Signed, error) {
	return signV2(t, body, priv, priv.pub.Ed25519(), "", false)
}

// SignCompositeFull is SignComposite with the whole composite public key in k, for the
// keys that aren't in a chain: recovery, epoch, reg, and code keys, and link proofs.
func SignCompositeFull(t string, body any, priv *CompositePrivateKey) (Signed, error) {
	return signV2(t, body, priv, priv.pub.Bytes(), "", false)
}

// SignCompositeKID is SignComposite naming a composite server key by its ID (SPEC §5.1).
func SignCompositeKID(t string, body any, priv *CompositePrivateKey, kid string) (Signed, error) {
	return signV2(t, body, priv, nil, kid, false)
}

func signV2(t string, body any, priv *CompositePrivateKey, k []byte, kid string, deterministic bool) (Signed, error) {
	b, err := Marshal(body)
	if err != nil {
		return Signed{}, err
	}
	in, err := SigInputV2(t, string(b))
	if err != nil {
		return Signed{}, err
	}
	sig, err := priv.sign(in, deterministic)
	if err != nil {
		return Signed{}, err
	}
	return Signed{T: t, B: string(b), K: k, KID: kid, S: sig}, nil
}

func (s Signed) checkType(t string) error {
	if t != "" && s.T != t {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongType, s.T, t)
	}
	return nil
}

// VerifyComposite checks a composite signature over the wire version 2 input against pub,
// and the type if t isn't empty. A k, if present, must name pub: its Ed25519 component or
// the whole key. An Ed25519-only signature fails: there's no fallback (SPEC §3.2.2). It
// doesn't check that pub is authorized; that's the caller's job.
func (s Signed) VerifyComposite(t string, pub *CompositePublicKey) error {
	if err := s.checkType(t); err != nil {
		return err
	}
	if pub == nil || len(s.S) != CompositeSignatureSize {
		return ErrBadSignature
	}
	switch len(s.K) {
	case 0:
	case ed25519.PublicKeySize:
		if !bytes.Equal(s.K, pub.raw[len(pub.raw)-ed25519.PublicKeySize:]) {
			return ErrBadSignature
		}
	default:
		if !bytes.Equal(s.K, pub.raw) {
			return ErrBadSignature
		}
	}
	in, err := SigInputV2(s.T, s.B)
	if err != nil {
		return err
	}
	if !pub.Verify(in, s.S) {
		return ErrBadSignature
	}
	return nil
}

// VerifyCompositeSelf verifies against the composite public key in k itself: recovery
// keys, link proofs, and epoch, reg, and code keys (SPEC §3.2.2). The caller then checks
// that key's authority, such as its hash against a recovery commitment (SPEC §6.3).
func (s Signed) VerifyCompositeSelf(t string) (*CompositePublicKey, error) {
	if len(s.K) != CompositePublicKeySize {
		return nil, ErrBadSignature
	}
	pub, err := ParseCompositePublicKey(s.K)
	if err != nil {
		return nil, ErrBadSignature
	}
	return pub, s.VerifyComposite(t, pub)
}

// VerifyMessageKey checks an object a message key signs (SPEC §3.2.3): k is the 32-byte
// message key, which must be key, and s an Ed25519 signature over the wire version 2 input.
// The caller checks key against the sender's msg-key (VerifyMsgKey).
func (s Signed) VerifyMessageKey(t string, key ed25519.PublicKey) error {
	if err := s.checkType(t); err != nil {
		return err
	}
	if len(s.S) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize || !bytes.Equal(s.K, key) {
		return ErrBadSignature
	}
	in, err := SigInputV2(s.T, s.B)
	if err != nil {
		return err
	}
	if !VerifyStrict(key, in, s.S) {
		return ErrBadSignature
	}
	return nil
}

// MsgKey is the body of a msg-key: a device's certificate for its Ed25519 message key,
// signed with its composite key (SPEC §3.2.3).
type MsgKey struct {
	ID  string `json:"id"`
	Dev Bytes  `json:"dev"` // SHA-256 of the device's composite public key
	Key Bytes  `json:"key"` // the Ed25519 message key
	N   uint64 `json:"n"`   // 1 for the device's first message key, one higher each rotation
}

// KPBinding is the body of a kp-binding: a device's composite signature over the hash of
// a key package it uploads (SPEC §3.2.2).
type KPBinding struct {
	ID string `json:"id"`
	KP Bytes  `json:"kp"` // SHA-256 of the KeyPackage's raw bytes
}

var ErrMsgKey = errors.New("wire: msg-key doesn't match its device")

// VerifyMsgKey checks a msg-key against the composite key of the device that signed it,
// taken from the identity id's chain (SPEC §3.2.3), and returns the certified message key.
// dev must be that device's key: dev names it by hash, so a certificate one device signs
// for another fails.
func VerifyMsgKey(cert Signed, id string, dev *CompositePublicKey) (MsgKey, error) {
	if err := cert.VerifyComposite(TypeMsgKey, dev); err != nil {
		return MsgKey{}, err
	}
	var m MsgKey
	if err := cert.OpenClosed(&m); err != nil {
		return MsgKey{}, err
	}
	if m.ID != id || !bytes.Equal(m.Dev, dev.Hash()) || m.N < 1 {
		return MsgKey{}, ErrMsgKey
	}
	if len(m.Key) != ed25519.PublicKeySize || SmallOrder(m.Key) || !Canonical25519(m.Key) {
		return MsgKey{}, ErrMsgKey
	}
	return m, nil
}

// VerifyKPBinding checks that a key package was bound by the device whose composite key
// is dev, in the identity id's chain (SPEC §3.2.2). keyPackage is the KeyPackage's raw bytes.
func VerifyKPBinding(binding Signed, id string, dev *CompositePublicKey, keyPackage []byte) error {
	if err := binding.VerifyComposite(TypeKPBinding, dev); err != nil {
		return err
	}
	var b KPBinding
	if err := binding.OpenClosed(&b); err != nil {
		return err
	}
	sum := sha256.Sum256(keyPackage)
	if b.ID != id || !bytes.Equal(b.KP, sum[:]) {
		return errors.New("wire: kp-binding doesn't match its key package")
	}
	return nil
}
