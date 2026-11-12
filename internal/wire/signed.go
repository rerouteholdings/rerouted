package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Signed is the envelope every signed object uses (SPEC §4.3). The body travels as
// JSON text in B; the signer is a public key (K) or a server key ID (KID), never both.
type Signed struct {
	T   string `json:"t"`
	B   string `json:"b"`
	K   Bytes  `json:"k,omitempty"`
	KID string `json:"kid,omitempty"`
	S   Bytes  `json:"s"`
}

var (
	ErrBadSignature = errors.New("wire: bad signature")
	ErrWrongType    = errors.New("wire: unexpected signed type")
)

// sigInput is JCS(["tieroute/v1", t, b]), the bytes that get signed.
func sigInput(t, b string) ([]byte, error) {
	return Marshal([]any{SigContext, t, b})
}

// Sign builds a Signed envelope over body, signed by priv, with the public key in K.
func Sign(t string, body any, priv ed25519.PrivateKey) (Signed, error) {
	b, err := Marshal(body)
	if err != nil {
		return Signed{}, err
	}
	in, err := sigInput(t, string(b))
	if err != nil {
		return Signed{}, err
	}
	return Signed{T: t, B: string(b), K: Bytes(priv.Public().(ed25519.PublicKey)), S: ed25519.Sign(priv, in)}, nil
}

// SignKID is like Sign, but names the signer by a server key ID instead of
// embedding the public key (SPEC §4.3). Servers use it for receipts and S2S requests.
func SignKID(t string, body any, priv ed25519.PrivateKey, kid string) (Signed, error) {
	s, err := Sign(t, body, priv)
	if err != nil {
		return Signed{}, err
	}
	s.K, s.KID = nil, kid
	return s, nil
}

// KeyBytes returns the signer's public key, if the envelope carries one.
func (s Signed) KeyBytes() ([]byte, bool) {
	if s.KID != "" || len(s.K) != ed25519.PublicKeySize {
		return nil, false
	}
	return s.K, true
}

// KeyID returns the server key ID, if the envelope names one.
func (s Signed) KeyID() (string, bool) { return s.KID, s.KID != "" && s.K == nil }

// Verify checks the signature against pub (and that the type is t, if t isn't empty).
// It doesn't check that pub is authorized; that's the caller's job.
func (s Signed) Verify(t string, pub ed25519.PublicKey) error {
	if t != "" && s.T != t {
		return fmt.Errorf("%w: got %q, want %q", ErrWrongType, s.T, t)
	}
	in, err := sigInput(s.T, s.B)
	if err != nil {
		return err
	}
	if !VerifyStrict(pub, in, s.S) {
		return ErrBadSignature
	}
	return nil
}

// VerifySelf verifies against the public key in K itself. Use it when the caller
// then checks that key's authority separately (devices, recovery commitments).
func (s Signed) VerifySelf(t string) (ed25519.PublicKey, error) {
	k, ok := s.KeyBytes()
	if !ok {
		return nil, ErrBadSignature
	}
	return ed25519.PublicKey(k), s.Verify(t, k)
}

// OpenClosed is Open for the closed schemas of SPEC §19.2: a member v doesn't
// declare is an error, not ignored.
func (s Signed) OpenClosed(v any) error { return UnmarshalClosed([]byte(s.B), v) }

// Open decodes the body into v. The signature is over the text as received, so
// any valid I-JSON is accepted (SPEC §4.3).
func (s Signed) Open(v any) error { return Unmarshal([]byte(s.B), v) }

// Encode returns JCS of the whole envelope. Hashes of signed objects (chain prev,
// identifiers, declines) are SHA-256 over these bytes, however the object traveled.
func (s Signed) Encode() ([]byte, error) { return Marshal(s) }

// Hash is SHA-256(JCS(signed)) (SPEC §4.3).
func (s Signed) Hash() ([]byte, error) {
	enc, err := s.Encode()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(enc)
	return sum[:], nil
}

// DecodeSigned decodes an envelope from any valid I-JSON and checks its shape. The envelope
// is closed (SPEC §4.3): a member other than t, b, k, kid, and s is an error, not ignored,
// since the object's hash covers the whole envelope.
func DecodeSigned(data []byte) (Signed, error) {
	var s Signed
	if err := UnmarshalClosed(data, &s); err != nil {
		return Signed{}, err
	}
	if s.T == "" || len(s.S) != ed25519.SignatureSize || (len(s.K) == 0) == (s.KID == "") {
		return Signed{}, errors.New("wire: malformed signed object")
	}
	if len(s.K) != 0 && len(s.K) != ed25519.PublicKeySize {
		return Signed{}, errors.New("wire: signer key must be 32 bytes")
	}
	if err := CheckIJSON([]byte(s.B)); err != nil {
		return Signed{}, fmt.Errorf("signed body: %w", err)
	}
	return s, nil
}

// CanonicalSigned re-encodes a signed object as JCS, so stored copies compare byte for byte.
func CanonicalSigned(data []byte) ([]byte, error) {
	s, err := DecodeSigned(data)
	if err != nil {
		return nil, err
	}
	return s.Encode()
}

// VerifyStrict is Ed25519 verification as SPEC §4.3 pins it: S < L, A and R not of small
// order, and the cofactorless equation. crypto/ed25519 does the first and the last.
func VerifyStrict(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if SmallOrder(pub) || SmallOrder(sig[:32]) || !Canonical25519(pub) || !Canonical25519(sig[:32]) {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// Canonical25519 reports whether a point encoding is canonical: with the sign bit cleared,
// the little-endian y is less than p = 2^255 - 19 (SPEC §4.3, as libsodium checks).
func Canonical25519(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	// y >= p exactly when bytes 1..30 are 0xff, byte 31 (sign bit cleared) is 0x7f, and byte 0 >= 0xed.
	if b[31]&0x7f != 0x7f {
		return true
	}
	for i := 30; i >= 1; i-- {
		if b[i] != 0xff {
			return true
		}
	}
	return b[0] < 0xed
}

// smallOrder lists the encodings of the small-order Edwards points (libsodium's list),
// compared with the sign bit of the last byte cleared (SPEC §4.3).
var smallOrder = [7][32]byte{
	{},
	{0x01},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// SmallOrder reports whether a 32-byte point encoding is one of the small-order points.
func SmallOrder(p []byte) bool {
	if len(p) != 32 {
		return true
	}
	var q [32]byte
	copy(q[:], p)
	q[31] &= 0x7f
	for _, bad := range smallOrder {
		if q == bad {
			return true
		}
	}
	return false
}
