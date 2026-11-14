package api

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Wire versions side by side (SPEC §5.1, §6.8). rerouted serves wire version 1 and wire
// version 2 at once, each under its own API base, as two Servers sharing one mux and one
// database: the version 1 Server, which New returns, owns discovery and holds its version
// 2 sibling in v2. Each Server sees only its own version's identities (store.ForWire),
// decodes and verifies only its own version's signatures, and federates through its own
// Fed, so a signature of one version is never accepted on the other's API.
//
// The handlers are the same code for both versions. What differs goes through the methods
// in this file: decoding signed objects, validating chains, and checking an object a
// device signed. In wire version 1, a device's key is in k and signs with Ed25519; in
// version 2, k names the device by its key's Ed25519 component, and the composite key
// that signed comes from the identity's chain (SPEC §3.2.2).

// decodeSigned decodes a signed object under this Server's wire version.
func (s *Server) decodeSigned(b []byte) (wire.Signed, error) {
	return wire.DecodeSignedFor(s.wv, b)
}

// decodeSignedField decodes a signed object carried inside a leniently decoded body,
// writing the error response itself on failure. The envelope itself must be canonical,
// because it's hashed (SPEC §4.1).
func (s *Server) decodeSignedField(w http.ResponseWriter, raw wire.Raw) (wire.Signed, bool) {
	sig, err := s.decodeSigned(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "signed object: "+err.Error())
		return wire.Signed{}, false
	}
	return sig, true
}

// decodeChain decodes and validates a chain under this Server's wire version.
func (s *Server) decodeChain(raw [][]byte) (*chain.State, error) { return decodeChainFor(s.wv, raw) }

// canonChain is canonChainFor under this Server's wire version.
func (s *Server) canonChain(in [][]byte) ([][]byte, error) { return canonChainFor(s.wv, in) }

// replay is replayFor under this Server's wire version.
func (s *Server) replay(raw [][]byte) ([]string, []bool, int) { return replayFor(s.wv, raw) }

// fromHome is fromHome under this Server's wire version.
func (s *Server) fromHome(raw [][]byte, from string, now int64, grace bool) bool {
	return fromHomeFor(s.wv, raw, from, now, grace)
}

// genesis validates a genesis entry under this Server's wire version.
func (s *Server) genesis(sig wire.Signed) (*chain.State, *chain.Applied, error) {
	return chain.GenesisFor(s.wv, sig)
}

// errNotDeviceKey is a version 2 object a device signs whose k isn't a device key.
var errNotDeviceKey = errors.New("k must name a device by its 32-byte key")

// signer returns the device key that claims to have signed sig, an object of type t that a
// device signs with k. In wire version 1 the claim is checked here, against the key in k.
// In version 2 it can't be yet: the composite key is in the signer's chain, so deviceSigned
// checks the signature once the caller has the chain.
func (s *Server) signer(sig wire.Signed, t string) ([]byte, error) {
	if s.wv != wire.V2 {
		return sig.VerifySelf(t)
	}
	if sig.T != t {
		return nil, wire.ErrWrongType
	}
	if len(sig.K) != ed25519.PublicKeySize || sig.KID != "" || len(sig.S) != wire.CompositeSignatureSize {
		return nil, errNotDeviceKey
	}
	return sig.K, nil
}

// deviceSigned reports whether key, from signer, is a current device of st, and in wire
// version 2, whether that device's composite key signed sig.
func (s *Server) deviceSigned(st *chain.State, sig wire.Signed, t string, key []byte) bool {
	if st == nil || !st.HasDevice(key) {
		return false
	}
	if s.wv != wire.V2 {
		return true
	}
	return sig.VerifyComposite(t, st.DevicePub(key)) == nil
}

// selfSigned verifies an object whose signer isn't in a chain yet, carrying its own key in
// k, and returns the device key it names: a new device's link proof (SPEC §7.2). In wire
// version 2, k is the whole composite key, and the device key is its Ed25519 component.
func (s *Server) selfSigned(sig wire.Signed, t string) ([]byte, error) {
	if s.wv != wire.V2 {
		return sig.VerifySelf(t)
	}
	pub, err := sig.VerifyCompositeSelf(t)
	if err != nil {
		return nil, err
	}
	return pub.Ed25519(), nil
}

// epochKeyOK reports whether b can be a group's epoch key, `next`, or one-time `reg` key
// (SPEC §11.6). In wire version 1 it's 32 bytes. In version 2 it's a composite public key
// (SPEC §3.2.2) whose Ed25519 component is canonical and not of small order (SPEC §4.3):
// nothing could ever sign for any other, so a group whose next key it was would freeze.
func (s *Server) epochKeyOK(b []byte) bool {
	if s.wv != wire.V2 {
		return len(b) == ed25519.PublicKeySize
	}
	pub, err := wire.ParseCompositePublicKey(b)
	if err != nil {
		return false
	}
	ed := pub.Ed25519()
	return !wire.SmallOrder(ed) && wire.Canonical25519(ed)
}

// epochSigned reports whether sig, of type t, was signed with the epoch key the hub holds
// (SPEC §11.6): in wire version 1, the Ed25519 key in k; in version 2, the composite key in
// k, which has to be that key exactly.
func (s *Server) epochSigned(sig wire.Signed, t string, key []byte) bool {
	if s.wv != wire.V2 {
		k, ok := sig.KeyBytes()
		return ok && bytes.Equal(k, key) && sig.Verify(t, k) == nil
	}
	if sig.KID != "" || !bytes.Equal(sig.K, key) {
		return false
	}
	_, err := sig.VerifyCompositeSelf(t)
	return err == nil
}

// selfKey verifies an object signed by the key it carries in k, and returns that key: a
// one-time `reg` key's epoch-key registration (SPEC §11.6). In wire version 2 it's the
// whole composite key.
func (s *Server) selfKey(sig wire.Signed, t string) ([]byte, error) {
	if s.wv != wire.V2 {
		return sig.VerifySelf(t)
	}
	pub, err := sig.VerifyCompositeSelf(t)
	if err != nil {
		return nil, err
	}
	return pub.Bytes(), nil
}

// publicMessage reports whether data is an MLSMessage framed as a PublicMessage: protocol
// version mls10 (1), then wire_format public_message (1) (RFC 9420 §6).
func publicMessage(data []byte) bool {
	return len(data) >= 4 && data[0] == 0 && data[1] == 1 && data[2] == 0 && data[3] == 1
}
