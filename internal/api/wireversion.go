package api

import (
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

// v1Only answers 501 on the version 2 API, for endpoints whose version 2 form rerouted
// doesn't serve yet: groups and their hub (SPEC §11.6), which wait for version 2's epoch
// keys and receipts.
func (s *Server) v1Only(h http.HandlerFunc) http.HandlerFunc {
	if s.wv == wire.V2 {
		return notImplemented
	}
	return h
}
