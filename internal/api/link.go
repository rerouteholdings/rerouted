package api

import (
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Link proofs (spec/api/client-stage3.md): during sign-in with another device, the
// new device signs the confirmation code shown on the approving device and leaves it
// here, and the approving device picks it up before appending add-device. Proofs are
// short-lived and only kept in memory: a restart just means starting the sign-in again.

const (
	linkProofTTL      = 10 * 60 // seconds
	linkProofAttempts = 5       // per new device key, so the 40-bit code can't be guessed
	// Proofs and parked keys are unauthenticated, so they're limited per source address
	// and per identity too (SPEC §7.2), each per hour.
	linkProofsPerAddress  = 30
	linkProofsPerIdentity = 30
)

type linkProof struct {
	enc      []byte // the signed link-proof
	attempts int
	expires  int64
}

type linkProofs struct {
	mu sync.Mutex
	m  map[string]*linkProof // id + "|" + hex(device key)
}

func (l *linkProofs) sweep(t int64) {
	for k, p := range l.m {
		if p.expires < t {
			delete(l.m, k)
		}
	}
}

// POST link/proof, no session: the new device isn't signed in yet.
// hpkeKeySize is an MLKEM768-X25519 public key (SPEC §3).
const hpkeKeySize = 1216

func (s *Server) postLinkProof(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proof wire.Raw `json:"proof"`
	}
	if !readBody(w, r, &req) {
		return
	}
	// Unauthenticated, so limited per source address too (SPEC §7.2).
	if !s.limits.allow("link|"+clientIP(r), linkProofsPerAddress, 3600, now(), true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 3600})
		return
	}
	sig, ok := decodeSignedField(w, req.Proof)
	if !ok {
		return
	}
	key, err := sig.VerifySelf("link-proof")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var body struct {
		ID   string     `json:"id"`
		Code string     `json:"code"`
		TS   int64      `json:"ts"`
		HPKE wire.Bytes `json:"hpke"`
	}
	// A proof carries the confirmation code, the new device's one-time HPKE key for the
	// link bundle (SPEC §7.2), or both. One with only the key "parks" it.
	if sig.Open(&body) != nil || (body.Code == "" && len(body.HPKE) == 0) || len(body.Code) > 32 || (len(body.HPKE) != 0 && len(body.HPKE) != hpkeKeySize) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	t := now()
	if body.TS > t+600 || body.TS+600 < t {
		s.writeClockSkew(w, body.TS, 600)
		return
	}
	st, _, err := s.identity(r.Context(), body.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	if st.HasDevice(key) {
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "already a device on this account")
		return
	}
	// And per identity, whatever the address: requests spread over many addresses, each
	// with a fresh device key, would otherwise get around both limits above.
	if !s.limits.allow("link-id|"+body.ID, linkProofsPerIdentity, 3600, t, true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 3600})
		return
	}
	enc, _ := sig.Encode()
	k := body.ID + "|" + hex.EncodeToString(key)
	s.links.mu.Lock()
	defer s.links.mu.Unlock()
	s.links.sweep(t)
	p := s.links.m[k]
	if p == nil {
		p = &linkProof{}
		s.links.m[k] = p
	}
	if p.attempts >= linkProofAttempts {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Msg: "too many tries; start the sign-in again", Retry: linkProofTTL})
		return
	}
	// Only proofs with a code count as guesses; parking the HPKE key doesn't.
	if body.Code != "" {
		p.attempts++
	} else if p.enc != nil && p.expires > t {
		parked := false
		if old, err := wire.DecodeSigned(p.enc); err == nil {
			var ob struct {
				Code string `json:"code"`
			}
			parked = old.Open(&ob) == nil && ob.Code == ""
		}
		if !parked {
			writeBody(w, http.StatusAccepted, map[string]any{}) // a code proof is waiting: keep it
			return
		}
	}
	p.enc, p.expires = enc, t+linkProofTTL
	writeBody(w, http.StatusAccepted, map[string]any{})
}

// GET link/proof/{device}: the account's own devices pick up a proof.
func (s *Server) getLinkProof(w http.ResponseWriter, r *http.Request, sess session) {
	dev, err := wire.DecodeB64(r.PathValue("device"))
	if err != nil || len(dev) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "device must be a base64url device key")
		return
	}
	s.links.mu.Lock()
	defer s.links.mu.Unlock()
	s.links.sweep(now())
	p := s.links.m[sess.id+"|"+hex.EncodeToString(dev)]
	if p == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"proof": wire.Raw(p.enc)})
}

// clientIP is the caller's address. Behind a reverse proxy on the same machine (rerouted
// listens on localhost), it's the first X-Forwarded-For entry.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			first, _, _ := strings.Cut(f, ",")
			return strings.TrimSpace(first)
		}
	}
	return host
}
