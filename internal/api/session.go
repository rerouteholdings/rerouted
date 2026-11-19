package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// session is the authenticated caller of a client API request.
type session struct {
	id        string
	device    []byte
	tokenHash []byte
}

const tokenTTL = 30 * 24 * time.Hour

func now() int64 { return time.Now().Unix() + testClockOffset() }

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

// authed wraps a handler that needs a bearer token (spec/api/conventions.md).
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "missing bearer token")
			return
		}
		sum := sha256.Sum256([]byte(tok))
		id, dev, err := s.st.Sessions().LookupToken(r.Context(), sum[:], now())
		if err != nil {
			writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "")
			return
		}
		h(w, r, session{id: id, device: dev, tokenHash: sum[:]})
	}
}

// revokeRemoved ends the sessions of the devices in `before` that `after` no longer has,
// and returns them. Run it before storing the chain change that removes them: if it
// fails, nothing has changed, and if storing the change fails afterwards, the devices are
// still in the chain and can sign in again. The other way round, a failure would leave a
// removed device signed in.
func (s *Server) revokeRemoved(ctx context.Context, id string, before, after map[string]string) ([][]byte, error) {
	var removed [][]byte
	for k := range before {
		if _, still := after[k]; !still {
			if err := s.st.Sessions().RevokeDevice(ctx, id, unhex(k)); err != nil {
				return nil, err
			}
			if err := s.st.Push().DropAPNSDevice(ctx, id, unhex(k)); err != nil {
				return nil, err
			}
			removed = append(removed, unhex(k))
		}
	}
	return removed, nil
}

// writeChainWriteError answers a failed chain write: 409 stale-head if the head moved
// since it was read, and 503 for a storage failure, which the client retries as is.
func writeChainWriteError(w http.ResponseWriter, s *Server, err error) {
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, wire.ErrCodeStaleHead, "")
		return
	}
	if errors.Is(err, store.ErrHandleTaken) {
		writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "")
		return
	}
	s.unavailableRead(w, "writing a chain", err)
}

// identity loads and validates a local identity's chain.
func (s *Server) identity(ctx context.Context, id string) (*chain.State, [][]byte, error) {
	raw, err := s.st.Chains().Entries(ctx, id, -1)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.decodeChain(raw)
	return st, raw, err
}

// ---- POST register ----

// reservedHandles can't be registered as subdomain handles: they could pass for official
// accounts (SPEC §5.4). Some are also hostnames a server may use, like www.chat.example.
var reservedHandles = map[string]bool{
	"admin": true, "administrator": true, "root": true, "system": true, "support": true, "help": true,
	"security": true, "abuse": true, "postmaster": true, "hostmaster": true, "webmaster": true, "www": true,
	"mail": true, "api": true, "staff": true, "mod": true, "moderator": true, "official": true,
	"verified": true, "tieroute": true, "reroute": true, "rerouted": true,
}

func validHandleUnder(handle, domain string) bool {
	label, ok := strings.CutSuffix(handle, "."+domain)
	if !ok || label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for _, c := range label {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Genesis wire.Raw   `json:"genesis"`
		Chain   []wire.Raw `json:"chain"`
		Move    wire.Raw   `json:"move"`
		Invite  string     `json:"invite,omitempty"`
		Check   bool       `json:"check,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Check && len(req.Chain) == 0 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `"check" is for moves, with "chain"`)
		return
	}
	// A version 2 genesis that names a version 1 identity was registered with that
	// identity's migrate, which needed no invite (SPEC §6.8): this only confirms it.
	if s.wv == wire.V2 && len(req.Chain) == 0 && req.Genesis != nil {
		if sig, err := s.decodeSigned(req.Genesis); err == nil {
			if st, _, err := s.genesis(sig); err == nil && st.MigratedFrom != "" {
				enc, _ := sig.Encode()
				s.registerMigrated(w, r, st, enc)
				return
			}
		}
	}
	// Registration is by invite (SPEC §8.2). Open signups are a published code.
	reg := s.cfg.Now()
	switch {
	case reg.Registration == "invite" && subtle.ConstantTimeCompare([]byte(req.Invite), []byte(reg.RegistrationCode)) == 1:
	case reg.Registration == "invite":
		writeError(w, http.StatusForbidden, wire.ErrCodeBadInvite, "registration needs a valid invite code")
		return
	default:
		writeError(w, http.StatusForbidden, wire.ErrCodeRegistrationClosed, "")
		return
	}
	if len(req.Chain) > 0 {
		s.registerMove(w, r, req.Chain, req.Move, req.Check)
		return
	}
	sig, ok := s.decodeSignedField(w, req.Genesis)
	if !ok {
		return
	}
	st, applied, err := s.genesis(sig)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	if chain.CheckClock(applied.Entry.TS, uint64(now()), true) != nil {
		s.writeClockSkew(w, int64(applied.Entry.TS), chain.MaxSkew)
		return
	}
	if st.Home != s.cfg.Name {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "set-home must name this server")
		return
	}
	if s.cfg.Handles == "" || !validHandleUnder(st.Handle, s.cfg.Handles) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "handle must be <name>."+s.cfg.Handles)
		return
	}
	if reservedHandles[strings.TrimSuffix(st.Handle, "."+s.cfg.Handles)] {
		writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "that name is reserved")
		return
	}
	enc, _ := sig.Encode()
	switch err := s.st.Chains().Create(r.Context(), st.ID, enc, st.Handle); {
	case errors.Is(err, store.ErrHandleTaken):
		writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, wire.ErrCodeUnavailable, "")
		return
	}
	s.log.Info("registered", "id", st.ID, "handle", st.Handle)
	writeBody(w, http.StatusOK, map[string]any{"id": st.ID})
}

// ---- POST auth/challenge, auth/session, auth/logout ----

func (s *Server) authChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID  string     `json:"id"`
		Key wire.Bytes `json:"key"`
	}
	if !readBody(w, r, &req) {
		return
	}
	st, _, err := s.identity(r.Context(), req.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	if !st.HasDevice(req.Key) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not a current device")
		return
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	t := now()
	exp := t + 60
	if err := s.st.Sessions().PutNonce(r.Context(), req.ID, req.Key, nonce, exp); err != nil {
		s.unavailableRead(w, "storing an auth challenge", err)
		return
	}
	// `now`: the homeserver is the clock, and the client corrects for the difference (SPEC §8.4).
	writeBody(w, http.StatusOK, map[string]any{"nonce": nonce, "expires": exp, "now": t})
}

func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Auth wire.Raw `json:"auth"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := s.decodeSignedField(w, req.Auth)
	if !ok {
		return
	}
	key, err := s.signer(sig, "auth")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var body struct {
		ID     string     `json:"id"`
		Nonce  wire.Bytes `json:"nonce"`
		Server string     `json:"server"`
		TS     int64      `json:"ts"`
		Name   string     `json:"name,omitempty"`
	}
	if err := sig.Open(&body); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, err.Error())
		return
	}
	if body.Server != s.cfg.Name {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "signed for a different server")
		return
	}
	if absDiff(body.TS, now()) > chain.MaxSkew {
		s.writeClockSkew(w, body.TS, chain.MaxSkew)
		return
	}
	st, _, err := s.identity(r.Context(), body.ID)
	if err != nil || !st.HasDevice(key) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "")
		return
	}
	if !s.deviceSigned(st, sig, "auth", key) { // wire version 2: the composite key in the chain
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	if err := s.st.Sessions().TakeNonce(r.Context(), body.ID, key, body.Nonce, now()); err != nil {
		writeError(w, http.StatusGone, wire.ErrCodeExpired, "nonce unknown, used, or expired")
		return
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(tok))
	exp := time.Now().Add(tokenTTL).Unix()
	if err := s.st.Sessions().CreateToken(r.Context(), sum[:], body.ID, key, body.Name, exp); err != nil {
		s.unavailableRead(w, "creating a session", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"token": tok, "expires": exp})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request, sess session) {
	// A failed sign-out must never look like it worked: the token would still be live.
	if err := s.st.Sessions().RevokeToken(r.Context(), sess.tokenHash); err != nil {
		s.unavailableRead(w, "signing out", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- chains ----

func (s *Server) getChain(w http.ResponseWriter, r *http.Request, sess session) {
	id := r.PathValue("id")
	home := r.URL.Query().Get("home")
	if sess.id == "" {
		home = "" // without a session, only local and already-cached chains (no fetching for strangers)
	}
	// fresh: the client is about to reject something on the strength of this chain, so
	// ask its home again rather than trust the cache (SPEC §7.1, §11.8). What comes back
	// is still accepted only under §6.5.
	// It answers with an error, never the cache, when it can't: the client is about to decide
	// on what it gets, and the cache may be missing a removal.
	// On version 2, the identity may be a version 1 one that migrated, whose closed chain a
	// version 2 client checks (SPEC §6.8, below): one of ours needs no fetching either.
	v1Local := s.wv == wire.V2 && s.legacy().isLocal(r.Context(), id)
	if r.URL.Query().Get("fresh") == "1" && !s.isLocal(r.Context(), id) && !v1Local {
		from := home
		if cached, _, err := s.st.Remote().Get(r.Context(), id); err == nil && from == "" {
			from = cached
		}
		if from == "" && s.wv == wire.V2 {
			if cached, _, err := s.legacy().st.Remote().Get(r.Context(), id); err == nil {
				from = cached
			}
		}
		// Someone who moved away from here: ask where they went, not us (our copy is the
		// tombstone, which stops at the move).
		if from == "" || from == s.cfg.Name {
			if moved := s.tombstoneHome(r.Context(), id); moved != "" {
				from = moved
			}
		}
		switch {
		case sess.id == "":
			writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "fresh needs a session")
			return
		case from == "" || from == s.cfg.Name || s.fed == nil:
			writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no home to ask")
			return
		case !s.limits.allow("fresh|"+sess.id, 600, 3600, now(), true):
			writeError(w, http.StatusTooManyRequests, wire.ErrCodeRateLimited, "")
			return
		}
		if _, _, err := s.fetchRemote(r.Context(), id, from, true); err != nil {
			// Not a version 2 identity there: a version 1 one, fetched by version 1's rules
			// and served below only if it ends in migrate (SPEC §6.8).
			if s.wv != wire.V2 {
				writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "couldn't fetch the chain from its home: "+err.Error())
				return
			}
			if _, _, lerr := s.legacy().fetchRemote(r.Context(), id, from, true); lerr != nil {
				writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "couldn't fetch the chain from its home: "+err.Error())
				return
			}
		}
	}
	var all [][]byte
	var err error
	if sess.id == "" {
		all, err = s.lookupCached(r.Context(), id)
	} else {
		_, all, err = s.lookup(r.Context(), id, home)
	}
	if err != nil && s.wv == wire.V2 {
		// A version 1 chain that ends in migrate, for a version 2 client checking a
		// contact's migration: it validates version 1 chains by version 1's rules (SPEC
		// §6.8). Any other version 1 chain stays a stranger here.
		var st *chain.State
		if sess.id == "" {
			if all, err = s.legacy().lookupCached(r.Context(), id); err == nil {
				st, err = s.legacy().decodeChain(all)
			}
		} else {
			st, all, err = s.legacy().lookup(r.Context(), id, home)
		}
		if err == nil && !st.Closed() {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	after := queryInt(r, "after", -1)
	entries := []wire.Raw{}
	for i, e := range all {
		if int64(i) > after {
			entries = append(entries, e)
		}
	}
	writeBody(w, http.StatusOK, map[string]any{"entries": entries, "head": len(all) - 1})
}

func (s *Server) appendChain(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Entry       wire.Raw `json:"entry"`
		Reservation wire.Raw `json:"reservation,omitempty"` // a device-signed move's, from its destination (SPEC §6.6)
		Genesis     wire.Raw `json:"genesis,omitempty"`     // with migrate: the version 2 genesis it names (SPEC §6.8)
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := s.decodeSignedField(w, req.Entry)
	if !ok {
		return
	}
	st, raw, err := s.identity(r.Context(), sess.id)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	enc, _ := sig.Encode()
	if string(enc) == string(raw[len(raw)-1]) { // idempotent retry
		writeBody(w, http.StatusOK, map[string]any{"seq": st.Seq, "head": st.Head})
		return
	}
	var e wire.ChainEntry
	if err := sig.OpenClosed(&e); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	if e.Seq != st.Seq+1 || string(e.Prev) != string(st.Head) {
		writeError(w, http.StatusConflict, wire.ErrCodeStaleHead, "")
		return
	}
	if chain.CheckClock(e.TS, uint64(now()), true) != nil {
		s.writeClockSkew(w, int64(e.TS), chain.MaxSkew)
		return
	}
	before := st.Seq
	devicesBefore := st.Devices
	homeBefore, handleBefore := st.Home, st.Handle
	applied, err := st.Apply(sig)
	switch {
	case errors.Is(err, chain.ErrUnknownOp):
		writeError(w, http.StatusBadRequest, wire.ErrCodeUnknownKind, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	if st.Closed() {
		// migrate: the version 2 identity is registered in the same step (SPEC §6.8).
		s.appendMigrate(w, r, sess, st, before, applied, enc, req.Genesis)
		return
	}
	if req.Genesis != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `"genesis" goes only with migrate`)
		return
	}
	// Moves paused by the operator: refuse a device-signed move before it's stored, so
	// nothing changes, routing included. A recovery-signed entry still goes through.
	if s.cfg.Now().PauseMoves && st.Home != homeBefore && applied.Signer != chain.SignerRecovery {
		s.log.Info("move refused: moves are paused", "id", sess.id)
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, movesPausedMsg)
		return
	}
	// A device-signed move to another server needs that server's reservation, checked
	// before anything is stored: an app that moves without asking first (older clients) is
	// refused here, with nothing changed, rather than left with a chain naming a home that
	// won't take it. A recovery-signed move doesn't need one.
	if st.Home != homeBefore && st.Home != s.cfg.Name && applied.Signer != chain.SignerRecovery {
		sum := sha256.Sum256(enc)
		if status, code, msg := s.checkReservation(r.Context(), req.Reservation, sess.id, st.Home, sum[:]); code != "" {
			s.log.Info("move refused: no valid reservation", "id", sess.id, "to", st.Home, "why", msg)
			writeError(w, status, code, msg)
			return
		}
	}
	// A new name here has to be free, and the one it replaces is held (SPEC §5.3).
	names, status, code, msg := s.handleChange(handleBefore, homeBefore, st, applied.Signer == chain.SignerRecovery)
	if code != "" {
		writeError(w, status, code, msg)
		return
	}
	// Removed devices lose their sessions right away (spec/api/conventions.md). A move
	// away doesn't end any: if a thief made it, the owner's devices still have to see the
	// alarm, and recover within 72 hours (SPEC §6.4.1). Deliveries go to the new home now.
	removed, err := s.revokeRemoved(r.Context(), sess.id, devicesBefore, st.Devices)
	if err != nil {
		s.unavailableRead(w, "revoking a removed device's sessions", err)
		return
	}
	if err := s.appendEntry(r.Context(), sess.id, before, enc, names); err != nil {
		writeChainWriteError(w, s, err)
		return
	}
	for _, dev := range removed {
		s.closeDevice(sess.id, dev)
	}
	if st.Home != s.cfg.Name {
		s.dropPush(r.Context(), sess.id) // moved away: its new home sends its notifications
	}
	// Alerts (SPEC §6.4.1).
	if lvl := chain.Alert(applied); lvl != chain.AlertNone {
		level := "alarm"
		if lvl == chain.AlertNotice {
			level = "notice"
		}
		s.logged("sending a chain alert", s.notify(r.Context(), sess.id, map[string]any{"t": "chain-alert", "level": level, "entry": wire.Raw(enc)}))
	}
	s.pushChain(r.Context(), sess.id) // contacts learn about new or removed devices (SPEC §6.5)
	writeBody(w, http.StatusOK, map[string]any{"seq": st.Seq, "head": st.Head})
}

func (s *Server) resolve(w http.ResponseWriter, r *http.Request, sess session) {
	handle := strings.ToLower(r.PathValue("handle"))
	if id, err := s.st.Chains().ByHandle(r.Context(), handle); err == nil {
		// Registered here, but it only resolves while the chain still names it (SPEC §5.3):
		// after a set-handle to another name, the old one answers like any stale record.
		// The handle document stays served, so the identity can switch back to it.
		st, _, err := s.identity(r.Context(), id)
		if err != nil && s.wv == wire.V1 {
			if st2, _, err2 := s.modern().identity(r.Context(), id); err2 == nil && st2.MigratedFrom != "" {
				// It's a version 2 identity's now: the version 1 one migrated (SPEC §6.8).
				writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, migratedMsg)
				return
			}
		}
		if err != nil || st.Handle != handle {
			writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "handle and chain don't agree")
			return
		}
		writeBody(w, http.StatusOK, map[string]any{"id": id, "home": s.cfg.Name})
		return
	}
	// Fetching from other servers is for signed-in users, so this isn't an open resolver. The
	// exception is this server's own names, its domain and its handle domain, whose documents
	// may be published beside it (the operator's own handle, say): it answers for those to anyone.
	own := handle == s.cfg.Name || (s.cfg.Handles != "" && (handle == s.cfg.Handles || strings.HasSuffix(handle, "."+s.cfg.Handles)))
	if s.fed == nil || (sess.id == "" && !own) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	d, err := s.fed.ResolveHandle(r.Context(), handle)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, err.Error())
		return
	}
	// Fetch and cache the chain now, and check it points back at the handle (SPEC §5.3).
	st, _, err := s.lookup(r.Context(), d.ID, d.Home)
	if err != nil && s.wv == wire.V2 {
		// A record that still names a version 1 identity that migrated resolves to its
		// version 2 identity (SPEC §5.3 step 3, §6.8).
		st, err = s.followMigration(r.Context(), d.ID, d.Home)
	}
	if err == nil && st.Closed() {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, migratedMsg)
		return
	}
	if err != nil || st.Handle != handle {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "handle and chain don't agree")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"id": st.ID, "home": st.Home})
}

// movesPausedMsg is the refusal while the operator has paused moves (REROUTED_PAUSE_MOVES).
const movesPausedMsg = "moving to another homeserver is paused on this server until an app update makes it safe. Nothing has changed: your account stays here, and your recovery code works as usual"

// Move reservations (SPEC §6.6): the destination's signed word that it checked a
// device-signed move and will take it. The old home appends the move only with one.
const (
	reservationTTL  = 10 * 60   // seconds: the same window an entry's ts has (SPEC §6.4)
	reservationHold = retention // the handle stays held this long after exp, unless registered
	noReservation   = "the new homeserver has to accept this move first: update the app, and try again. Nothing has changed: your account stays here"
)

type reservationBody struct {
	ID     string     `json:"id"`
	Server string     `json:"server"`
	Entry  wire.Bytes `json:"entry"`
	Exp    int64      `json:"exp"`
}

// checkReservation checks a move reservation for the entry with hash `entry`, moving `id`
// to `dest`. It returns an HTTP status, error code, and message, or code "" if it's valid.
func (s *Server) checkReservation(ctx context.Context, raw wire.Raw, id, dest string, entry []byte) (int, string, string) {
	if raw == nil {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, noReservation
	}
	sig, err := s.decodeSigned(raw)
	if err != nil {
		return http.StatusBadRequest, wire.ErrCodeBadRequest, "reservation: " + err.Error()
	}
	_, ok := sig.KeyID()
	var body reservationBody
	if sig.T != "move-reservation" || !ok || sig.OpenClosed(&body) != nil {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "that isn't a move reservation"
	}
	if body.ID != id || body.Server != dest || !bytes.Equal(body.Entry, entry) {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "the reservation is for another identity, server, or entry"
	}
	if body.Exp < now() {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "the reservation has expired: ask " + dest + " again"
	}
	if s.fed == nil {
		return http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "this server can't check other servers' signatures"
	}
	if _, err := s.fed.ServerDoc(ctx, dest); err != nil {
		return http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "couldn't reach " + dest + " to check its reservation"
	}
	if s.fed.VerifyServerSigned(ctx, dest, sig, "move-reservation", now()) != nil {
		return http.StatusBadRequest, wire.ErrCodeBadSignature, "the reservation isn't signed by " + dest
	}
	return 0, "", ""
}

// moveBody is a signed `move` (SPEC §6.6): the user's own word that this registration is
// theirs, with the allowlists it brings. The chain is public, so it can't be that.
type moveBody struct {
	ID       string       `json:"id"`
	Server   string       `json:"server"`
	Head     wire.Bytes   `json:"head"`
	TS       int64        `json:"ts"`
	Contacts []string     `json:"contacts"`
	Groups   []wire.Bytes `json:"groups"`
}

// checkMove checks a registration's signed `move` (SPEC §6.6): signed by a current device
// of the moving identity, naming it, this server, and the chain's newest entry, and recent.
// It returns the body, or an error code and message.
func (s *Server) checkMove(raw wire.Raw, st *chain.State, head []byte) (*moveBody, string, string) {
	if raw == nil {
		return nil, wire.ErrCodeBadRequest, "moving here needs a move signed by one of your devices"
	}
	sig, err := s.decodeSigned(raw)
	if err != nil || sig.T != "move" {
		return nil, wire.ErrCodeBadRequest, "move: not a signed move"
	}
	key, err := s.signer(sig, "move")
	if err != nil || !s.deviceSigned(st, sig, "move", key) {
		return nil, wire.ErrCodeBadSignature, "the move isn't signed by a current device"
	}
	var mv moveBody
	if sig.OpenClosed(&mv) != nil || mv.ID != st.ID || mv.Server != s.cfg.Name || !bytes.Equal(mv.Head, head) {
		return nil, wire.ErrCodeBadRequest, "the move names another identity, server, or chain head"
	}
	if mv.TS < 0 || chain.CheckClock(uint64(mv.TS), uint64(now()), true) != nil {
		return &mv, wire.ErrCodeClockSkew, "the move has to be recent"
	}
	if len(mv.Contacts) > 10000 || len(mv.Groups) > 10000 {
		return nil, wire.ErrCodeTooLarge, ""
	}
	return &mv, "", ""
}

// registerMove takes an identity that's moving here (SPEC §6.6, §8.2): its whole chain,
// whose newest entry sets this server as home. A device-signed move has to be one the
// previous home appended (§6.5); a recovery-signed one counts from anywhere. The user's
// contact and group allowlists come along in a `move` signed by one of the identity's
// current devices, since anyone who has seen the chain could otherwise register it first,
// with allowlists of their choosing (§10.3).
//
// With check, nothing is registered: it's the client asking, before it gives the previous
// home the move, whether this server would take it (SPEC §6.6). Every check runs except
// asking the previous home about the newest entry, which it doesn't have yet. A client that
// moved without asking could be left with a chain naming a home that refuses it.
func (s *Server) registerMove(w http.ResponseWriter, r *http.Request, in []wire.Raw, moveRaw wire.Raw, check bool) {
	ctx := r.Context()
	if len(in) > 10000 {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "")
		return
	}
	raw := make([][]byte, len(in))
	for i, e := range in {
		raw[i] = e
	}
	raw, err := s.canonChain(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	st, err := s.decodeChain(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	if st.Home != s.cfg.Name {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "the chain's newest home must be this server")
		return
	}
	// Moves paused by the operator: a device-signed move isn't taken, or checked as if it
	// would be. A recovery-signed one still is.
	if s.cfg.Now().PauseMoves {
		if _, byRecovery, n := s.replay(raw); n == len(raw) && !byRecovery[n-1] {
			s.log.Info("move refused: moves are paused", "id", st.ID, "check", check)
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, movesPausedMsg)
			return
		}
	}
	last, _ := s.decodeSigned(raw[len(raw)-1])
	var e wire.ChainEntry
	if last.OpenClosed(&e) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "")
		return
	}
	head, _ := last.Hash()
	mv, code, msg := s.checkMove(moveRaw, st, head)
	if code == wire.ErrCodeClockSkew && mv != nil {
		s.writeClockSkew(w, mv.TS, chain.MaxSkew)
		return
	}
	if code != "" {
		writeError(w, http.StatusBadRequest, code, msg)
		return
	}
	// Authentication and freshness always precede receipt lookup. A completed
	// operation needs neither re-vouching by the old home nor any routing effects.
	op, err := (store.MoveIntent{ID: mv.ID, Server: mv.Server, Head: mv.Head, Contacts: mv.Contacts, Groups: mv.Groups}).Encode()
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	reg := store.MoveRegistration{ID: st.ID, Handle: st.Handle, Operation: op, Entries: raw, Check: check, Probe: true}
	if _, err := s.st.Chains().RegisterMove(ctx, reg); err == nil {
		writeBody(w, http.StatusOK, map[string]any{"id": st.ID})
		return
	} else if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "") // SPEC §6.6: storage failure
		return
	}
	reg.Probe = false
	// Only a genuine return may extend an existing local tombstone. A foreign
	// genesis or a partially written arrival is not proof we ever hosted it.
	var expected [][]byte
	have, err := s.st.Chains().Entries(ctx, st.ID, -1)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	if len(have) > 0 && len(have) < len(raw) && hasPrefix(raw, have) {
		local, localErr := s.decodeChain(have)
		if localErr == nil && local.Home != s.cfg.Name {
			homes, _, _ := s.replay(have)
			for _, home := range homes {
				if home == s.cfg.Name {
					expected = have
					break
				}
			}
		}
	}
	if s.cfg.Handles == "" || !validHandleUnder(st.Handle, s.cfg.Handles) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "handle must be <name>."+s.cfg.Handles)
		return
	}
	if reservedHandles[strings.TrimSuffix(st.Handle, "."+s.cfg.Handles)] {
		writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "that name is reserved")
		return
	}
	// The move away from the previous home has to be one that home knows about.
	upto := len(raw)
	if check {
		upto--
	}
	confirmed, err := s.confirmMoves(ctx, st.ID, raw, s.cfg.Name, upto)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	// A newest entry the previous home appended had its clock checked there (SPEC §6.4 rule
	// 5), so a registration that comes late, after a lost reply or a crash, still works. Any
	// other newest entry (recovery-signed, or one its previous home never knew) is first
	// accepted here, and has to be recent.
	if !confirmed && chain.CheckClock(e.TS, uint64(now()), true) != nil {
		s.writeClockSkew(w, int64(e.TS), chain.MaxSkew)
		return
	}
	reg.Expected = expected
	// A device-signed move asked about before the old home appends it gets a reservation:
	// the old home won't append it without one (SPEC §6.6). Recovery-signed moves don't.
	var res *reservationBody
	if prev, byRecovery, n := s.replay(raw); check && n == len(raw) && !byRecovery[n-1] && prev[n-1] != s.cfg.Name {
		res = &reservationBody{ID: st.ID, Server: s.cfg.Name, Entry: head, Exp: now() + reservationTTL}
		reg.Reserve = &store.MoveReservation{ID: st.ID, Entry: head, Handle: st.Handle, Exp: res.Exp, Hold: res.Exp + reservationHold}
	}
	for _, id := range mv.Contacts {
		if id != st.ID && wire.ValidIdentityID(id) {
			reg.Contacts = append(reg.Contacts, store.Contact{ID: id, State: store.StateContact, Since: now()})
		}
	}
	for _, g := range mv.Groups {
		if len(g) == 32 {
			reg.Groups = append(reg.Groups, g)
		}
	}
	committed, err := s.st.Chains().RegisterMove(ctx, reg)
	switch {
	case errors.Is(err, store.ErrHandleTaken):
		writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	case err != nil:
		// SPEC §6.6: nothing was stored, and the client can retry.
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	if check {
		out := map[string]any{"id": st.ID}
		if committed && res != nil {
			signed, err := s.fed.SignKID("move-reservation", res)
			if err != nil {
				writeError(w, http.StatusInternalServerError, wire.ErrCodeUnavailable, "")
				return
			}
			enc, _ := signed.Encode()
			out["reservation"] = wire.Raw(enc)
			s.log.Info("move reserved", "id", st.ID, "handle", st.Handle)
		}
		writeBody(w, http.StatusOK, out)
		return
	}
	if committed {
		s.pushChain(ctx, st.ID)
		s.log.Info("move registration accepted", "id", st.ID, "handle", st.Handle)
	}
	writeBody(w, http.StatusOK, map[string]any{"id": st.ID})
}
