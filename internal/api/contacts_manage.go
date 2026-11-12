package api

import (
	"bytes"
	"context"
	"net/http"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// After a decline, the requester can't send another request for 30 days (SPEC §9.3).
const declineCooldown = 30 * 24 * 3600

// contactDecline is the body of a signed contact-decline (SPEC §9.3).
type contactDecline struct {
	From    string     `json:"from"`
	To      string     `json:"to"`
	Request wire.Bytes `json:"request"`
	TS      int64      `json:"ts"`
}

// ---- POST contacts/decline (spec/api/client-stage1.md) ----

func (s *Server) contactDeclineReq(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Decline wire.Raw `json:"decline"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := decodeSignedField(w, req.Decline)
	if !ok {
		return
	}
	key, err := sig.VerifySelf("contact-decline")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var d contactDecline
	if err := sig.OpenClosed(&d); err != nil || d.From != sess.id || !wire.ValidIdentityID(d.To) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	if me, _, err := s.identity(ctx, sess.id); err != nil || !me.HasDevice(key) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "signer isn't a current device")
		return
	}
	c, err := s.st.Contacts().Get(ctx, sess.id, d.To)
	if err != nil || c.State != store.StatePendingIn || !requestMatches(c.Request, d.Request) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no pending request from that identity matches")
		return
	}
	// Our side: no new requests from them for 30 days.
	s.st.Contacts().Put(ctx, sess.id, store.Contact{ID: d.To, State: store.StateDeclined, Since: now()})
	if s.isLocal(ctx, d.To) {
		s.receiveDecline(ctx, d, req.Decline)
	} else if them, _, err := s.lookup(ctx, d.To, ""); err == nil && s.fed != nil {
		s.enqueue(ctx, them.Home, "contacts/decline", map[string]any{"decline": req.Decline})
	}
	writeBody(w, http.StatusAccepted, map[string]any{})
}

// receiveDecline clears the requester's pending request and tells their devices, if the
// decline matches a request they sent (SPEC §9.3). Anything else is dropped silently.
func (s *Server) receiveDecline(ctx context.Context, d contactDecline, raw wire.Raw) {
	c, err := s.st.Contacts().Get(ctx, d.To, d.From)
	if err != nil || c.State != store.StatePendingOut || !requestMatches(c.Request, d.Request) {
		return
	}
	s.st.Contacts().Delete(ctx, d.To, d.From)
	s.notify(ctx, d.To, map[string]any{"t": "contact-declined", "decline": raw})
}

// requestMatches reports whether stored (an encoded signed contact-request) hashes to h.
func requestMatches(stored []byte, h []byte) bool {
	if stored == nil {
		return false
	}
	sig, err := wire.DecodeSigned(stored)
	if err != nil {
		return false
	}
	sum, err := sig.Hash()
	return err == nil && bytes.Equal(sum, h)
}

// ---- S2S contacts/decline (spec/api/s2s-stage2.md) ----

func (s *Server) s2sContactDecline(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Decline wire.Raw `json:"decline"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	sig, err := wire.DecodeSigned(req.Decline)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	key, err := sig.VerifySelf("contact-decline")
	var d contactDecline
	if err != nil || sig.OpenClosed(&d) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	ctx := r.Context()
	// The decliner has to live on the caller, and sign with one of their devices.
	if !s.remoteUser(ctx, d.From, from) {
		writeBody(w, http.StatusAccepted, map[string]any{})
		return
	}
	if st, _, err := s.lookup(ctx, d.From, ""); err != nil || !st.HasDevice(key) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "signer isn't a current device")
		return
	}
	if s.isLocal(ctx, d.To) {
		s.receiveDecline(ctx, d, req.Decline)
	}
	writeBody(w, http.StatusAccepted, map[string]any{})
}

// ---- cancel, remove, block, unblock (SPEC §9.6) ----

func (s *Server) contactCancel(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := readID(w, r)
	if !ok {
		return
	}
	c, err := s.st.Contacts().Get(r.Context(), sess.id, id)
	if err != nil || c.State != store.StatePendingOut {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no pending request to that identity")
		return
	}
	s.st.Contacts().Delete(r.Context(), sess.id, id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) contactRemove(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := readID(w, r)
	if !ok {
		return
	}
	c, err := s.st.Contacts().Get(r.Context(), sess.id, id)
	if err != nil || c.State == store.StateBlocked || c.State == store.StateDeclined {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	s.st.Contacts().Delete(r.Context(), sess.id, id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) contactBlock(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := readID(w, r)
	if !ok {
		return
	}
	// Blocking replaces whatever was there: contact, request, or decline (SPEC §9.6).
	s.st.Contacts().Put(r.Context(), sess.id, store.Contact{ID: id, State: store.StateBlocked, Since: now()})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) contactUnblock(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := readID(w, r)
	if !ok {
		return
	}
	if c, err := s.st.Contacts().Get(r.Context(), sess.id, id); err == nil && c.State == store.StateBlocked {
		s.st.Contacts().Delete(r.Context(), sess.id, id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// readID reads a { "id": identifier } body.
func readID(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		ID string `json:"id"`
	}
	if !readBody(w, r, &req) {
		return "", false
	}
	if !wire.ValidIdentityID(req.ID) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "id must be an identifier")
		return "", false
	}
	return req.ID, true
}
