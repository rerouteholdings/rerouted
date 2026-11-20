package api

import (
	"crypto/ed25519"
	"net/http"
	"unicode/utf8"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- reports (SPEC §17.3) ----

type reportBody struct {
	Reporter string     `json:"reporter"`
	Reported string     `json:"reported"`
	Reason   string     `json:"reason"`
	Evidence []wire.Raw `json:"evidence,omitempty"`
}

// evidenceOK reports whether a report's evidence has its wire version's shape. In wire
// version 2 each item is an object with the reported app-message, signed by a message key,
// and the msg-key that certifies that key, signed by a device, with the delivery ID and the
// blob's hash if the reporter has them (SPEC §17.3). The server keeps the evidence for its
// admins, who verify it against the reported identity's chain (SPEC §17.2); it doesn't.
// Version 1's evidence is kept as it comes.
func (s *Server) evidenceOK(evidence []wire.Raw) bool {
	if s.wv != wire.V2 {
		return true
	}
	for _, raw := range evidence {
		var ev struct {
			Msg      wire.Raw   `json:"msg"`
			MK       wire.Raw   `json:"mk"`
			Delivery wire.Bytes `json:"delivery,omitempty"`
			Blob     wire.Bytes `json:"blob,omitempty"`
		}
		if wire.Unmarshal(raw, &ev) != nil || ev.Msg == nil || ev.MK == nil {
			return false
		}
		msg, err := wire.DecodeSignedV2(ev.Msg)
		if err != nil || msg.T != "app-message" || len(msg.S) != ed25519.SignatureSize {
			return false
		}
		mk, err := wire.DecodeSignedV2(ev.MK)
		if err != nil || mk.T != wire.TypeMsgKey || len(mk.K) != ed25519.PublicKeySize || len(mk.S) != wire.CompositeSignatureSize {
			return false
		}
		if (ev.Delivery != nil && len(ev.Delivery) != 16) || (ev.Blob != nil && len(ev.Blob) != 32) {
			return false
		}
	}
	return true
}

func (s *Server) postReport(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Report  wire.Raw `json:"report"`
		Forward bool     `json:"forward,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	var rep reportBody
	if wire.Unmarshal(req.Report, &rep) != nil || !wire.ValidIdentityID(rep.Reported) || utf8.RuneCountInString(rep.Reason) > 2000 || !s.evidenceOK(rep.Evidence) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if rep.Reporter != sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "reporter must be you")
		return
	}
	ctx := r.Context()
	if err := s.st.Reports().Add(ctx, store.Report{Received: now(), Origin: s.cfg.Name, Reporter: rep.Reporter, Reported: rep.Reported, Body: req.Report}); err != nil {
		s.unavailableRead(w, "storing a report", err) // the reporter retries: never lose a report
		return
	}
	s.log.Warn("report received", "reporter", rep.Reporter, "reported", rep.Reported)
	if req.Forward && !s.isLocal(ctx, rep.Reported) && s.fed != nil {
		if them, _, err := s.lookup(ctx, rep.Reported, ""); err == nil {
			s.logged("queueing a report to forward", s.enqueue(ctx, them.Home, "report", map[string]any{"report": req.Report}))
		}
	}
	writeBody(w, http.StatusAccepted, map[string]any{})
}

func (s *Server) s2sReport(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Report wire.Raw `json:"report"`
	}
	var rep reportBody
	if wire.Unmarshal(body, &req) != nil || wire.Unmarshal(req.Report, &rep) != nil || utf8.RuneCountInString(rep.Reason) > 2000 || !s.evidenceOK(rep.Evidence) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	if !s.remoteUser(ctx, rep.Reporter, from) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the reporter doesn't live on your server")
		return
	}
	if !s.isLocal(ctx, rep.Reported) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	if !s.limits.allow("report|"+from, 100, 24*3600, now(), true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 3600})
		return
	}
	if err := s.st.Reports().Add(ctx, store.Report{Received: now(), Origin: from, Reporter: rep.Reporter, Reported: rep.Reported, Body: req.Report}); err != nil {
		s.unavailableRead(w, "storing a forwarded report", err) // the forwarding server retries
		return
	}
	s.log.Warn("report forwarded", "from", from, "reporter", rep.Reporter, "reported", rep.Reported)
	writeBody(w, http.StatusAccepted, map[string]any{})
}
