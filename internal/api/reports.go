package api

import (
	"net/http"
	"unicode/utf8"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- reports (SPEC §16.3) ----

type reportBody struct {
	Reporter string     `json:"reporter"`
	Reported string     `json:"reported"`
	Reason   string     `json:"reason"`
	Evidence []wire.Raw `json:"evidence,omitempty"`
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
	if wire.Unmarshal(req.Report, &rep) != nil || !wire.ValidIdentityID(rep.Reported) || utf8.RuneCountInString(rep.Reason) > 2000 {
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
	if wire.Unmarshal(body, &req) != nil || wire.Unmarshal(req.Report, &rep) != nil {
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
