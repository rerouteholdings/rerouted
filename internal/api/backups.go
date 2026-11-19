package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- backups (SPEC §7.5, spec/api/client-stage4.md) ----

const (
	maxSegment    = 1<<20 + 28
	maxBackupBody = 2 << 20 // backup/put bodies: a 1 MiB segment in base64url (spec/api/conventions.md)
)

func (s *Server) backupPut(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Seq      int64      `json:"seq"`
		CT       wire.Bytes `json:"ct"`
		Snapshot bool       `json:"snapshot,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Seq < 0 || len(req.CT) < 28 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if len(req.CT) > maxSegment {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "a segment holds at most 1 MiB")
		return
	}
	ctx := r.Context()
	used, err := s.st.Backups().Usage(ctx, sess.id)
	if err != nil {
		s.unavailableRead(w, "reading backup usage", err) // never let a failed check past the quota
		return
	}
	if req.Snapshot {
		used = 0 // a snapshot replaces everything before it
	}
	if used+int64(len(req.CT)) > s.cfg.Now().BackupQuota {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "the backup is full: compact it with a snapshot")
		return
	}
	err = s.st.Backups().Put(ctx, sess.id, store.Segment{Seq: req.Seq, CT: req.CT, Snapshot: req.Snapshot})
	switch {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "that seq holds a different segment")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, wire.ErrCodeStaleVersion, "seq must be higher than every stored segment's")
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) backupList(w http.ResponseWriter, r *http.Request, sess session) {
	segs, err := s.st.Backups().List(r.Context(), sess.id)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	out := []map[string]any{}
	for _, sg := range segs {
		m := map[string]any{"seq": sg.Seq, "size": sg.Size}
		if sg.Snapshot {
			m["snapshot"] = true
		}
		out = append(out, m)
	}
	writeBody(w, http.StatusOK, map[string]any{"segments": out})
}

func (s *Server) backupGet(w http.ResponseWriter, r *http.Request, sess session) {
	seq, err := strconv.ParseInt(r.URL.Query().Get("seq"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "seq is required")
		return
	}
	sg, err := s.st.Backups().Get(r.Context(), sess.id, seq)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	res := map[string]any{"seq": sg.Seq, "ct": wire.Bytes(sg.CT)}
	if sg.Snapshot {
		res["snapshot"] = true
	}
	writeBody(w, http.StatusOK, res)
}
