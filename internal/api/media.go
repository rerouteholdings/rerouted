package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- files and profile pictures (SPEC §13.1, §14) ----

// Size limits.
const (
	maxFile   = 64<<20 + 16 // 64 MiB of plaintext, plus the AES-GCM tag
	maxAvatar = 1_000_000
	fileTTL   = 30 * 24 * 3600
)

var avatarTypes = map[string][]byte{
	"image/png":  []byte("\x89PNG\r\n\x1a\n"),
	"image/jpeg": {0xFF, 0xD8, 0xFF},
	"image/gif":  []byte("GIF8"),
	"image/webp": []byte("RIFF"), // and "WEBP" at offset 8, checked below
}

func (s *Server) mediaUpload(w http.ResponseWriter, r *http.Request, sess session) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "files are uploaded as application/octet-stream")
		return
	}
	s.storeMedia(w, r, sess, "", maxFile)
}

func (s *Server) mediaUploadPublic(w http.ResponseWriter, r *http.Request, sess session) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if _, ok := avatarTypes[mt]; !ok {
		writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "a profile picture is image/png, image/jpeg, image/webp, or image/gif")
		return
	}
	s.storeMedia(w, r, sess, mt, maxAvatar)
}

// storeMedia stores the request body as a file. With mimeType set, it's a public picture.
func (s *Server) storeMedia(w http.ResponseWriter, r *http.Request, sess session, mimeType string, max int64) {
	ctx := r.Context()
	used, err := s.st.Media().Usage(ctx, sess.id)
	if err != nil {
		s.unavailableRead(w, "reading file usage", err) // never let a failed check past the quota
		return
	}
	if used >= s.cfg.Now().MediaQuota {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "")
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	m := &store.MediaMeta{ID: id, Owner: sess.id, Mime: mimeType, Public: mimeType != "", Created: now()}
	body := http.MaxBytesReader(w, r.Body, max+1)
	var head bytes.Buffer
	if err := s.st.Media().Write(ctx, m, io.TeeReader(body, &limitedBuffer{&head, 16}), max); err != nil {
		if errors.Is(err, store.ErrOverQuota) || errors.As(err, new(*http.MaxBytesError)) {
			writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, fmt.Sprintf("at most %d bytes", max))
			return
		}
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	if used+m.Size > s.cfg.Now().MediaQuota {
		s.logged("removing a file over the quota", s.st.Media().Remove(ctx, id))
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "")
		return
	}
	if m.Public {
		// Check the picture is what it says it is (spec/api/client-stage5.md).
		h := head.Bytes()
		ok := bytes.HasPrefix(h, avatarTypes[mimeType])
		if mimeType == "image/webp" {
			ok = ok && len(h) >= 12 && string(h[8:12]) == "WEBP"
		}
		if !ok {
			s.logged("removing a picture of the wrong type", s.st.Media().Remove(ctx, id))
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "the bytes aren't a "+mimeType)
			return
		}
		writeBody(w, http.StatusOK, map[string]any{"media": map[string]any{
			"server": s.cfg.Name, "id": wire.Bytes(id), "sha256": wire.Bytes(m.SHA256), "size": m.Size, "mime": mimeType}})
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(id), "sha256": wire.Bytes(m.SHA256), "size": m.Size})
}

// limitedBuffer keeps the first n bytes written to it.
type limitedBuffer struct {
	b *bytes.Buffer
	n int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (s *Server) mediaGet(w http.ResponseWriter, r *http.Request, _ session) {
	server := r.PathValue("server")
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 16 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "id must be 16 bytes of base64url")
		return
	}
	if server == s.cfg.Name {
		s.serveMedia(w, r.Context(), id)
		return
	}
	if s.fed == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	// Fetched on the client's behalf, so the other server never sees its address (SPEC §14).
	body, _ := wire.Marshal(map[string]any{"id": wire.Bytes(id)})
	ctype, b, err := s.fed.Fetch(r.Context(), server, "media/fetch", body)
	var es *fed.ErrStatus
	switch {
	case errors.As(err, &es):
		writeError(w, es.Status, es.Code, "")
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, err.Error())
	default:
		if _, ok := avatarTypes[ctype]; !ok {
			ctype = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ctype)
		w.Write(b)
	}
}

// serveMedia writes a local file, or the error for why it can't.
func (s *Server) serveMedia(w http.ResponseWriter, ctx context.Context, id []byte) {
	m, err := s.st.Media().Get(ctx, id)
	switch {
	case err != nil:
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	case m.Removed:
		writeError(w, http.StatusGone, wire.ErrCodeRemoved, "")
		return
	case m.Expired || (!m.Public && now()-m.Created > fileTTL):
		writeError(w, http.StatusGone, wire.ErrCodeExpired, "")
		return
	}
	f, err := s.st.Media().Open(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	defer f.Close()
	ctype := "application/octet-stream"
	if m.Public {
		ctype = m.Mime
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	w.Header().Set("Content-Type", ctype)
	io.Copy(w, f)
}

func (s *Server) s2sMediaFetch(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		ID wire.Bytes `json:"id"`
	}
	if wire.Unmarshal(body, &req) != nil || len(req.ID) != 16 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if !s.limits.allow("media-fetch|"+from, 2000, 3600, now(), true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 60})
		return
	}
	s.serveMedia(w, r.Context(), req.ID)
}
