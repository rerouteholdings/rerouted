package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Community icons (SPEC §16.2.3, spec/api/community.md). The chain names the icon by hash in
// create and set-name; the bytes live here. Anyone may fetch the icon the current state
// names, for the join preview. An upload is kept 24 hours, and from then on only while the
// current state names it.

// iconKeep is how long an icon the state doesn't name is kept after its upload.
const iconKeep = 24 * 3600

// iconMagic reports whether data starts like an image of type mt.
func iconMagic(mt string, data []byte) bool {
	switch mt {
	case "image/png":
		return bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n"))
	case "image/jpeg":
		return bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff})
	case "image/webp":
		return len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP"
	}
	return false
}

// ---- GET icon/{hash} ----

func (c *community) iconGet(w http.ResponseWriter, r *http.Request) {
	hash, err := base64.RawURLEncoding.DecodeString(r.PathValue("hash"))
	st := c.snapshot()
	if err != nil || st == nil || st.Icon == nil || !bytes.Equal(hash, st.Icon.Hash) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "the community's icon has another hash, or it has none")
		return
	}
	mt, data, err := c.st.Icon(r.Context(), c.name, hash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "the icon was never uploaded here")
		return
	case err != nil:
		c.hs.unavailableRead(w, "reading the community's icon", err)
		return
	}
	w.Header().Set("Content-Type", mt)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable") // named by its hash
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// ---- POST icon/upload ----

func (c *community) iconUpload(w http.ResponseWriter, r *http.Request, _ csess) {
	if r.ContentLength > cchain.MaxIconSize {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "an icon is at most 262144 bytes")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cchain.MaxIconSize))
	if errors.As(err, new(*http.MaxBytesError)) {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "an icon is at most 262144 bytes")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "reading the body: "+err.Error())
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !cchain.IconMime(mt) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "an icon is image/png, image/jpeg, or image/webp")
		return
	}
	if !iconMagic(mt, data) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "the bytes don't start like "+mt)
		return
	}
	sum := sha256.Sum256(data)
	if err := c.st.PutIcon(r.Context(), c.name, sum[:], mt, data, now()); err != nil {
		c.hs.unavailableRead(w, "storing an icon", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"hash": wire.Bytes(sum[:])})
}
