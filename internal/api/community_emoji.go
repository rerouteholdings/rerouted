package api

import (
	"bytes"
	"context"
	"crypto/rand"
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

// Custom emoji (SPEC §16.9, spec/api/community.md). Members with administrate upload each
// emoji as an encrypted blob, then name it with a signed community-emoji record, which holds
// the name and key sealed under the community metadata key. Members list the records. Anyone
// may fetch a blob by its ID, so recipients' homeservers can fetch it for them (SPEC §12.2):
// only emoji blobs, never channel files. A deleted emoji's blob is served 30 days more.

const (
	// maxEmojiBlob is the largest blob: 256 KiB of plaintext and the 16-byte tag.
	maxEmojiBlob = cchain.MaxEmojiSize + 16
	// emojiUnnamedKeep: a blob no record names is deleted this long after its upload.
	emojiUnnamedKeep = 24 * 3600
	// emojiDeletedKeep: a deleted emoji's blob is served this long after the delete.
	emojiDeletedKeep = 30 * 24 * 3600
	// Limits (spec/api/community.md, Rate limits).
	emojiUploadsPerHour  = 50
	emojiChangesPerHour  = 200
	emojiFetchesPerHour  = 3600 // GET emoji/{id}, per caller address
	emojiRecordClockSkew = cchain.ClockSkew
)

// maxEmoji is how many current emoji a community may have; a variable for tests.
var maxEmoji = cchain.MaxEmoji

// ---- POST emoji/upload ----

func (c *community) emojiUpload(w http.ResponseWriter, r *http.Request, sess csess) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "use application/octet-stream")
		return
	}
	if r.ContentLength > maxEmojiBlob {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "an emoji is at most 262160 bytes")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEmojiBlob))
	if errors.As(err, new(*http.MaxBytesError)) {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "an emoji is at most 262160 bytes")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "reading the body: "+err.Error())
		return
	}
	if len(data) < 17 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "an emoji blob is at least 17 bytes: one byte and the tag")
		return
	}
	t := now()
	key := "cm-emoji-up|" + c.name + "|" + sess.id
	if !c.hs.limits.allow(key, emojiUploadsPerHour, 3600, t, true) {
		rateLimited(w, uint64(c.hs.limits.retryAfter(key, 3600, t)))
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	sum := sha256.Sum256(data)
	e := store.CEmoji{ID: id, SHA256: sum[:], Size: int64(len(data)), Data: data, Uploader: sess.id, Uploaded: t}
	if err := c.st.PutEmojiBlob(r.Context(), c.name, e); err != nil {
		c.hs.unavailableRead(w, "storing an emoji", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(id), "sha256": wire.Bytes(sum[:]), "size": len(data)})
}

// ---- POST emoji/put ----

func (c *community) emojiPut(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Emoji wire.Raw `json:"emoji"`
	}
	if !readBody(w, r, &req) {
		return
	}
	em, e := cchain.ParseEmoji(req.Emoji)
	if e != nil {
		c.cerr(w, e)
		return
	}
	st := c.snapshot()
	if st == nil || !bytes.Equal(em.Community, st.ID) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "community isn't this community's identifier")
		return
	}
	if em.By != sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "by must be you")
		return
	}
	ctx := r.Context()
	signer, err := c.appendKeys(ctx, sess)(em.By, em.Sig.K)
	if errors.Is(err, cchain.ErrNotDevice) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "k isn't a current device of by")
		return
	}
	if err != nil {
		c.cerr(w, err)
		return
	}
	if em.Sig.VerifyComposite(cchain.TypeEmoji, signer.Pub) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	t := now()
	if em.TS > t+emojiRecordClockSkew || em.TS < t-emojiRecordClockSkew {
		c.cerr(w, &cchain.Error{Status: http.StatusBadRequest, Code: wire.ErrCodeClockSkew, Msg: "ts is more than 10 minutes from the server's clock"})
		return
	}
	if !c.inChain(em.Head) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "head isn't an entry of the community chain")
		return
	}
	blob, err := c.st.EmojiBlob(ctx, c.name, em.Blob)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && (blob.Deleted != 0 || blob.Data == nil):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no emoji blob with that ID, or it was deleted")
		return
	case err != nil:
		c.hs.unavailableRead(w, "reading an emoji", err)
		return
	}
	if !bytes.Equal(blob.SHA256, em.SHA256) || blob.Size != em.Size+16 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "sha256 or size doesn't match the blob")
		return
	}
	if !c.emojiChangeAllowed(w, sess.id, t) {
		return
	}
	switch err := c.st.PutEmojiRecord(ctx, c.name, em.Blob, em.Enc, maxEmoji); {
	case errors.Is(err, store.ErrOverQuota):
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "a community has at most 200 emoji")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "the emoji blob was deleted")
	case err != nil:
		c.hs.unavailableRead(w, "storing an emoji record", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// emojiChangeAllowed counts a put or a delete against the caller's hourly limit.
func (c *community) emojiChangeAllowed(w http.ResponseWriter, id string, t int64) bool {
	key := "cm-emoji-change|" + c.name + "|" + id
	if !c.hs.limits.allow(key, emojiChangesPerHour, 3600, t, true) {
		rateLimited(w, uint64(c.hs.limits.retryAfter(key, 3600, t)))
		return false
	}
	return true
}

// inChain reports whether hash is the hash of an entry in the stored community chain.
func (c *community) inChain(hash []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, raw := range c.ent {
		sum := sha256.Sum256(raw)
		if bytes.Equal(sum[:], hash) {
			return true
		}
	}
	return false
}

// ---- POST emoji/delete ----

func (c *community) emojiDelete(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		ID wire.Bytes `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if len(req.ID) != 16 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "id must be 16 bytes")
		return
	}
	t := now()
	if !c.emojiChangeAllowed(w, sess.id, t) {
		return
	}
	switch err := c.st.DeleteEmoji(r.Context(), c.name, req.ID, t); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no current emoji with that ID")
	case err != nil:
		c.hs.unavailableRead(w, "deleting an emoji", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- GET emoji ----

func (c *community) emojiList(w http.ResponseWriter, r *http.Request, _ csess) {
	recs, err := c.st.EmojiRecords(r.Context(), c.name)
	if err != nil {
		c.hs.unavailableRead(w, "listing emoji", err)
		return
	}
	items := make([]wire.Raw, len(recs))
	for i, rec := range recs {
		items[i] = rec
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// ---- GET emoji/{id} ----

// emojiBlobGet serves an emoji blob to anyone, also after the community moved away.
func (c *community) emojiBlobGet(w http.ResponseWriter, r *http.Request) {
	t := now()
	key := "cm-emoji-fetch|" + c.name + "|@" + addressKey(clientIP(r))
	if !c.hs.limits.allow(key, emojiFetchesPerHour, 3600, t, true) {
		rateLimited(w, uint64(c.hs.limits.retryAfter(key, 3600, t)))
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 16 {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	status, code, data := c.emojiBlob(r.Context(), id)
	if status != http.StatusOK {
		if status == http.StatusServiceUnavailable {
			c.hs.unavailableRead(w, "reading an emoji", errors.New(code))
			return
		}
		writeError(w, status, code, "")
		return
	}
	writeEmoji(w, data, "public, max-age=86400")
}

// emojiBlob finds a blob to serve: one a current record names, or one deleted under 30 days
// ago. Anything else is 404, unnamed uploads and channel files included; a blob deleted
// longer ago is 410 expired.
func (c *community) emojiBlob(ctx context.Context, id []byte) (int, string, []byte) {
	e, err := c.st.EmojiBlob(ctx, c.name, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, wire.ErrCodeNotFound, nil
	case err != nil:
		return http.StatusServiceUnavailable, err.Error(), nil
	case e.Record == nil && e.Deleted == 0:
		return http.StatusNotFound, wire.ErrCodeNotFound, nil // never named
	case e.Data == nil || e.Deleted != 0 && now()-e.Deleted >= emojiDeletedKeep:
		return http.StatusGone, wire.ErrCodeExpired, nil
	}
	return http.StatusOK, "", e.Data
}

func writeEmoji(w http.ResponseWriter, data []byte, cache string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", cache)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// maintainEmoji drops unnamed uploads after 24 hours and deleted blobs' bytes after 30 days.
// Once the community has moved away, every current emoji counts as deleted at that time, so
// this server serves them 30 days more (SPEC §16.9).
func (c *community) maintainEmoji(ctx context.Context, t int64) error {
	if st := c.snapshot(); c.moved(st) {
		if _, err := c.st.DeleteAllEmoji(ctx, c.name, t); err != nil {
			return err
		}
	}
	_, err := c.st.PruneEmoji(ctx, c.name, t-emojiUnnamedKeep, t-emojiDeletedKeep)
	return err
}
