package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- history segments (SPEC §16.5, spec/api/community.md) ----

func (c *community) historyPut(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Channel uint64     `json:"channel"`
		Start   uint64     `json:"start"`
		End     uint64     `json:"end"`
		CT      wire.Bytes `json:"ct"`
		Replace bool       `json:"replace,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	st := c.snapshot()
	ch, ok := c.channelFor(w, st, sess, req.Channel, "")
	if !ok {
		return
	}
	if ch.Kind != "text" || !ch.History {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "history is off for that channel")
		return
	}
	head, err := c.st.ChannelHead(ctx, c.name, req.Channel)
	if err != nil {
		c.hs.unavailableRead(w, "reading a channel", err)
		return
	}
	if req.Start == 0 || req.Start > req.End || req.End > head || len(req.CT) < 28 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "start <= end <= the channel's newest sequence number, and a ct")
		return
	}
	if len(req.CT) > maxSegmentCT {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "at most 1 MiB of plaintext")
		return
	}
	used, err := c.st.SegmentUsage(ctx, c.name)
	if err != nil {
		c.hs.unavailableRead(w, "reading history usage", err)
		return
	}
	if used+int64(len(req.CT)) > c.hs.cfg.CommunityHistoryQuota {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "the community's history storage is full")
		return
	}
	err = c.st.PutSegment(ctx, c.name, store.CSegment{Channel: req.Channel, Start: req.Start, End: req.End, CT: req.CT, TS: now()}, req.Replace)
	switch {
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	case err != nil:
		c.hs.unavailableRead(w, "storing a history segment", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *community) historyList(w http.ResponseWriter, r *http.Request, sess csess) {
	id, ok := queryUint(r, "channel", 0)
	after, ok2 := queryUint(r, "after", 0)
	if !ok || !ok2 || id == 0 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "channel")
		return
	}
	if _, ok := c.channelFor(w, c.snapshot(), sess, id, ""); !ok {
		return
	}
	limit := limitParam(r, 100, 500)
	segs, err := c.st.Segments(r.Context(), c.name, id, after, limit)
	if err != nil {
		c.hs.unavailableRead(w, "listing history segments", err)
		return
	}
	items := make([]map[string]any, len(segs))
	for i, s := range segs {
		items[i] = map[string]any{"start": s.Start, "end": s.End, "size": s.Size, "ts": s.TS}
	}
	res := map[string]any{"items": items}
	if len(segs) == limit {
		res["next"] = strconv.FormatUint(segs[len(segs)-1].Start, 10)
	}
	writeBody(w, http.StatusOK, res)
}

func (c *community) historyGet(w http.ResponseWriter, r *http.Request, sess csess) {
	id, ok := queryUint(r, "channel", 0)
	start, ok2 := queryUint(r, "start", 0)
	if !ok || !ok2 || id == 0 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "channel and start")
		return
	}
	if _, ok := c.channelFor(w, c.snapshot(), sess, id, ""); !ok {
		return
	}
	s, err := c.st.Segment(r.Context(), c.name, id, start)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a history segment", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"channel": id, "start": s.Start, "end": s.End, "ct": wire.Bytes(s.CT)})
}

// ---- files (SPEC §16.4) ----

func (c *community) mediaUpload(w http.ResponseWriter, r *http.Request, sess csess) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "use application/octet-stream")
		return
	}
	st := c.snapshot()
	if !st.Has(sess.id, cchain.Talk) || st.TimedOut(sess.id, now()) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "uploading needs talk, and no timeout")
		return
	}
	if r.ContentLength > maxCommunityFile {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "at most 64 MiB")
		return
	}
	ctx := r.Context()
	used, err := c.st.MediaUsage(ctx, c.name)
	if err != nil {
		c.hs.unavailableRead(w, "reading file usage", err)
		return
	}
	room := c.hs.cfg.CommunityFileQuota - used
	if room <= 0 || (r.ContentLength > 0 && r.ContentLength > room) {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "the community's file storage is full")
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	m := &store.CMedia{ID: id, Author: sess.id, Created: now()}
	err = c.st.PutMedia(ctx, c.name, m, http.MaxBytesReader(w, r.Body, maxCommunityFile+1), min(int64(maxCommunityFile), room))
	if errors.Is(err, store.ErrOverQuota) || errors.As(err, new(*http.MaxBytesError)) {
		if room < maxCommunityFile {
			writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "the community's file storage is full")
		} else {
			writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "at most 64 MiB")
		}
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "storing a file", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(m.ID), "sha256": wire.Bytes(m.SHA256), "size": m.Size})
}

func (c *community) mediaGet(w http.ResponseWriter, r *http.Request, _ csess) {
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 16 {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	ctx := r.Context()
	m, err := c.st.Media(ctx, c.name, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	case err != nil:
		c.hs.unavailableRead(w, "reading a file", err)
		return
	case m.Removed:
		writeError(w, http.StatusGone, wire.ErrCodeRemoved, "deleted with its message")
		return
	case m.Expired:
		writeError(w, http.StatusGone, wire.ErrCodeExpired, "")
		return
	}
	f, err := c.st.OpenMedia(ctx, c.name, id)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(m.Size, 10))
	io.Copy(w, f)
}

// ---- moderation (SPEC §16.7) ----

func (c *community) messagesDelete(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Channel uint64       `json:"channel"`
		Seq     uint64       `json:"seq"`
		By      uint64       `json:"by"`
		Media   []wire.Bytes `json:"media,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	st := c.snapshot()
	msg, err := c.st.ChannelItem(ctx, c.name, req.Channel, req.Seq)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no such message")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a message", err)
		return
	}
	del, err := c.st.ChannelItem(ctx, c.name, req.Channel, req.By)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "by must be your delete, sent in the channel after the message")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a message", err)
		return
	}
	author := msg.FromID
	allowed := author == sess.id || (st.Has(sess.id, cchain.Moderate) && author != st.Owner && st.Level(author) < st.Level(sess.id))
	if !allowed || del.FromID != sess.id || req.By <= req.Seq {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "only the author, or a moderator who outranks them, with their own later delete")
		return
	}
	if msg.Deleted == 0 {
		if err := c.st.DeleteItem(ctx, c.name, req.Channel, req.Seq, req.By, now()); err != nil {
			c.hs.unavailableRead(w, "deleting a message", err)
			return
		}
	}
	for _, id := range req.Media {
		if m, err := c.st.Media(ctx, c.name, id); err == nil && m.Author == author && !m.Removed {
			c.hs.logged("removing a deleted message's file", c.st.RemoveMedia(ctx, c.name, id))
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *community) report(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Report wire.Raw `json:"report"`
		At     []struct {
			Channel uint64 `json:"channel"`
			Seq     uint64 `json:"seq"`
		} `json:"at,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	var rep reportBody
	if wire.Unmarshal(req.Report, &rep) != nil || !wire.ValidIdentityID(rep.Reported) || utf8.RuneCountInString(rep.Reason) > 2000 || !c.hs.evidenceOK(rep.Evidence) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if rep.Reporter != sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "reporter must be you")
		return
	}
	if !c.hs.limits.allow("cm-report|"+c.name+"|"+sess.id, 50, 24*3600, now(), true) {
		rateLimited(w, 3600)
		return
	}
	var at []byte
	if req.At != nil {
		at, _ = wire.Marshal(req.At)
	}
	id := make([]byte, 16)
	rand.Read(id)
	if err := c.st.AddReport(r.Context(), c.name, store.CReport{ID: id, TS: now(), Reporter: sess.id, Body: req.Report, At: at}); err != nil {
		c.hs.unavailableRead(w, "storing a report", err)
		return
	}
	c.hs.log.Warn("community report", "name", c.name, "reporter", sess.id, "reported", rep.Reported)
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(id)})
}

func (c *community) reports(w http.ResponseWriter, r *http.Request, _ csess) {
	after, ok := cursorParam(r.URL.Query().Get("after"))
	if !ok {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "after")
		return
	}
	limit := limitParam(r, 50, 200)
	rs, err := c.st.Reports(r.Context(), c.name, after, limit)
	if err != nil {
		c.hs.unavailableRead(w, "listing reports", err)
		return
	}
	items := make([]map[string]any, len(rs))
	for i, rp := range rs {
		items[i] = map[string]any{"id": wire.Bytes(rp.ID), "ts": rp.TS, "report": wire.Raw(rp.Body)}
		if rp.At != nil {
			items[i]["at"] = wire.Raw(rp.At)
		}
	}
	res := map[string]any{"items": items}
	if len(rs) == limit {
		res["next"] = strconv.FormatInt(rs[len(rs)-1].N, 10)
	}
	writeBody(w, http.StatusOK, res)
}

func (c *community) reportClose(w http.ResponseWriter, r *http.Request, _ csess) {
	var req struct {
		ID wire.Bytes `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	switch err := c.st.CloseReport(r.Context(), c.name, req.ID); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
	case err != nil:
		c.hs.unavailableRead(w, "closing a report", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- maintenance ----

// maintainCommunities runs each community's upkeep: inbox, commits, and sent results past
// 30 days; trees no commit named within an hour, and kept ones past 30 days; files past the
// retention; idle non-members' key packages; and the daily chain re-fetch (spec/api/community.md).
func (s *Server) maintainCommunities(ctx context.Context) {
	if s.comm == nil || len(s.comm.byName) == 0 {
		return
	}
	t := now()
	cs := s.st.Communities()
	s.logged("pruning community inboxes", cs.Prune(ctx, t-inboxRetention))
	if _, err := cs.PruneTrees(ctx, t-3600, t); err != nil {
		s.log.Error("pruning ratchet trees", "err", err)
	}
	for _, c := range s.comm.byName {
		if days := s.cfg.CommunityFileDays; days > 0 {
			if _, err := cs.ExpireMedia(ctx, c.name, t-int64(days)*24*3600); err != nil {
				s.log.Error("expiring community files", "err", err)
			}
		}
		if _, err := cs.PruneKPs(ctx, c.name, t-30*24*3600); err != nil {
			s.log.Error("pruning community key packages", "err", err)
		}
		c.refreshChains(ctx)
	}
}

// RunCommunityVoice re-checks who may speak in each voice channel every few seconds, so a
// timeout's end lets a member speak again, until ctx ends.
func (s *Server) RunCommunityVoice(ctx context.Context) {
	if s.comm == nil || len(s.comm.byName) == 0 {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, c := range s.comm.byName {
				if st := c.snapshot(); st != nil {
					c.voice.regate(st)
				}
			}
		}
	}
}

// retryAfter is how many seconds until key's oldest event leaves the window.
func (l *limiter) retryAfter(key string, window, t int64) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := l.prune(key, window, t)
	if len(ev) == 0 {
		return 0
	}
	return max(ev[0]+window-t, 1)
}
