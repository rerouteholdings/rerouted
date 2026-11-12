package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// plain converts a decoded list of byte strings for the store.
func plain(xs []wire.Bytes) [][]byte {
	out := make([][]byte, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func containsBytes(list [][]byte, b []byte) bool {
	for _, x := range list {
		if string(x) == string(b) {
			return true
		}
	}
	return false
}

func queryInt(r *http.Request, key string, def int64) int64 {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// maxPage is the most items one page of a list returns, and defaultPage how many it
// returns when the request doesn't say (GET inbox, GET contacts).
const (
	maxPage     = 500
	defaultPage = 100
)

// pageLimit reads a list's `limit` parameter. It writes a 400 itself and returns false
// for anything but a positive whole number; numbers over maxPage get maxPage.
func pageLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return defaultPage, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "limit must be a whole number from 1 up")
		return 0, false
	}
	return int(min(n, maxPage)), true
}

// notify puts a server notice in a user's inbox (spec/api/client-stage1.md).
func (s *Server) notify(ctx context.Context, owner string, notice map[string]any) {
	b, err := wire.Marshal(notice)
	if err != nil {
		s.log.Error("encode notice", "err", err)
		return
	}
	it := store.Item{TS: now(), Notice: b}
	if cur, err := s.st.Inbox().Append(ctx, owner, it); err == nil {
		it.Cursor = cur
		s.pushItem(owner, it)
	}
}

// isContactOrRequested reports whether owner accepts things from other:
// a full contact, or someone owner has a pending request out to (SPEC §9.3).
// A pending-outgoing request lasts 30 days (SPEC §9.3).
const pendingTTL = 30 * 24 * 3600

func (s *Server) isContactOrRequested(ctx context.Context, owner, other string) bool {
	c, err := s.st.Contacts().Get(ctx, owner, other)
	if err != nil {
		return false
	}
	return c.State == store.StateContact || (c.State == store.StatePendingOut && c.Since+pendingTTL > now())
}

// ---- key packages (SPEC §11.4) ----

func (s *Server) kpUpload(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Packages   []wire.Bytes `json:"packages"`
		LastResort wire.Bytes   `json:"last-resort,omitempty"`
		Replace    bool         `json:"replace,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Replace {
		s.st.KeyPackages().Clear(r.Context(), sess.id, sess.device)
	}
	n, err := s.st.KeyPackages().Upload(r.Context(), sess.id, sess.device, plain(req.Packages), req.LastResort)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"count": n})
}

func (s *Server) kpCount(w http.ResponseWriter, r *http.Request, sess session) {
	n, lr, _ := s.st.KeyPackages().Count(r.Context(), sess.id, sess.device)
	writeBody(w, http.StatusOK, map[string]any{"count": n, "last-resort": lr})
}

func (s *Server) kpClaim(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		ID      string       `json:"id"`
		Group   wire.Bytes   `json:"group,omitempty"`
		Devices []wire.Bytes `json:"devices,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if s.isLocal(r.Context(), req.ID) {
		s.claimFor(w, r, req.ID, sess.id, s.cfg.Name, req.Group, plain(req.Devices))
		return
	}
	// The target lives elsewhere: claim through its homeserver (S2S keypackages/claim).
	st, _, err := s.lookup(r.Context(), req.ID, "")
	if err != nil || s.fed == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "fetch the identity's chain first")
		return
	}
	body := map[string]any{"id": req.ID, "claimant": sess.id}
	if req.Group != nil {
		body["group"] = req.Group
	}
	if req.Devices != nil {
		body["devices"] = req.Devices
	}
	enc, _ := wire.Marshal(body)
	b, err := s.fed.Call(r.Context(), st.Home, "keypackages/claim", enc)
	if err != nil {
		var es interface{ Error() string } = err
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, es.Error())
		return
	}
	w.Header().Set("Content-Type", wire.MediaType)
	w.Write(b)
}

// claimFor claims key packages of a local identity for a claimant (SPEC §11.4).
// If `only` is non-empty, packages are claimed for just those devices.
// origin is the claimant's homeserver.
func (s *Server) claimFor(w http.ResponseWriter, r *http.Request, target, claimant, origin string, group []byte, only [][]byte) {
	st, _, err := s.identity(r.Context(), target)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	allowed := target == claimant || s.isContactOrRequested(r.Context(), target, claimant)
	if !allowed && group != nil {
		// Group IDs aren't secret, so these claims are rate-limited (SPEC §11.4).
		allowed, _ = s.st.Contacts().GroupAllowed(r.Context(), target, group)
		// Per claimant and per origin server: identities are free, servers aren't (SPEC §9.5).
		allowed = allowed && s.limits.allowAll(now(),
			limit{"group-claim|" + claimant + "|" + target, 10, 24 * 3600},
			limit{"group-claim-origin|" + originKey(origin) + "|" + target, 10, 24 * 3600})
	}
	if !allowed {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "")
		return
	}
	// A contact can claim too, but not without limit: each claim uses up a one-time key
	// package, and once they're gone the reusable last-resort one stands in. Starting chats takes a few claims a day, not dozens.
	if target != claimant && group == nil && !s.limits.allow("claim|"+claimant+"|"+target, 50, 24*3600, now(), true) {
		writeError(w, http.StatusTooManyRequests, wire.ErrCodeRateLimited, "")
		return
	}
	var devices [][]byte
	for k := range st.Devices {
		d := unhex(k)
		if len(only) > 0 && !containsBytes(only, d) {
			continue
		}
		devices = append(devices, d)
	}
	kps, _ := s.st.KeyPackages().Claim(r.Context(), target, devices)
	out := []map[string]any{}
	for _, kp := range kps {
		out = append(out, map[string]any{"dev": kp.Device, "kp": kp.Data, "last-resort": kp.LastResort})
	}
	writeBody(w, http.StatusOK, map[string]any{"packages": out})
}

// ---- contacts (SPEC §9) ----

type contactRequestBody struct {
	From   string     `json:"from"`
	To     string     `json:"to"`
	TS     int64      `json:"ts"`
	Nonce  wire.Bytes `json:"nonce"`
	Invite string     `json:"invite"`
}

func (s *Server) contactRequest(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Request wire.Raw `json:"request"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := decodeSignedField(w, req.Request)
	if !ok {
		return
	}
	key, err := sig.VerifySelf("contact-request")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var body contactRequestBody
	if err := sig.OpenClosed(&body); err != nil || body.From != sess.id || !wire.ValidIdentityID(body.To) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	me, myChain, err := s.identity(r.Context(), sess.id)
	if err != nil || !me.HasDevice(key) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "signer isn't a current device")
		return
	}
	ctx := r.Context()
	chainRaw := make([]wire.Raw, len(myChain))
	for i, e := range myChain {
		chainRaw[i] = e
	}
	// Everything below answers 202, whatever happens (SPEC §10.3).
	defer writeBody(w, http.StatusAccepted, map[string]any{})

	if s.isLocal(ctx, body.To) {
		s.receiveContactRequest(ctx, body, req.Request, chainRaw, s.cfg.Name)
		return
	}
	// Another server: remember the request on our side, then forward it (S2S contacts/request).
	them, _, err := s.lookup(ctx, body.To, "")
	if err != nil || s.fed == nil {
		return // unknown identity: the client should resolve and fetch its chain first
	}
	if c, err := s.st.Contacts().Get(ctx, sess.id, body.To); err == nil && c.State == store.StatePendingIn {
		// They already asked us: that makes it mutual (client-stage1.md).
		s.st.Contacts().Put(ctx, sess.id, store.Contact{ID: body.To, State: store.StateContact, Since: now()})
	} else {
		// Keep the request, so a decline can be matched to it (SPEC §9.3).
		s.st.Contacts().Put(ctx, sess.id, store.Contact{ID: body.To, State: store.StatePendingOut, Since: now(), Request: req.Request})
	}
	s.enqueue(ctx, them.Home, "contacts/request", map[string]any{"request": req.Request, "chain": chainRaw})
}

// receiveContactRequest handles a request whose recipient is local, from any server.
// origin is the requester's homeserver. Every refusal is silent (SPEC §10.3), to the sender;
// the operator's log says why, with no identifiers, so a request someone says never arrived
// can be traced.
func (s *Server) receiveContactRequest(ctx context.Context, body contactRequestBody, reqRaw wire.Raw, chainRaw []wire.Raw, origin string) {
	from, to := body.From, body.To
	drop := func(why string) { s.log.Info("contact request dropped", "origin", origin, "why", why) }
	if c, err := s.st.Contacts().Get(ctx, to, from); err == nil {
		switch {
		case c.State == store.StateBlocked:
			drop("blocked")
			return
		case c.State == store.StateDeclined && now()-c.Since < declineCooldown:
			drop("declined in the last 30 days") // no new requests, even with a new code (SPEC §9.3)
			return
		}
	}
	if why := s.checkInvite(ctx, body, origin); why != "" {
		drop(why) // every contact request needs a valid invite code (SPEC §9.1)
		return
	}
	notice := map[string]any{"t": "contact-request", "request": reqRaw, "chain": chainRaw}
	if s.isContactOrRequested(ctx, to, from) { // requests in both directions
		s.st.Contacts().Put(ctx, to, store.Contact{ID: from, State: store.StateContact, Since: now()})
		if s.isLocal(ctx, from) {
			s.st.Contacts().Put(ctx, from, store.Contact{ID: to, State: store.StateContact, Since: now()})
		}
		s.notify(ctx, to, notice)
		return
	}
	if s.isLocal(ctx, from) {
		s.st.Contacts().Put(ctx, from, store.Contact{ID: to, State: store.StatePendingOut, Since: now(), Request: reqRaw})
	}
	s.st.Contacts().Put(ctx, to, store.Contact{ID: from, State: store.StatePendingIn, Since: now(), Request: reqRaw})
	s.notify(ctx, to, notice)
}

func (s *Server) contactAccept(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		ID string `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	c, err := s.st.Contacts().Get(r.Context(), sess.id, req.ID)
	if err != nil || c.State != store.StatePendingIn {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no pending request from that identity")
		return
	}
	s.st.Contacts().Put(r.Context(), sess.id, store.Contact{ID: req.ID, State: store.StateContact, Since: now()})
	writeBody(w, http.StatusOK, map[string]any{})
}

func (s *Server) listContacts(w http.ResponseWriter, r *http.Request, sess session) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	cs, next, err := s.st.Contacts().List(r.Context(), sess.id, r.URL.Query().Get("after"), limit)
	if err != nil {
		s.unavailableRead(w, "listing contacts", err)
		return
	}
	items := []map[string]any{}
	for _, c := range cs {
		m := map[string]any{"id": c.ID, "state": c.State, "since": c.Since}
		if c.Request != nil {
			m["request"] = wire.Raw(c.Request)
		}
		items = append(items, m)
	}
	resp := map[string]any{"items": items}
	if next != "" {
		resp["next"] = next
	}
	writeBody(w, http.StatusOK, resp)
}
