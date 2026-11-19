package api

import (
	"context"
	"encoding/hex"
	"errors"
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
func (s *Server) notify(ctx context.Context, owner string, notice map[string]any) error {
	b, err := wire.Marshal(notice)
	if err != nil {
		return err
	}
	it := store.Item{TS: now(), Notice: b}
	cur, err := s.st.Inbox().Append(ctx, owner, it)
	if err != nil {
		return err
	}
	it.Cursor = cur
	s.pushItem(owner, it)
	if notice["t"] == "contact-request" {
		s.pushNotify(owner) // the only notice worth a push notification (push.go)
	}
	return nil
}

// logged logs a failure in a side effect the request doesn't depend on, such as telling
// other devices about a change that's already stored.
func (s *Server) logged(what string, err error) {
	if err != nil {
		s.log.Error(what, "err", err)
	}
}

// notFound answers a lookup that failed: 404 with msg if nothing is stored, and 503 for a
// storage failure, which the client retries.
func (s *Server) notFound(w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, msg)
		return
	}
	s.unavailableRead(w, "a lookup", err)
}

// isContactOrRequested reports whether owner accepts things from other:
// a full contact, or someone owner has a pending request out to (SPEC §9.3).
// A pending-outgoing request lasts 30 days (SPEC §9.3).
const pendingTTL = 30 * 24 * 3600

func (s *Server) isContactOrRequested(ctx context.Context, owner, other string) bool {
	ok, _ := s.contactOrRequested(ctx, owner, other) // an error counts as no
	return ok
}

// contactOrRequested is isContactOrRequested, returning storage failures.
func (s *Server) contactOrRequested(ctx context.Context, owner, other string) (bool, error) {
	c, err := s.st.Contacts().Get(ctx, owner, other)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return c.State == store.StateContact || (c.State == store.StatePendingOut && c.Since+pendingTTL > now()), nil
}

// ---- key packages (SPEC §11.4) ----

func (s *Server) kpUpload(w http.ResponseWriter, r *http.Request, sess session) {
	if s.wv == wire.V2 {
		s.kpUploadV2(w, r, sess)
		return
	}
	var req struct {
		Packages   []wire.Bytes `json:"packages"`
		LastResort wire.Bytes   `json:"last-resort,omitempty"`
		Replace    bool         `json:"replace,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Replace {
		if err := s.st.KeyPackages().Clear(r.Context(), sess.id, sess.device); err != nil {
			s.unavailableRead(w, "clearing key packages", err)
			return
		}
	}
	packages := make([]store.KeyPackage, len(req.Packages))
	for i, p := range req.Packages {
		packages[i] = store.KeyPackage{Data: p}
	}
	var lastResort *store.KeyPackage
	if req.LastResort != nil {
		lastResort = &store.KeyPackage{Data: req.LastResort}
	}
	n, err := s.st.KeyPackages().Upload(r.Context(), sess.id, sess.device, packages, lastResort)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"count": n})
}

// kpWithBinding is a wire version 2 key package with its kp-binding (SPEC §3.2.2), the
// shape spec/api/community.md gives community servers' uploads.
type kpWithBinding struct {
	KP      wire.Bytes `json:"kp"`
	Binding wire.Raw   `json:"binding"`
}

// kpUploadV2 is POST keypackages/upload in wire version 2: each package comes with its
// kp-binding, which has to be signed by the token device's composite key, name the
// token's identity, and hash the package (SPEC §3.2.2). Claimants check it again. The
// server never parses the package, so the msg-key in its leaf (SPEC §7.1) is theirs to check.
func (s *Server) kpUploadV2(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Packages   []kpWithBinding `json:"packages"`
		LastResort *kpWithBinding  `json:"last-resort,omitempty"`
		Replace    bool            `json:"replace,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	me, _, err := s.identity(r.Context(), sess.id)
	if err != nil {
		s.unavailableRead(w, "reading the uploader's chain", err)
		return
	}
	dev := me.DevicePub(sess.device)
	if dev == nil {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not a current device")
		return
	}
	check := func(p kpWithBinding) (store.KeyPackage, bool) {
		if len(p.KP) == 0 {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "a key package needs kp and binding")
			return store.KeyPackage{}, false
		}
		sig, err := s.decodeSigned(p.Binding)
		if err != nil {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "binding: "+err.Error())
			return store.KeyPackage{}, false
		}
		if err := wire.VerifyKPBinding(sig, sess.id, dev, p.KP); errors.Is(err, wire.ErrBadSignature) {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "the binding isn't signed by this device")
			return store.KeyPackage{}, false
		} else if err != nil {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "the binding doesn't match its key package and identity")
			return store.KeyPackage{}, false
		}
		enc, _ := sig.Encode()
		return store.KeyPackage{Data: p.KP, Binding: enc}, true
	}
	packages := make([]store.KeyPackage, len(req.Packages))
	for i, p := range req.Packages {
		var ok bool
		if packages[i], ok = check(p); !ok {
			return
		}
	}
	var lastResort *store.KeyPackage
	if req.LastResort != nil {
		lr, ok := check(*req.LastResort)
		if !ok {
			return
		}
		lastResort = &lr
	}
	if req.Replace {
		if err := s.st.KeyPackages().Clear(r.Context(), sess.id, sess.device); err != nil {
			s.unavailableRead(w, "clearing key packages", err)
			return
		}
	}
	n, err := s.st.KeyPackages().Upload(r.Context(), sess.id, sess.device, packages, lastResort)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"count": n})
}

func (s *Server) kpCount(w http.ResponseWriter, r *http.Request, sess session) {
	n, lr, err := s.st.KeyPackages().Count(r.Context(), sess.id, sess.device)
	if err != nil {
		// A count of 0 would have the client upload a fresh batch it doesn't need.
		s.unavailableRead(w, "counting key packages", err)
		return
	}
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
	if st.Closed() {
		writeError(w, http.StatusGone, wire.ErrCodeMigrated, migratedMsg) // SPEC §6.8
		return
	}
	allowed := target == claimant || s.isContactOrRequested(r.Context(), target, claimant)
	if !allowed && group != nil {
		// Group IDs aren't secret, so these claims are rate-limited (SPEC §11.4).
		if allowed, err = s.st.Contacts().GroupAllowed(r.Context(), target, group); err != nil {
			s.unavailableRead(w, "checking a group allowlist", err)
			return
		}
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
	kps, err := s.st.KeyPackages().Claim(r.Context(), target, devices)
	if err != nil {
		s.unavailableRead(w, "claiming key packages", err)
		return
	}
	out := []map[string]any{}
	for _, kp := range kps {
		p := map[string]any{"dev": kp.Device, "kp": kp.Data, "last-resort": kp.LastResort}
		if kp.Binding != nil {
			p["binding"] = wire.Raw(kp.Binding) // wire version 2 (SPEC §3.2.2)
		}
		out = append(out, p)
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
	sig, ok := s.decodeSignedField(w, req.Request)
	if !ok {
		return
	}
	key, err := s.signer(sig, "contact-request")
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
	if err != nil || !s.deviceSigned(me, sig, "contact-request", key) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "signer isn't a current device")
		return
	}
	ctx := r.Context()
	// Either side migrated to wire version 2 (SPEC §6.8). The chains are public, so saying
	// so out loud gives nothing away.
	switch {
	case me.Closed():
		writeError(w, http.StatusGone, wire.ErrCodeMigrated, migratedSelfMsg)
		return
	case s.closedKnown(ctx, body.To):
		writeError(w, http.StatusGone, wire.ErrCodeMigrated, migratedMsg)
		return
	}
	chainRaw := make([]wire.Raw, len(myChain))
	for i, e := range myChain {
		chainRaw[i] = e
	}
	// Everything below answers 202, whatever happens to the request (SPEC §10.3), unless
	// our own storage fails: then 503, which says nothing about the recipient.
	if err := s.sendContactRequest(ctx, sess, body, req.Request, chainRaw); err != nil {
		s.unavailableRead(w, "sending a contact request", err)
		return
	}
	writeBody(w, http.StatusAccepted, map[string]any{})
}

func (s *Server) sendContactRequest(ctx context.Context, sess session, body contactRequestBody, reqRaw wire.Raw, chainRaw []wire.Raw) error {
	if s.isLocal(ctx, body.To) {
		return s.receiveContactRequest(ctx, body, reqRaw, chainRaw, s.cfg.Name)
	}
	// Another server: remember the request on our side, then forward it (S2S contacts/request).
	them, _, err := s.lookup(ctx, body.To, "")
	if err != nil || s.fed == nil {
		return nil // unknown identity: the client should resolve and fetch its chain first
	}
	c, err := s.st.Contacts().Get(ctx, sess.id, body.To)
	switch {
	case err == nil && c.State == store.StatePendingIn:
		// They already asked us: that makes it mutual (client-stage1.md).
		err = s.st.Contacts().Put(ctx, sess.id, store.Contact{ID: body.To, State: store.StateContact, Since: now()})
	case err == nil && c.State == store.StateContact:
		// Already a contact, as one carried over from wire version 1 is (SPEC §6.8): asking
		// again doesn't make it a pending request. The request still goes, so their
		// client hears that this one lost the contact.
		err = nil
	case err == nil || errors.Is(err, store.ErrNotFound):
		// Keep the request, so a decline can be matched to it (SPEC §9.3).
		err = s.st.Contacts().Put(ctx, sess.id, store.Contact{ID: body.To, State: store.StatePendingOut, Since: now(), Request: reqRaw})
	}
	if err != nil {
		return err
	}
	return s.enqueue(ctx, them.Home, "contacts/request", map[string]any{"request": reqRaw, "chain": chainRaw})
}

// receiveContactRequest handles a request whose recipient is local, from any server.
// origin is the requester's homeserver. Every refusal is silent (SPEC §10.3), to the sender;
// the operator's log says why, with no identifiers, so a request someone says never arrived
// can be traced. An error is a storage failure, and the request should be retried.
func (s *Server) receiveContactRequest(ctx context.Context, body contactRequestBody, reqRaw wire.Raw, chainRaw []wire.Raw, origin string) error {
	from, to := body.From, body.To
	drop := func(why string) { s.log.Info("contact request dropped", "origin", origin, "why", why) }
	switch c, err := s.st.Contacts().Get(ctx, to, from); {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return err
	case err != nil:
	case c.State == store.StateBlocked:
		drop("blocked")
		return nil
	case c.State == store.StateDeclined && now()-c.Since < declineCooldown:
		drop("declined in the last 30 days") // no new requests, even with a new code (SPEC §9.3)
		return nil
	}
	if s.closedLocal(ctx, to) {
		drop("the recipient migrated to wire version 2") // SPEC §6.8
		return nil
	}
	if why := s.checkInvite(ctx, body, origin); why != "" {
		drop(why) // every contact request needs a valid invite code (SPEC §9.1)
		return nil
	}
	put := func(owner string, c store.Contact) error { return s.st.Contacts().Put(ctx, owner, c) }
	var err error
	if s.isContactOrRequested(ctx, to, from) { // requests in both directions
		err = put(to, store.Contact{ID: from, State: store.StateContact, Since: now()})
		if err == nil && s.isLocal(ctx, from) {
			err = put(from, store.Contact{ID: to, State: store.StateContact, Since: now()})
		}
	} else {
		if s.isLocal(ctx, from) {
			// A contact asking again stays a contact (sendContactRequest).
			if c, gerr := s.st.Contacts().Get(ctx, from, to); gerr != nil || c.State != store.StateContact {
				err = put(from, store.Contact{ID: to, State: store.StatePendingOut, Since: now(), Request: reqRaw})
			}
		}
		if err == nil {
			err = put(to, store.Contact{ID: from, State: store.StatePendingIn, Since: now(), Request: reqRaw})
		}
	}
	if err != nil {
		return err
	}
	return s.notify(ctx, to, map[string]any{"t": "contact-request", "request": reqRaw, "chain": chainRaw})
}

func (s *Server) contactAccept(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		ID string `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	const none = "no pending request from that identity"
	c, err := s.st.Contacts().Get(r.Context(), sess.id, req.ID)
	if err != nil {
		s.notFound(w, err, none)
		return
	}
	if c.State == store.StateContact {
		// Already a contact: a request from someone this identity lists, such as a contact
		// carried over from wire version 1 asking again (SPEC §6.8), is accepted already.
		writeBody(w, http.StatusOK, map[string]any{})
		return
	}
	if c.State != store.StatePendingIn {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, none)
		return
	}
	if err := s.st.Contacts().Put(r.Context(), sess.id, store.Contact{ID: req.ID, State: store.StateContact, Since: now()}); err != nil {
		s.unavailableRead(w, "accepting a contact", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{})
}

func (s *Server) listContacts(w http.ResponseWriter, r *http.Request, sess session) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	cs, next, err := s.st.Contacts().List(r.Context(), sess.id, r.URL.Query().Get("after"), limit)
	if err == nil && s.wv == wire.V2 && s.reconcile(r.Context(), sess.id, cs) {
		// Contacts that migrated from wire version 1 are listed as their version 2
		// identities now (SPEC §6.8).
		cs, next, err = s.st.Contacts().List(r.Context(), sess.id, r.URL.Query().Get("after"), limit)
	}
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
