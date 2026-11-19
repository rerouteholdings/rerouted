package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- groups (SPEC §9.3, §11.6) ----

func (s *Server) groupCreate(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Group    wire.Bytes `json:"group"`
		Kind     string     `json:"kind"`
		EpochKey wire.Bytes `json:"epoch-key"`
		Epoch    uint64     `json:"epoch,omitempty"` // after a hub handoff: the epoch the new hub starts at
		Hub      string     `json:"hub,omitempty"`   // the group's hub, if it isn't this server (SPEC §11.11)
	}
	if !readBody(w, r, &req) {
		return
	}
	if len(req.Group) != 32 || !s.epochKeyOK(req.EpochKey) || (req.Kind != "direct" && req.Kind != "group") {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	// Allowlisted first: it's harmless if the rest fails, and a retry would otherwise find
	// the group registered and get 409.
	if err := s.st.Contacts().AllowGroup(ctx, sess.id, req.Group); err != nil {
		s.unavailableRead(w, "allowlisting a group", err)
		return
	}
	if req.Hub != "" && req.Hub != s.cfg.Name {
		// Hub handoff to another server: register the group there (S2S group/register).
		body, _ := wire.Marshal(map[string]any{"group": req.Group, "epoch": req.Epoch, "epoch-key": req.EpochKey})
		if _, err := s.fed.Call(ctx, req.Hub, "group/register", body); err != nil {
			var es *fed.ErrStatus
			if errors.As(err, &es) {
				writeError(w, es.Status, es.Code, "")
			} else {
				writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, err.Error())
			}
			return
		}
	} else if err := s.st.Hub().Register(ctx, store.HubGroup{Group: req.Group, Epoch: req.Epoch, EpochKey: req.EpochKey}); err != nil {
		s.registerFailed(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// registerFailed answers a failed hub registration: 409 if the group is already
// registered, 503 if storage failed.
func (s *Server) registerFailed(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	}
	s.unavailableRead(w, "registering a group", err)
}

// S2S group/register: a hub handoff names this server as a group's new hub (SPEC §11.11).
// SPEC §11.11 doesn't yet say how the hub checks the caller speaks for the group, so
// rerouted takes it only from servers that are home to a full contact of one of its own
// users (spec/api/s2s-stage2.md), and only once per group.
func (s *Server) s2sGroupRegister(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Group    wire.Bytes `json:"group"`
		Epoch    uint64     `json:"epoch"`
		EpochKey wire.Bytes `json:"epoch-key"`
	}
	if wire.Unmarshal(body, &req) != nil || len(req.Group) != 32 || !s.epochKeyOK(req.EpochKey) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	ok, err := s.st.Remote().HasContactOn(ctx, from)
	if err != nil {
		s.unavailableRead(w, "checking a hub handoff", err) // not a refusal: the caller retries
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "this hub takes groups only from servers its users have contacts on")
		return
	}
	if !s.limits.allow("group-register|"+from, 100, 24*3600, now(), true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 3600})
		return
	}
	if err := s.st.Hub().Register(ctx, store.HubGroup{Group: req.Group, Epoch: req.Epoch, EpochKey: req.EpochKey}); err != nil {
		s.registerFailed(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) groupRegister(allow bool) func(http.ResponseWriter, *http.Request, session) {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		var req struct {
			Group wire.Bytes `json:"group"`
		}
		if !readBody(w, r, &req) {
			return
		}
		var err error
		if allow {
			err = s.st.Contacts().AllowGroup(r.Context(), sess.id, req.Group)
		} else {
			err = s.st.Contacts().DisallowGroup(r.Context(), sess.id, req.Group)
		}
		if err != nil {
			s.unavailableRead(w, "changing the groups allowlist", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) groupCommits(w http.ResponseWriter, r *http.Request, sess session) {
	group, err := base64.RawURLEncoding.DecodeString(r.PathValue("group"))
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "group must be base64url")
		return
	}
	ctx := r.Context()
	switch ok, err := s.st.Contacts().GroupAllowed(ctx, sess.id, group); {
	case err != nil:
		s.unavailableRead(w, "checking the groups allowlist", err)
		return
	case !ok:
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "")
		return
	}
	after := queryInt(r, "after", -1) // "after" is exclusive (client-stage1.md)
	if hub := r.URL.Query().Get("hub"); hub != "" && hub != s.cfg.Name {
		// The group's hub is elsewhere: fetch from it (S2S commit/fetch, SPEC §11.6).
		body, _ := wire.Marshal(map[string]any{"group": wire.Bytes(group), "after": after})
		b, err := s.fed.Call(ctx, hub, "commit/fetch", body)
		var es *fed.ErrStatus
		switch {
		case errors.As(err, &es):
			writeError(w, es.Status, es.Code, "")
		case err != nil:
			writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, err.Error())
		default:
			writeRaw(w, http.StatusOK, b)
		}
		return
	}
	items, status, code := s.hubCommits(ctx, group, after)
	if code != "" {
		writeError(w, status, code, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// hubCommits lists the commits this server holds as hub for epochs after `after`.
func (s *Server) hubCommits(ctx context.Context, group []byte, after int64) ([]map[string]any, int, string) {
	g, err := s.st.Hub().Group(ctx, group)
	if err != nil {
		return nil, http.StatusNotFound, wire.ErrCodeNotFound
	}
	from := uint64(max(after+1, 0))
	cs, err := s.st.Hub().Commits(ctx, group, from)
	if err != nil {
		return nil, http.StatusNotFound, wire.ErrCodeNotFound
	}
	// Epochs the hub has moved past but no longer holds were pruned (30 days, SPEC §11.6).
	if from < g.Epoch && (len(cs) == 0 || cs[0].Epoch > from) {
		return nil, http.StatusGone, wire.ErrCodeExpired
	}
	items := []map[string]any{}
	for _, c := range cs {
		enc, _ := c.Receipt.Encode()
		items = append(items, map[string]any{"epoch": c.Epoch, "data": wire.Bytes(c.Data), "receipt": wire.Raw(enc)})
	}
	return items, 0, ""
}

// S2S commit/fetch: a member's homeserver fetches missed commits from the hub (SPEC §11.6).
// Commits are encrypted, so there's no access check beyond a rate limit (SPEC §10.3).
func (s *Server) s2sCommitFetch(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Group wire.Bytes `json:"group"`
		After int64      `json:"after"`
	}
	if wire.Unmarshal(body, &req) != nil || len(req.Group) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if !s.limits.allow("commit-fetch|"+from, 3600, 3600, now(), true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 60})
		return
	}
	items, status, code := s.hubCommits(r.Context(), req.Group, req.After)
	if code != "" {
		writeError(w, status, code, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// ---- POST send (SPEC §9, §11.6) ----

type outgoing struct {
	ID        wire.Bytes `json:"id"`
	Kind      string     `json:"kind"`
	To        []string   `json:"to"`
	Group     wire.Bytes `json:"group"`
	Epoch     uint64     `json:"epoch"`
	MLS       string     `json:"mls"`
	Ephemeral bool       `json:"ephemeral,omitempty"`
	Data      wire.Bytes `json:"data"`
	Commit    wire.Raw   `json:"commit,omitempty"`
	Hub       string     `json:"hub,omitempty"` // the group's hub, if it isn't this server (SPEC §11.6)
	Welcomes  []struct {
		ID   wire.Bytes `json:"id"`
		To   []string   `json:"to"`
		Data wire.Bytes `json:"data"`
	} `json:"welcomes,omitempty"`
}

// maxLinkBundle bounds a link bundle: contacts, groups, and media references (SPEC §7.2).
const maxLinkBundle = 256 << 10

// delivery is the stored and delivered form (SPEC §9.1).
type delivery struct {
	ID        wire.Bytes `json:"id"`
	Kind      string     `json:"kind"`
	From      string     `json:"from"`
	To        []string   `json:"to"`
	Group     wire.Bytes `json:"group"`
	Epoch     uint64     `json:"epoch"`
	MLS       string     `json:"mls"`
	Receipt   wire.Raw   `json:"receipt,omitempty"`
	Ephemeral bool       `json:"ephemeral,omitempty"`
	Data      wire.Bytes `json:"data"`
}

// MarshalJSON leaves out the MLS fields for kinds other than "mls" (SPEC §10.1).
func (d delivery) MarshalJSON() ([]byte, error) {
	type plain delivery
	if d.Kind == "mls" {
		return json.Marshal(plain(d))
	}
	return json.Marshal(struct {
		ID        wire.Bytes `json:"id"`
		Kind      string     `json:"kind"`
		From      string     `json:"from"`
		To        []string   `json:"to"`
		Ephemeral bool       `json:"ephemeral,omitempty"`
		Data      wire.Bytes `json:"data"`
	}{d.ID, d.Kind, d.From, d.To, d.Ephemeral, d.Data})
}

type sendResult struct {
	ID      wire.Bytes `json:"id"`
	Status  string     `json:"status"`
	Error   string     `json:"error,omitempty"`
	Receipt wire.Raw   `json:"receipt,omitempty"`
}

// inboxRetention is how long undelivered items are kept (SPEC §9.4).
const inboxRetention = 30 * 24 * 3600

var mlsKinds = map[string]bool{"app": true, "proposal": true, "commit": true, "welcome": true}

func (s *Server) send(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Deliveries []outgoing `json:"deliveries"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if len(req.Deliveries) == 0 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "no deliveries")
		return
	}
	results := make([]sendResult, len(req.Deliveries))
	if s.closedLocal(r.Context(), sess.id) {
		// The sender migrated to wire version 2, and sends from there (SPEC §6.8).
		for i, o := range req.Deliveries {
			results[i] = reject(o.ID, wire.ErrCodeMigrated)
		}
		writeBody(w, http.StatusOK, map[string]any{"results": results})
		return
	}
	for i, o := range req.Deliveries {
		res, err := s.sendIdempotent(r.Context(), sess, o)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
			return
		}
		results[i] = res
	}
	writeBody(w, http.StatusOK, map[string]any{"results": results})
}

// sendIdempotent sends one delivery, or returns the result it got when its sender sent
// the same ID before: resubmitting an ID never delivers twice (POST send). Results are
// stored once the delivery is sent, and kept for 30 days. Two requests with the same ID
// at once take turns, so the second finds the first one's result. An error means the
// stored results couldn't be read, so the client should retry the request.
func (s *Server) sendIdempotent(ctx context.Context, sess session, o outgoing) (sendResult, error) {
	unlock, err := s.sending.lock(ctx, sess.id+"|"+hex.EncodeToString(o.ID))
	if err != nil {
		return sendResult{}, err
	}
	defer unlock()
	switch b, err := s.st.Sent().Get(ctx, sess.id, o.ID); {
	case err == nil:
		var prev sendResult
		if err := wire.Unmarshal(b, &prev); err != nil {
			return sendResult{}, err
		}
		return prev, nil
	case !errors.Is(err, store.ErrNotFound):
		return sendResult{}, err
	}
	res := s.sendOne(ctx, sess, o)
	if res.Status != "sent" {
		return res, nil // rejections aren't kept: a corrected retry gets a fresh try
	}
	b, err := wire.Marshal(res)
	if err == nil {
		err = s.st.Sent().Put(ctx, sess.id, o.ID, b, now())
	}
	if err != nil {
		// It was delivered: say so. A retry would deliver it again, but every recipient's
		// inbox drops a delivery ID it already has.
		s.log.Error("storing a send result", "err", err)
	}
	return res, nil
}

// keyLocks serializes work on the same key, such as one sender's delivery ID.
type keyLocks struct {
	mu   sync.Mutex
	busy map[string]chan struct{}
}

// lock waits until no one else holds key, then holds it until the returned func is called.
func (l *keyLocks) lock(ctx context.Context, key string) (func(), error) {
	for {
		l.mu.Lock()
		if l.busy == nil {
			l.busy = map[string]chan struct{}{}
		}
		done, held := l.busy[key]
		if !held {
			done = make(chan struct{})
			l.busy[key] = done
			l.mu.Unlock()
			return func() {
				l.mu.Lock()
				delete(l.busy, key)
				l.mu.Unlock()
				close(done)
			}, nil
		}
		l.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func reject(id []byte, code string) sendResult {
	return sendResult{ID: id, Status: "rejected", Error: code}
}

func (s *Server) sendOne(ctx context.Context, sess session, o outgoing) sendResult {
	if o.Kind == "link" {
		// A link bundle for a new device of the sender's own identity (SPEC §7.2): it only
		// ever goes to the sender's own inbox.
		if len(o.ID) != 16 || len(o.Data) == 0 || len(o.Data) > maxLinkBundle || len(o.To) != 1 || o.To[0] != sess.id {
			return reject(o.ID, wire.ErrCodeBadRequest)
		}
		if err := s.deliverLocal(ctx, delivery{ID: o.ID, Kind: o.Kind, From: sess.id, To: o.To, Data: o.Data}, s.cfg.Name); err != nil {
			return s.unavailable(o.ID, err)
		}
		return sendResult{ID: o.ID, Status: "sent"}
	}
	switch {
	case o.Kind != "mls":
		return reject(o.ID, wire.ErrCodeUnknownKind)
	case !mlsKinds[o.MLS]:
		return reject(o.ID, wire.ErrCodeUnknownKind)
	case len(o.ID) != 16 || len(o.Group) != 32 || len(o.To) == 0 || len(o.Data) == 0:
		return reject(o.ID, wire.ErrCodeBadRequest)
	}
	if s.allMigrated(ctx, sess.id, o.To) {
		// Nobody it's for can get it: they all migrated to wire version 2 (SPEC §6.8).
		// Refused before anything happens, a commit's sequencing included.
		return reject(o.ID, wire.ErrCodeMigrated)
	}
	d := delivery{ID: o.ID, Kind: o.Kind, From: sess.id, To: o.To, Group: o.Group, Epoch: o.Epoch, MLS: o.MLS, Data: o.Data}
	res := sendResult{ID: o.ID, Status: "sent"}
	if s.wv == wire.V2 && publicMessage(o.Data) {
		// Members send everything as PrivateMessage; only a community code join's external
		// commit is a PublicMessage (SPEC §10.1, §11.1), and community groups aren't here.
		return reject(o.ID, wire.ErrCodeBadRequest)
	}
	if o.MLS == "commit" {
		var enc []byte
		var code string
		if o.Hub != "" && o.Hub != s.cfg.Name {
			enc, code = s.sequenceRemote(ctx, o)
		} else {
			var receipt wire.Signed
			if receipt, code = s.sequence(ctx, o.Commit, o.Data, o.Group, o.Epoch); code == "" {
				enc, _ = receipt.Encode()
			}
		}
		if code != "" {
			return reject(o.ID, code)
		}
		d.Receipt, res.Receipt = enc, enc
	}
	if o.Ephemeral {
		// Typing and receipts: to connected devices only, never stored or retried (SPEC §13.3).
		d.Ephemeral = true
		s.deliverEphemeral(ctx, d, s.cfg.Name, true)
		return res
	}
	// If storing fails, the client retries. A retried commit gets the receipt the hub
	// already gave it (SPEC §11.6), and recipients drop what they already have.
	if err := s.deliver(ctx, d); err != nil {
		return s.unavailable(o.ID, err)
	}
	// Welcomes go out only after the hub accepted the commit (SPEC §11.6).
	for _, wl := range o.Welcomes {
		if err := s.deliver(ctx, delivery{ID: wl.ID, Kind: "mls", From: sess.id, To: wl.To, Group: o.Group, Epoch: o.Epoch + 1, MLS: "welcome", Data: wl.Data}); err != nil {
			return s.unavailable(o.ID, err)
		}
	}
	return res
}

// unavailable is the result for a delivery that couldn't be stored. It isn't kept, so
// the client's retry tries again.
func (s *Server) unavailable(id []byte, err error) sendResult {
	s.log.Error("storing a delivery", "err", err)
	return reject(id, wire.ErrCodeUnavailable)
}

// sequenceRemote asks the group's hub on another server to sequence a commit (S2S commit).
func (s *Server) sequenceRemote(ctx context.Context, o outgoing) ([]byte, string) {
	body, _ := wire.Marshal(map[string]any{"commit": o.Commit, "data": o.Data})
	b, err := s.fed.Call(ctx, o.Hub, "commit", body)
	var es *fed.ErrStatus
	switch {
	case errors.As(err, &es) && es.Code != "":
		return nil, es.Code
	case err != nil:
		return nil, wire.ErrCodeUnavailable
	}
	var res struct {
		Receipt wire.Raw `json:"receipt"`
	}
	if wire.Unmarshal(b, &res) != nil || res.Receipt == nil {
		return nil, wire.ErrCodeUnavailable
	}
	return res.Receipt, ""
}

// sequence runs the hub step for a commit this server is the hub for (SPEC §11.6).
func (s *Server) sequence(ctx context.Context, commit wire.Raw, data, group []byte, epoch uint64) (wire.Signed, string) {
	o := struct {
		Data  []byte
		Group []byte
		Epoch uint64
	}{data, group, epoch}
	if commit == nil {
		return wire.Signed{}, wire.ErrCodeBadRequest
	}
	sig, err := s.decodeSigned(commit)
	if err != nil || sig.T != "commit-request" {
		return wire.Signed{}, wire.ErrCodeBadRequest
	}
	var cr struct {
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
		Hash  wire.Bytes `json:"hash"`
		Next  wire.Bytes `json:"next,omitempty"`
		Reg   wire.Bytes `json:"reg,omitempty"` // the fallback: register next after acceptance (SPEC §11.6)
	}
	sum := sha256.Sum256(o.Data)
	if sig.OpenClosed(&cr) != nil || !bytes.Equal(cr.Group, o.Group) || cr.Epoch != o.Epoch || !bytes.Equal(cr.Hash, sum[:]) {
		return wire.Signed{}, wire.ErrCodeBadRequest
	}
	// Exactly one of next and reg.
	key, awaiting := []byte(cr.Next), false
	switch {
	case s.wv == wire.V2 && cr.Next != nil && cr.Reg == nil && s.epochKeyOK(cr.Next):
	case s.wv == wire.V2 && cr.Reg != nil && cr.Next == nil && s.epochKeyOK(cr.Reg):
		key, awaiting = cr.Reg, true
	case s.wv == wire.V2:
		return wire.Signed{}, wire.ErrCodeBadRequest
	case len(cr.Next) == 32 && cr.Reg == nil:
	case len(cr.Reg) == 32 && cr.Next == nil && !wire.SmallOrder(cr.Reg) && wire.Canonical25519(cr.Reg):
		key, awaiting = cr.Reg, true
	default:
		return wire.Signed{}, wire.ErrCodeBadRequest
	}
	g, err := s.st.Hub().Group(ctx, o.Group)
	if err != nil {
		return wire.Signed{}, wire.ErrCodeNotFound
	}
	if g.Epoch != o.Epoch {
		return s.retried(ctx, o.Group, o.Epoch, commit)
	}
	if g.Awaiting {
		return wire.Signed{}, wire.ErrCodeAwaitingKey
	}
	if !s.epochSigned(sig, "commit-request", g.EpochKey) {
		return wire.Signed{}, wire.ErrCodeBadSignature
	}
	// Signed with this server's key for the wire version: composite in version 2.
	receipt, err := s.fed.SignKID("commit-receipt", map[string]any{
		"hub": s.cfg.Name, "group": o.Group, "epoch": o.Epoch, "hash": sum[:], "ts": now(),
	})
	if err != nil {
		return wire.Signed{}, wire.ErrCodeUnavailable
	}
	err = s.st.Hub().Accept(ctx, o.Group, o.Epoch, key, awaiting, store.Commit{Epoch: o.Epoch, Data: o.Data, Receipt: receipt, TS: now(), Request: commit})
	if errors.Is(err, store.ErrConflict) {
		return s.retried(ctx, o.Group, o.Epoch, commit)
	}
	if err != nil {
		return wire.Signed{}, wire.ErrCodeUnavailable
	}
	return receipt, ""
}

// retried answers a commit request for an epoch the hub has moved past. If it's the very
// request the hub accepted for that epoch, the reply was lost and this is a retry: it gets
// the same receipt, so its fan-out and Welcomes still go out (SPEC §11.6). Anything else
// lost the race.
func (s *Server) retried(ctx context.Context, group []byte, epoch uint64, request []byte) (wire.Signed, string) {
	if cs, err := s.st.Hub().Commits(ctx, group, epoch); err == nil && len(cs) > 0 && cs[0].Epoch == epoch && len(cs[0].Request) > 0 && bytes.Equal(cs[0].Request, request) {
		return cs[0].Receipt, ""
	}
	return wire.Signed{}, wire.ErrCodeStaleEpoch
}

// deliver sends a locally submitted delivery: into local inboxes, and through
// the outbox to every other server with recipients, one call per server (SPEC §9.2).
// An error means some of it wasn't stored, and the whole delivery should be retried.
func (s *Server) deliver(ctx context.Context, d delivery) error {
	if err := s.deliverLocal(ctx, d, s.cfg.Name); err != nil {
		return err
	}
	byHome := map[string][]string{}
	var migrated []string
	for _, to := range d.To {
		if s.closedLocal(ctx, to) {
			migrated = append(migrated, to) // deliverLocal left it out
			continue
		}
		if s.isLocal(ctx, to) {
			continue
		}
		if st, _, err := s.lookup(ctx, to, ""); err == nil {
			if st.Closed() {
				migrated = append(migrated, to)
				continue
			}
			byHome[st.Home] = append(byHome[st.Home], to)
		}
		// Unknown identities are dropped: a sender only talks to people it has fetched.
	}
	if len(migrated) > 0 && s.isLocal(ctx, d.From) {
		// Not dropped silently: the sender's devices learn who migrated (SPEC §6.8, §10.5).
		s.logged("telling a sender a delivery failed", s.notify(ctx, d.From, map[string]any{"t": "delivery-failed", "id": d.ID, "to": migrated, "reason": wire.ErrCodeMigrated}))
	}
	if s.fed == nil {
		return nil
	}
	for home, tos := range byHome {
		out := d
		out.To = tos
		if err := s.enqueue(ctx, home, "deliver", map[string]any{"deliveries": []delivery{out}}); err != nil {
			return err
		}
	}
	return nil
}

// deliverLocal puts a delivery in each local recipient's inbox, applying the
// allowlists (SPEC §9.3). Drops are silent.
// origin is the server that delivered it.
//
// Every recipient's copy is stored in one transaction, then pushed to their connected
// devices. It returns the first storage error, after trying every recipient. Copies are
// stored whole or not at all, and a recipient that already has it drops the repeat, so
// the caller can retry the whole delivery.
func (s *Server) deliverLocal(ctx context.Context, d delivery, origin string) error {
	enc, err := wire.Marshal(d)
	if err != nil {
		return err
	}
	var first error
	var ds []store.Delivered
	for _, to := range d.To {
		ok, err := s.admit(ctx, d, to, origin)
		if err != nil && first == nil {
			first = err
		}
		if ok {
			ds = append(ds, store.Delivered{Owner: to, ID: d.ID, Item: store.Item{TS: now(), Delivery: enc}})
		}
	}
	if len(ds) == 0 {
		return first
	}
	curs, err := s.st.Inbox().DeliverAll(ctx, ds)
	if err != nil {
		return err
	}
	for i, cur := range curs {
		if cur == "" {
			continue // a repeat
		}
		it := ds[i].Item
		it.Cursor = cur
		s.pushItem(ds[i].Owner, it)
		s.fire.publish(ds[i].Owner, it)
		if pushWorthy(d, ds[i].Owner) {
			s.pushNotify(ds[i].Owner)
		}
	}
	return first
}

// admit reports whether a delivery goes into a recipient's inbox: they live here, and
// their allowlists let it in. Accepting a Welcome updates their allowlists on the way.
func (s *Server) admit(ctx context.Context, d delivery, to, origin string) (bool, error) {
	if here, err := s.local(ctx, to); err != nil || !here {
		return false, err
	}
	if ok, err := s.allowed(ctx, d, to, origin); err != nil || !ok {
		return false, err
	}
	if d.MLS == "welcome" && to != d.From {
		// A Welcome from someone we asked promotes them to a full contact (SPEC §10.3).
		if err := s.st.Contacts().Put(ctx, to, store.Contact{ID: d.From, State: store.StateContact, Since: now()}); err != nil {
			return false, err
		}
	}
	if d.MLS == "welcome" && len(d.Group) > 0 {
		// Accepting a Welcome allowlists its group, so what members send before the
		// recipient's device processes it isn't dropped (SPEC §10.3).
		if err := s.st.Contacts().AllowGroup(ctx, to, d.Group); err != nil {
			return false, err
		}
	}
	return true, nil
}

// allowed applies a local recipient's allowlists to a delivery (SPEC §10.3). An error is
// a storage failure: the caller retries rather than drop the delivery, or let it past a
// block it couldn't check.
func (s *Server) allowed(ctx context.Context, d delivery, to, origin string) (bool, error) {
	if s.closedLocal(ctx, to) {
		return false, nil // migrated to wire version 2 (SPEC §6.8): the caller says so
	}
	if to == d.From {
		return true, nil
	}
	switch c, err := s.st.Contacts().Get(ctx, to, d.From); {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		return false, err
	case err == nil && c.State == store.StateBlocked:
		return false, nil
	}
	if d.MLS == "welcome" {
		return s.contactOrRequested(ctx, to, d.From)
	}
	if ok, err := s.st.Contacts().GroupAllowed(ctx, to, d.Group); err != nil || !ok {
		return false, err
	}
	// Group IDs aren't secret: limit what one sender can push into a group (SPEC §10.3).
	g := wire.B64(d.Group)
	return s.limits.allowAll(now(),
		limit{"mls|" + d.From + "|" + g + "|" + to, 1000, 3600},
		limit{"mls-origin|" + originKey(origin) + "|" + g + "|" + to, 3000, 3600}), nil
}

// ---- inbox (SPEC §9.4) ----

func (s *Server) getInbox(w http.ResponseWriter, r *http.Request, sess session) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	items, next, gap, err := s.st.Inbox().List(r.Context(), sess.id, sess.device, r.URL.Query().Get("after"), limit)
	if err != nil {
		s.unavailableRead(w, "reading an inbox", err)
		return
	}
	out := []map[string]any{}
	for _, it := range items {
		m := map[string]any{"cursor": it.Cursor, "ts": it.TS}
		if it.Delivery != nil {
			m["delivery"] = wire.Raw(it.Delivery)
		} else {
			m["notice"] = wire.Raw(it.Notice)
		}
		out = append(out, m)
	}
	resp := map[string]any{"items": out, "gap": gap}
	if next != "" {
		resp["next"] = next
	}
	writeBody(w, http.StatusOK, resp)
}

func (s *Server) ackInbox(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Upto string `json:"upto"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if err := s.ack(r.Context(), sess.id, sess.device, req.Upto); err != nil {
		s.unavailableRead(w, "acking an inbox", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- the `reg` fallback: registering an epoch key after acceptance (SPEC §11.6) ----

// registerKey checks an epoch-key registration against the hub's state for its group.
// The signature by the one-time `reg` key, committed to in the accepted commit request,
// is the whole authorization: nobody but the committing device holds it.
func (s *Server) registerKey(ctx context.Context, raw wire.Raw) (int, string) {
	sig, err := s.decodeSigned(raw)
	if err != nil {
		return http.StatusBadRequest, wire.ErrCodeBadRequest
	}
	reg, err := s.selfKey(sig, "epoch-key")
	if err != nil {
		return http.StatusBadRequest, wire.ErrCodeBadSignature
	}
	var body struct {
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
		Next  wire.Bytes `json:"next"`
	}
	if sig.OpenClosed(&body) != nil || len(body.Group) != 32 {
		return http.StatusBadRequest, wire.ErrCodeBadRequest
	}
	nextOK := len(body.Next) == 32 && !wire.SmallOrder(body.Next) && wire.Canonical25519(body.Next)
	if s.wv == wire.V2 {
		nextOK = s.epochKeyOK(body.Next)
	}
	if !nextOK {
		return http.StatusBadRequest, wire.ErrCodeBadRequest
	}
	if _, err := s.st.Hub().Group(ctx, body.Group); err != nil {
		return http.StatusNotFound, wire.ErrCodeNotFound
	}
	if err := s.st.Hub().SetKey(ctx, body.Group, body.Epoch, reg, body.Next); err != nil {
		if s.keyRegistered(ctx, body.Group, body.Epoch, reg, body.Next) {
			return http.StatusNoContent, "" // a retry after a lost reply: it already took effect
		}
		return http.StatusConflict, wire.ErrCodeStaleEpoch
	}
	return http.StatusNoContent, ""
}

// keyRegistered reports whether this exact registration already took effect: the group is
// at `epoch` with `next` as its key, and the commit that created the epoch named `reg`.
func (s *Server) keyRegistered(ctx context.Context, group []byte, epoch uint64, reg, next []byte) bool {
	g, err := s.st.Hub().Group(ctx, group)
	if err != nil || g.Epoch != epoch || g.Awaiting || !bytes.Equal(g.EpochKey, next) || epoch == 0 {
		return false
	}
	cs, err := s.st.Hub().Commits(ctx, group, epoch-1)
	if err != nil || len(cs) == 0 || cs[0].Epoch != epoch-1 {
		return false
	}
	sig, err := s.decodeSigned(cs[0].Request)
	var cr struct {
		Reg wire.Bytes `json:"reg"`
	}
	return err == nil && sig.Open(&cr) == nil && bytes.Equal(cr.Reg, reg)
}

// POST groups/epoch-key: a committer registers the next epoch key with the group's hub,
// here or (with "hub") on another server.
func (s *Server) groupEpochKey(w http.ResponseWriter, r *http.Request, _ session) {
	var req struct {
		Hub string   `json:"hub,omitempty"`
		Key wire.Raw `json:"key"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Hub != "" && req.Hub != s.cfg.Name {
		body, _ := wire.Marshal(map[string]any{"key": req.Key})
		_, err := s.fed.Call(r.Context(), req.Hub, "group/epoch-key", body)
		var es *fed.ErrStatus
		switch {
		case errors.As(err, &es):
			writeError(w, es.Status, es.Code, "")
		case err != nil:
			writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, err.Error())
		default:
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	if status, code := s.registerKey(r.Context(), req.Key); code != "" {
		writeError(w, status, code, "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// S2S group/epoch-key: the same, for groups whose hub is here.
func (s *Server) s2sGroupEpochKey(w http.ResponseWriter, r *http.Request, _ string, body wire.Raw) {
	var req struct {
		Key wire.Raw `json:"key"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if status, code := s.registerKey(r.Context(), req.Key); code != "" {
		writeError(w, status, code, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{})
}
