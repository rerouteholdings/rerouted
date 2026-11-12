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
	if len(req.Group) != 32 || len(req.EpochKey) != 32 || (req.Kind != "direct" && req.Kind != "group") {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
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
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	}
	s.st.Contacts().AllowGroup(ctx, sess.id, req.Group)
	w.WriteHeader(http.StatusNoContent)
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
	if wire.Unmarshal(body, &req) != nil || len(req.Group) != 32 || len(req.EpochKey) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	if ok, _ := s.st.Remote().HasContactOn(ctx, from); !ok {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "this hub takes groups only from servers its users have contacts on")
		return
	}
	if !s.limits.allow("group-register|"+from, 100, 24*3600, now(), true) {
		writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: 3600})
		return
	}
	if err := s.st.Hub().Register(ctx, store.HubGroup{Group: req.Group, Epoch: req.Epoch, EpochKey: req.EpochKey}); err != nil {
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
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
		if allow {
			s.st.Contacts().AllowGroup(r.Context(), sess.id, req.Group)
		} else {
			s.st.Contacts().DisallowGroup(r.Context(), sess.id, req.Group)
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
	if ok, _ := s.st.Contacts().GroupAllowed(ctx, sess.id, group); !ok {
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

// sent remembers results per sender and delivery ID, so retries are idempotent.
var (
	sentMu sync.Mutex
	sent   = map[string]sendResult{}
)

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
	for i, o := range req.Deliveries {
		key := sess.id + "|" + hex.EncodeToString(o.ID)
		sentMu.Lock()
		prev, dup := sent[key]
		sentMu.Unlock()
		if dup {
			results[i] = prev
			continue
		}
		res := s.sendOne(r.Context(), sess, o)
		if res.Status == "sent" {
			sentMu.Lock()
			sent[key] = res
			sentMu.Unlock()
		}
		results[i] = res
	}
	writeBody(w, http.StatusOK, map[string]any{"results": results})
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
		s.deliverLocal(ctx, delivery{ID: o.ID, Kind: o.Kind, From: sess.id, To: o.To, Data: o.Data}, s.cfg.Name)
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
	d := delivery{ID: o.ID, Kind: o.Kind, From: sess.id, To: o.To, Group: o.Group, Epoch: o.Epoch, MLS: o.MLS, Data: o.Data}
	res := sendResult{ID: o.ID, Status: "sent"}

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
	s.deliver(ctx, d)

	// Welcomes go out only after the hub accepted the commit (SPEC §11.6).
	for _, wl := range o.Welcomes {
		s.deliver(ctx, delivery{ID: wl.ID, Kind: "mls", From: sess.id, To: wl.To, Group: o.Group, Epoch: o.Epoch + 1, MLS: "welcome", Data: wl.Data})
	}
	return res
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
	sig, err := wire.DecodeSigned(commit)
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
	if k, ok := sig.KeyBytes(); !ok || !bytes.Equal(k, g.EpochKey) || sig.Verify("commit-request", k) != nil {
		return wire.Signed{}, wire.ErrCodeBadSignature
	}
	receipt, err := wire.SignKID("commit-receipt", map[string]any{
		"hub": s.cfg.Name, "group": o.Group, "epoch": o.Epoch, "hash": sum[:], "ts": now(),
	}, s.key.Priv, s.key.KID)
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
func (s *Server) deliver(ctx context.Context, d delivery) {
	s.deliverLocal(ctx, d, s.cfg.Name)
	byHome := map[string][]string{}
	for _, to := range d.To {
		if s.isLocal(ctx, to) {
			continue
		}
		if st, _, err := s.lookup(ctx, to, ""); err == nil {
			byHome[st.Home] = append(byHome[st.Home], to)
		}
		// Unknown identities are dropped: a sender only talks to people it has fetched.
	}
	if s.fed == nil {
		return
	}
	for home, tos := range byHome {
		out := d
		out.To = tos
		s.enqueue(ctx, home, "deliver", map[string]any{"deliveries": []delivery{out}})
	}
}

// deliverLocal puts a delivery in each local recipient's inbox, applying the
// allowlists (SPEC §9.3). Drops are silent.
// origin is the server that delivered it.
func (s *Server) deliverLocal(ctx context.Context, d delivery, origin string) {
	enc, err := wire.Marshal(d)
	if err != nil {
		s.log.Error("encode delivery", "err", err)
		return
	}
	for _, to := range d.To {
		if !s.isLocal(ctx, to) || !s.allowed(ctx, d, to, origin) {
			continue
		}
		if d.MLS == "welcome" && to != d.From {
			// A Welcome from someone we asked promotes them to a full contact (SPEC §10.3).
			s.st.Contacts().Put(ctx, to, store.Contact{ID: d.From, State: store.StateContact, Since: now()})
		}
		if d.MLS == "welcome" && len(d.Group) > 0 {
			// Accepting a Welcome allowlists its group, so what members send before the
			// recipient's device processes it isn't dropped (SPEC §10.3).
			s.st.Contacts().AllowGroup(ctx, to, d.Group)
		}
		if isNew, _ := s.st.Inbox().SeenDelivery(ctx, to, d.ID); !isNew {
			continue
		}
		it := store.Item{TS: now(), Delivery: enc}
		if cur, err := s.st.Inbox().Append(ctx, to, it); err == nil {
			it.Cursor = cur
			s.pushItem(to, it)
			s.fire.publish(to, it)
		}
	}
}

// allowed applies a local recipient's allowlists to a delivery (SPEC §10.3).
func (s *Server) allowed(ctx context.Context, d delivery, to, origin string) bool {
	if to == d.From {
		return true
	}
	if c, err := s.st.Contacts().Get(ctx, to, d.From); err == nil && c.State == store.StateBlocked {
		return false
	}
	if d.MLS == "welcome" {
		return s.isContactOrRequested(ctx, to, d.From)
	}
	if ok, _ := s.st.Contacts().GroupAllowed(ctx, to, d.Group); !ok {
		return false
	}
	// Group IDs aren't secret: limit what one sender can push into a group (SPEC §10.3).
	g := wire.B64(d.Group)
	return s.limits.allowAll(now(),
		limit{"mls|" + d.From + "|" + g + "|" + to, 1000, 3600},
		limit{"mls-origin|" + originKey(origin) + "|" + g + "|" + to, 3000, 3600})
}

// ---- inbox (SPEC §9.4) ----

func (s *Server) getInbox(w http.ResponseWriter, r *http.Request, sess session) {
	items, next, gap, _ := s.st.Inbox().List(r.Context(), sess.id, sess.device, r.URL.Query().Get("after"), int(queryInt(r, "limit", 100)))
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
	s.ack(r.Context(), sess.id, sess.device, req.Upto)
	w.WriteHeader(http.StatusNoContent)
}

// ---- the `reg` fallback: registering an epoch key after acceptance (SPEC §11.6) ----

// registerKey checks an epoch-key registration against the hub's state for its group.
// The signature by the one-time `reg` key, committed to in the accepted commit request,
// is the whole authorization: nobody but the committing device holds it.
func (s *Server) registerKey(ctx context.Context, raw wire.Raw) (int, string) {
	sig, err := wire.DecodeSigned(raw)
	if err != nil {
		return http.StatusBadRequest, wire.ErrCodeBadRequest
	}
	reg, err := sig.VerifySelf("epoch-key")
	if err != nil {
		return http.StatusBadRequest, wire.ErrCodeBadSignature
	}
	var body struct {
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
		Next  wire.Bytes `json:"next"`
	}
	if sig.OpenClosed(&body) != nil || len(body.Group) != 32 || len(body.Next) != 32 || wire.SmallOrder(body.Next) || !wire.Canonical25519(body.Next) {
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
	sig, err := wire.DecodeSigned(cs[0].Request)
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
