package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- joining and leaving (SPEC §16.6, spec/api/community.md) ----

// Failed joins are limited (SPEC §16.7): 10 per identity and 100 per origin registrable
// domain an hour (spec/api/community.md).
const (
	failedJoinsPerID     = 10
	failedJoinsPerOrigin = 100
)

func (c *community) joinFailed(sess csess) {
	t := now()
	c.hs.limits.allow("cm-joinfail|"+c.name+"|"+sess.id, failedJoinsPerID, 3600, t, true)
	c.hs.limits.allow("cm-joinfail|"+c.name+"|@"+originKey(sess.home), failedJoinsPerOrigin, 3600, t, true)
}

func (c *community) joinBlocked(sess csess) bool {
	t := now()
	return !c.hs.limits.allow("cm-joinfail|"+c.name+"|"+sess.id, failedJoinsPerID, 3600, t, false) ||
		!c.hs.limits.allow("cm-joinfail|"+c.name+"|@"+originKey(sess.home), failedJoinsPerOrigin, 3600, t, false)
}

// POST join: a code join's external commit, with its join proof (SPEC §16.6, §11.6).
func (c *community) join(w http.ResponseWriter, r *http.Request, sess csess) {
	if c.joinBlocked(sess) {
		rateLimited(w, 3600)
		return
	}
	var req struct {
		Group  wire.Bytes `json:"group"`
		Epoch  uint64     `json:"epoch"`
		Data   wire.Bytes `json:"data"`
		Commit wire.Raw   `json:"commit"`
		Proof  wire.Raw   `json:"proof"`
		Info   wire.Bytes `json:"info"`
		Tree   wire.Bytes `json:"tree"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	st := c.snapshot()
	cm, err := c.st.Get(ctx, c.name)
	if st == nil || errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a community", err)
		return
	}
	refuse := func(msg string) {
		c.joinFailed(sess)
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, msg)
	}
	code, ok := c.codeAccess(r)
	if !ok {
		refuse("no live code with uses left")
		return
	}
	if cm.Group == nil || !bytes.Equal(req.Group, cm.Group) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "group isn't the members group")
		return
	}
	// Only a code join's external commit is a PublicMessage (SPEC §10.1, §11.1).
	if len(req.Data) == 0 || !publicMessage(req.Data) || len(req.Info) == 0 || len(req.Tree) != 32 || req.Commit == nil || req.Proof == nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "data (a PublicMessage), commit, proof, info, and tree are required")
		return
	}
	if st.Approval {
		refuse("joins need approval here: POST join/request")
		return
	}
	if st.Banned(sess.id, sess.home) {
		refuse("banned")
		return
	}
	sum := sha256.Sum256(req.Data)
	// The join proof, under the code's composite key, naming this joiner, epoch, and commit.
	proof, err := wire.DecodeSignedV2(req.Proof)
	if err != nil || proof.T != "join-proof" || !bytes.Equal(proof.K, code.Key) {
		refuse("the join proof isn't signed with this code's key")
		return
	}
	if _, err := proof.VerifyCompositeSelf("join-proof"); err != nil {
		refuse("the join proof's signature doesn't verify")
		return
	}
	var pb struct {
		Commit wire.Bytes `json:"commit"`
		ID     string     `json:"id"`
		Epoch  uint64     `json:"epoch"`
	}
	if proof.OpenClosed(&pb) != nil || !bytes.Equal(pb.Commit, sum[:]) || pb.ID != sess.id || pb.Epoch != req.Epoch {
		refuse("the join proof names another commit, joiner, or epoch")
		return
	}
	// The commit-request, signed with the same code key instead of the epoch key (SPEC §11.6).
	creq, cr, code2 := c.commitRequest(req.Commit, req.Group, req.Epoch, req.Data)
	if code2 != "" {
		writeError(w, http.StatusBadRequest, code2, "commit")
		return
	}
	if !bytes.Equal(creq.K, code.Key) {
		refuse("the commit-request must be signed with the code's key")
		return
	}
	if _, err := creq.VerifyCompositeSelf("commit-request"); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "commit")
		return
	}
	size, ok := c.checkReg(w, ctx, groupReg{Group: req.Group, EpochKey: cr.key, Info: req.Info, Tree: req.Tree})
	if !ok {
		return
	}
	proofEnc, _ := proof.Encode()
	receipt, ecode := c.hubStep(ctx, hubIn{group: req.Group, epoch: req.Epoch, data: req.Data, request: req.Commit, next: cr.key, awaiting: cr.awaiting,
		info: req.Info, tree: req.Tree, treeSize: size, proof: proofEnc,
		join: &store.CJoin{ID: sess.id, Home: sess.home, Dev: sess.dev, Code: code.Hash, Limit: code.Uses, Cap: memberCap}})
	switch ecode {
	case "":
	case wire.ErrCodeNotAllowed:
		refuse("the code is used up, or the community is full")
		return
	default:
		writeError(w, hubStatus(ecode), ecode, "")
		return
	}
	enc, _ := receipt.Encode()
	d := cDelivery{ID: randomID(), Kind: "mls", From: sess.id, Group: req.Group, Epoch: req.Epoch, MLS: "commit", Receipt: enc, Proof: proofEnc, Data: req.Data}
	c.store(ctx, []store.CItem{c.groupItem(d, sess)})
	c.hs.log.Info("community code join", "name", c.name, "id", sess.id)
	writeBody(w, http.StatusOK, map[string]any{"receipt": wire.Raw(enc)})
}

// POST join/request: ask to join a community that needs approval.
func (c *community) joinRequest(w http.ResponseWriter, r *http.Request, sess csess) {
	ctx := r.Context()
	st := c.snapshot()
	if st == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	member, err := c.isMember(ctx, sess.id)
	if err != nil {
		c.hs.unavailableRead(w, "checking membership", err)
		return
	}
	n, err := c.st.MemberCount(ctx, c.name)
	if err != nil {
		c.hs.unavailableRead(w, "counting members", err)
		return
	}
	switch {
	case !st.Approval:
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "this community doesn't need approval: join with a code")
		return
	case member:
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "already a member")
		return
	case n >= memberCap:
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the community is full")
		return
	}
	if _, err := c.st.Request(ctx, c.name, sess.id); err == nil {
		writeBody(w, http.StatusAccepted, map[string]any{}) // pending already: nothing changes
		return
	}
	// A server MAY cap pending requests (spec/api/community.md).
	if pending, err := c.st.CountRequests(ctx, c.name); err != nil || pending >= 1000 {
		rateLimited(w, 3600)
		return
	}
	if err := c.st.PutRequest(ctx, c.name, store.CRequest{ID: sess.id, Home: sess.home, TS: now()}); err != nil {
		c.hs.unavailableRead(w, "storing a join request", err)
		return
	}
	notice, _ := wire.Marshal(map[string]any{"t": "join-request", "id": sess.id})
	var items []store.CItem
	for _, m := range c.membersWith(ctx, st, cchain.Moderate) {
		items = append(items, store.CItem{TS: now(), ToID: m, Notice: notice})
	}
	c.store(ctx, items)
	writeBody(w, http.StatusAccepted, map[string]any{})
}

// membersWith lists the members whose roles grant p.
func (c *community) membersWith(ctx context.Context, st *cchain.State, p cchain.Perms) []string {
	ms, err := c.st.Members(ctx, c.name)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range ms {
		if st.Has(m.ID, p) {
			out = append(out, m.ID)
		}
	}
	return out
}

func (c *community) joinRequests(w http.ResponseWriter, r *http.Request, sess csess) {
	limit := limitParam(r, 100, 500)
	rs, err := c.st.Requests(r.Context(), c.name, r.URL.Query().Get("after"), limit)
	if err != nil {
		c.hs.unavailableRead(w, "listing join requests", err)
		return
	}
	items := make([]map[string]any, len(rs))
	for i, q := range rs {
		items[i] = map[string]any{"id": q.ID, "home": q.Home, "ts": q.TS}
	}
	res := map[string]any{"items": items}
	if len(rs) == limit {
		res["next"] = rs[len(rs)-1].ID
	}
	writeBody(w, http.StatusOK, res)
}

// approvals remembers the key packages each approval claimed, so a retry by the same
// moderator within 10 minutes gets the same ones (spec/api/community.md).
type approvals struct {
	mu sync.Mutex
	m  map[string]approval
}

type approval struct {
	by  string
	at  int64
	res []map[string]any
}

const approvalHold = 600 // seconds

func (c *community) joinApprove(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		ID string `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	q, err := c.st.Request(ctx, c.name, req.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no pending request")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a join request", err)
		return
	}
	if n, err := c.st.MemberCount(ctx, c.name); err != nil || n >= memberCap {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the community is full")
		return
	}
	t := now()
	switch err := c.st.HoldRequest(ctx, c.name, req.ID, sess.id, t, t-approvalHold); {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "another moderator is approving it")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	case err != nil:
		c.hs.unavailableRead(w, "holding a join request", err)
		return
	}
	key := req.ID
	c.approvals.mu.Lock()
	prev, held := c.approvals.m[key]
	c.approvals.mu.Unlock()
	if held && prev.by == sess.id && prev.at > t-approvalHold {
		writeBody(w, http.StatusOK, map[string]any{"packages": prev.res})
		return
	}
	ch, err := c.identityChain(ctx, req.ID, q.Home, false)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "couldn't find the joiner's chain")
		return
	}
	res, err := c.claim(ctx, req.ID, ch, nil)
	if err != nil {
		c.hs.unavailableRead(w, "claiming key packages", err)
		return
	}
	c.approvals.mu.Lock()
	c.approvals.m[key] = approval{by: sess.id, at: t, res: res}
	c.approvals.mu.Unlock()
	writeBody(w, http.StatusOK, map[string]any{"packages": res})
}

// approved reports whether `by` holds an approval of id's request, within 10 minutes.
func (c *community) approved(ctx context.Context, id, by string) (*store.CRequest, bool) {
	q, err := c.st.Request(ctx, c.name, id)
	if err != nil || q.Approver != by || q.ApprovedAt <= now()-approvalHold {
		return nil, false
	}
	return q, true
}

func (c *community) joinDecline(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		ID string `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	switch err := c.st.DeleteRequest(ctx, c.name, req.ID); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	case err != nil:
		c.hs.unavailableRead(w, "declining a join request", err)
		return
	}
	notice, _ := wire.Marshal(map[string]any{"t": "join-declined"})
	c.store(ctx, []store.CItem{{TS: now(), ToID: req.ID, Notice: notice}})
	w.WriteHeader(http.StatusNoContent)
}

// POST leave: the owner hands ownership over first.
func (c *community) leave(w http.ResponseWriter, r *http.Request, sess csess) {
	if st := c.snapshot(); st != nil && st.Owner == sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the owner can't leave before handing ownership over")
		return
	}
	ctx := r.Context()
	if err := c.st.RemoveMember(ctx, c.name, sess.id); err != nil {
		c.hs.unavailableRead(w, "leaving a community", err)
		return
	}
	c.voice.leaveIdentity(sess.id)
	w.WriteHeader(http.StatusNoContent)
}

// POST members/kick, for members with moderate who outrank id (SPEC §16.7).
func (c *community) kick(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		ID string `json:"id"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	st := c.snapshot()
	if req.ID == st.Owner || st.Level(req.ID) >= st.Level(sess.id) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "you don't outrank them")
		return
	}
	ok, err := c.isMember(ctx, req.ID)
	if err != nil {
		c.hs.unavailableRead(w, "checking membership", err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "not a member")
		return
	}
	if err := c.st.RemoveMember(ctx, c.name, req.ID); err != nil {
		c.hs.unavailableRead(w, "kicking a member", err)
		return
	}
	c.removed(ctx, req.ID, "kick")
	w.WriteHeader(http.StatusNoContent)
}

// removed tells a kicked or banned identity, ends its voice visits, and closes its streams
// with 4403 (spec/api/community.md). Its membership is already gone.
func (c *community) removed(ctx context.Context, id, why string) {
	notice, _ := wire.Marshal(map[string]any{"t": "removed", "why": why})
	c.store(ctx, []store.CItem{{TS: now(), ToID: id, Notice: notice}})
	c.voice.leaveIdentity(id)
	// A moment for the notice to go out on the stream before it closes.
	time.AfterFunc(200*time.Millisecond, func() {
		for _, s := range c.streams.of(id) {
			s.close(closeNotAllowed, "removed from the community: "+why)
		}
	})
	c.hs.log.Info("community member removed", "name", c.name, "id", id, "why", why)
}

// parseSeeKey turns a cchain.SeeKey back into its list.
func parseSeeKey(k string) []uint64 {
	var out []uint64
	for _, p := range strings.Split(k, ",") {
		if n, err := strconv.ParseUint(p, 10, 64); err == nil {
			out = append(out, n)
		}
	}
	return out
}
