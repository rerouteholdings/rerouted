package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// ---- deliveries (SPEC §10.1, spec/api/community.md, Messages) ----

// cDelivery is a delivery in a community's groups. Stored without `to`: each recipient's
// copy names only itself (spec/api/community.md), and a channel message's seq is added
// when it's read.
type cDelivery struct {
	ID        wire.Bytes `json:"id"`
	Kind      string     `json:"kind"`
	From      string     `json:"from"`
	To        []string   `json:"to,omitempty"`
	Group     wire.Bytes `json:"group"`
	Epoch     uint64     `json:"epoch"`
	MLS       string     `json:"mls"`
	Receipt   wire.Raw   `json:"receipt,omitempty"`
	Ephemeral bool       `json:"ephemeral,omitempty"`
	Channel   uint64     `json:"channel,omitempty"`
	Seq       uint64     `json:"seq,omitempty"`
	Proof     wire.Raw   `json:"proof,omitempty"`
	Data      wire.Bytes `json:"data"`
}

func randomID() wire.Bytes {
	b := make([]byte, 16)
	rand.Read(b)
	return b
}

// groupItem stores d for every device registered for its group but the sender's.
func (c *community) groupItem(d cDelivery, sess csess) store.CItem {
	b, _ := wire.Marshal(d)
	return store.CItem{TS: now(), Group: d.Group, FromID: sess.id, FromDev: sess.dev, Channel: d.Channel, Delivery: b}
}

// render is an inbox item as a recipient sees it.
func render(it store.CItem, to string) map[string]any {
	m := map[string]any{"ts": it.TS}
	if it.Cursor > 0 {
		m["cursor"] = strconv.FormatInt(it.Cursor, 10)
	}
	if it.Notice != nil {
		m["notice"] = wire.Raw(it.Notice)
		return m
	}
	var d cDelivery
	if wire.Unmarshal(it.Delivery, &d) == nil {
		d.To = []string{to}
		if it.Seq > 0 {
			d.Seq = it.Seq
		}
		b, _ := wire.Marshal(d)
		m["delivery"] = wire.Raw(b)
	}
	return m
}

// store keeps items and pushes them to the streams they're for. A failure is logged: the
// caller already answered for what it accepted.
func (c *community) store(ctx context.Context, items []store.CItem) []store.CItem {
	if len(items) == 0 {
		return nil
	}
	out, err := c.st.Put(ctx, c.name, items)
	if err != nil {
		c.hs.log.Error("storing community items", "err", err)
		return nil
	}
	for _, it := range out {
		c.pushItem(ctx, it)
	}
	return out
}

// pushItem sends a stored or ephemeral item to the open streams it's for.
func (c *community) pushItem(ctx context.Context, it store.CItem) {
	send := func(st *stream) {
		frame, err := wire.Marshal(map[string]any{"t": "item", "item": render(it, st.id)})
		if err != nil {
			return
		}
		cursor := it.Cursor
		if cursor == 0 {
			cursor = -1
		}
		if !st.offer(frame, cursor) {
			st.close(closeGoingAway, "too slow; reconnect and replay")
		}
	}
	switch {
	case it.Group != nil:
		regs, err := c.st.Regs(ctx, it.Group)
		if err != nil {
			return
		}
		for _, reg := range regs {
			if reg.ID == it.FromID && bytes.Equal(reg.Dev, it.FromDev) {
				continue
			}
			for _, st := range c.streams.of(reg.ID) {
				if bytes.Equal(st.device, reg.Dev) {
					send(st)
				}
			}
		}
	case it.ToID != "":
		for _, st := range c.streams.of(it.ToID) {
			if it.ToDev == nil || bytes.Equal(st.device, it.ToDev) {
				send(st)
			}
		}
	case it.Members:
		ms, err := c.st.Members(ctx, c.name)
		if err != nil {
			return
		}
		for _, m := range ms {
			for _, st := range c.streams.of(m.ID) {
				send(st)
			}
		}
	}
}

// ---- POST send ----

type cOutgoing struct {
	ID        wire.Bytes   `json:"id"`
	Kind      string       `json:"kind"`
	Group     wire.Bytes   `json:"group"`
	Epoch     uint64       `json:"epoch"`
	MLS       string       `json:"mls"`
	Channel   uint64       `json:"channel,omitempty"`
	Ephemeral bool         `json:"ephemeral,omitempty"`
	Data      wire.Bytes   `json:"data"`
	Commit    wire.Raw     `json:"commit,omitempty"`
	Info      wire.Bytes   `json:"info,omitempty"`
	Tree      wire.Bytes   `json:"tree,omitempty"`
	Welcomes  []cWelcome   `json:"welcomes,omitempty"`
	To        []string     `json:"to,omitempty"`   // a standalone Welcome (mls "welcome"): who it adds
	Devs      []wire.Bytes `json:"devs,omitempty"` // and the devices it's for
}

type cWelcome struct {
	ID   wire.Bytes   `json:"id"`
	To   []string     `json:"to"`
	Devs []wire.Bytes `json:"devs"`
	Data wire.Bytes   `json:"data"`
}

type cResult struct {
	ID      wire.Bytes `json:"id"`
	Status  string     `json:"status"`
	Error   string     `json:"error,omitempty"`
	Retry   int64      `json:"retry,omitempty"`
	Receipt wire.Raw   `json:"receipt,omitempty"`
	Seq     uint64     `json:"seq,omitempty"`
}

func cReject(id []byte, code string) cResult { return cResult{ID: id, Status: "rejected", Error: code} }

func (c *community) send(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Deliveries []cOutgoing `json:"deliveries"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if len(req.Deliveries) == 0 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "no deliveries")
		return
	}
	results := make([]cResult, len(req.Deliveries))
	for i, o := range req.Deliveries {
		res, err := c.sendIdempotent(r.Context(), sess, o)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
			return
		}
		results[i] = res
	}
	writeBody(w, http.StatusOK, map[string]any{"results": results})
}

// sendIdempotent: a resubmitted ID gets its original result, and isn't delivered or
// numbered twice (spec/api/community.md).
func (c *community) sendIdempotent(ctx context.Context, sess csess, o cOutgoing) (cResult, error) {
	unlock, err := c.sending.lock(ctx, sess.id+"|"+hex.EncodeToString(o.ID))
	if err != nil {
		return cResult{}, err
	}
	defer unlock()
	switch b, err := c.st.SentResult(ctx, c.name, sess.id, o.ID); {
	case err == nil:
		var prev cResult
		if err := wire.Unmarshal(b, &prev); err != nil {
			return cResult{}, err
		}
		return prev, nil
	case !errors.Is(err, store.ErrNotFound):
		return cResult{}, err
	}
	res := c.sendOne(ctx, sess, o)
	if res.Status == "sent" && !o.Ephemeral {
		if b, err := wire.Marshal(res); err == nil {
			c.hs.logged("storing a send result", c.st.PutSentResult(ctx, c.name, sess.id, o.ID, b, now()))
		}
	}
	return res, nil
}

// carrier is the group that carries a channel: the members group for one everyone can see,
// else the group for its see list (SPEC §16.5).
func (c *community) carrier(ctx context.Context, st *cchain.State, ch *cchain.Channel) ([]byte, error) {
	if !st.Restricted(ch) {
		cm, err := c.st.Get(ctx, c.name)
		if err != nil {
			return nil, err
		}
		return cm.Group, nil
	}
	groups, err := c.st.Groups(ctx, c.name)
	if err != nil {
		return nil, err
	}
	key := cchain.SeeKey(ch.See)
	for _, g := range groups {
		if g.See == key {
			return g.Group, nil
		}
	}
	return nil, nil
}

func (c *community) sendOne(ctx context.Context, sess csess, o cOutgoing) cResult {
	switch {
	case o.Kind != "mls" || !mlsKinds[o.MLS]:
		return cReject(o.ID, wire.ErrCodeUnknownKind)
	case len(o.ID) != 16 || len(o.Group) != 32 || len(o.Data) == 0:
		return cReject(o.ID, wire.ErrCodeBadRequest)
	case len(o.Data) > MaxBody:
		return cReject(o.ID, wire.ErrCodeTooLarge)
	case publicMessage(o.Data):
		// Members send everything as PrivateMessage; a code join's external commit goes
		// through POST join (SPEC §10.1).
		return cReject(o.ID, wire.ErrCodeBadRequest)
	}
	st := c.snapshot()
	g, err := c.st.Group(ctx, o.Group)
	if errors.Is(err, store.ErrNotFound) || (err == nil && g.Name != c.name) {
		return cReject(o.ID, wire.ErrCodeNotFound)
	}
	if err != nil {
		return cReject(o.ID, wire.ErrCodeUnavailable)
	}
	// A community that moved away keeps sequencing commits for its hub handoff, and nothing else.
	if c.moved(st) && o.MLS != "commit" {
		return cReject(o.ID, wire.ErrCodeExpired)
	}
	if !c.mayReceive(st, g, sess.id) {
		return cReject(o.ID, wire.ErrCodeNotAllowed)
	}
	d := cDelivery{ID: o.ID, Kind: "mls", From: sess.id, Group: o.Group, Epoch: o.Epoch, MLS: o.MLS, Ephemeral: o.Ephemeral, Data: o.Data}
	switch o.MLS {
	case "commit":
		return c.sendCommit(ctx, sess, st, g, o, d)
	case "welcome":
		return c.sendWelcome(ctx, sess, st, g, o, d)
	}
	res := cResult{ID: o.ID, Status: "sent"}
	numbered := false
	if o.Channel != 0 {
		if o.MLS != "app" {
			return cReject(o.ID, wire.ErrCodeBadRequest)
		}
		ch := st.Channels[o.Channel]
		if ch == nil {
			return cReject(o.ID, wire.ErrCodeNotAllowed)
		}
		carrier, err := c.carrier(ctx, st, ch)
		if err != nil {
			return cReject(o.ID, wire.ErrCodeUnavailable)
		}
		if !bytes.Equal(carrier, o.Group) || st.TimedOut(sess.id, now()) || !st.CanSee(sess.id, ch) {
			return cReject(o.ID, wire.ErrCodeNotAllowed)
		}
		if ch.Kind == "text" {
			if !st.CanWrite(sess.id, ch) {
				return cReject(o.ID, wire.ErrCodeNotAllowed)
			}
			// Slow mode: one message per member every N seconds (SPEC §16.7). Typing
			// indicators don't count.
			if ch.Slow > 0 && !o.Ephemeral {
				key := "cm-slow|" + c.name + "|" + strconv.FormatUint(ch.ID, 10) + "|" + sess.id
				if !c.hs.limits.allow(key, 1, int64(ch.Slow), now(), false) {
					r := cReject(o.ID, wire.ErrCodeRateLimited)
					r.Retry = c.hs.limits.retryAfter(key, int64(ch.Slow), now())
					return r
				}
				c.hs.limits.allow(key, 1, int64(ch.Slow), now(), true)
			}
			numbered = !o.Ephemeral
		}
		d.Channel = o.Channel
	}
	if o.Ephemeral {
		// Typing indicators: to connected devices only, never stored (SPEC §13.3).
		c.pushItem(ctx, c.groupItem(d, sess))
		return res
	}
	it := c.groupItem(d, sess)
	it.Numbered = numbered
	out := c.store(ctx, []store.CItem{it})
	if out == nil {
		return cReject(o.ID, wire.ErrCodeUnavailable)
	}
	res.Seq = out[0].Seq
	return res
}

// welcomeOK checks that a Welcome may add `to`, on devs: members, or a joiner the sender
// holds an approval for (members group only); for a restricted group, only members with a
// role in its see list (spec/api/community.md). Each device is a current device of one of
// them. It returns each device's identity, and the approved joiners.
func (c *community) welcomeOK(ctx context.Context, sess csess, st *cchain.State, g *store.CGroup, to []string, devs []wire.Bytes) (map[string]string, []*store.CRequest, bool) {
	if len(to) == 0 || len(devs) == 0 {
		return nil, nil, false
	}
	owner := map[string]string{}
	var joiners []*store.CRequest
	for _, id := range to {
		home := ""
		if m, err := c.st.Member(ctx, c.name, id); err == nil {
			home = m.Home
		} else if q, ok := c.approved(ctx, id, sess.id); ok && g.See == "" {
			home = q.Home
			joiners = append(joiners, q)
		} else {
			return nil, nil, false
		}
		if st.Banned(id, home) || !c.mayReceive(st, g, id) {
			return nil, nil, false
		}
		ch, err := c.identityChain(ctx, id, home, false)
		if err != nil {
			return nil, nil, false
		}
		for k := range ch.st.Devices {
			owner[k] = id
		}
	}
	devOwner := map[string]string{}
	for _, d := range devs {
		id, ok := owner[hex.EncodeToString(d)]
		if !ok {
			return nil, nil, false
		}
		devOwner[hex.EncodeToString(d)] = id
	}
	return devOwner, joiners, true
}

func (c *community) sendCommit(ctx context.Context, sess csess, st *cchain.State, g *store.CGroup, o cOutgoing, d cDelivery) cResult {
	if o.Commit == nil {
		return cReject(o.ID, wire.ErrCodeBadRequest)
	}
	creq, cr, code := c.commitRequest(o.Commit, o.Group, o.Epoch, o.Data)
	if code != "" {
		return cReject(o.ID, code)
	}
	// A commit to the members group, and any with Welcomes, names its new epoch's tree and
	// GroupInfo, uploaded in the last hour (spec/api/community.md).
	var size int64
	if g.See == "" || len(o.Welcomes) > 0 {
		if len(o.Info) == 0 || len(o.Tree) != 32 {
			return cReject(o.ID, wire.ErrCodeBadRequest)
		}
		var err error
		if size, err = c.st.TreeSize(ctx, c.name, o.Tree); err != nil {
			return cReject(o.ID, wire.ErrCodeBadRequest)
		}
	} else if (o.Info == nil) != (o.Tree == nil) {
		return cReject(o.ID, wire.ErrCodeBadRequest)
	} else if o.Tree != nil {
		var err error
		if size, err = c.st.TreeSize(ctx, c.name, o.Tree); err != nil {
			return cReject(o.ID, wire.ErrCodeBadRequest)
		}
	}
	// Every Welcome is checked before anything is sequenced: one that isn't allowed rejects
	// the commit, and nothing is delivered.
	type welcome struct {
		w       cWelcome
		owners  map[string]string
		joiners []*store.CRequest
	}
	var welcomes []welcome
	for _, wl := range o.Welcomes {
		if len(wl.ID) != 16 || len(wl.Data) == 0 {
			return cReject(o.ID, wire.ErrCodeBadRequest)
		}
		owners, joiners, ok := c.welcomeOK(ctx, sess, st, g, wl.To, wl.Devs)
		if !ok {
			return cReject(o.ID, wire.ErrCodeNotAllowed)
		}
		welcomes = append(welcomes, welcome{wl, owners, joiners})
	}
	var info, tree []byte
	if o.Tree != nil {
		info, tree = o.Info, o.Tree
	}
	receipt, code := c.hubStep(ctx, hubIn{group: o.Group, epoch: o.Epoch, data: o.Data, request: o.Commit, sig: &creq,
		next: cr.key, awaiting: cr.awaiting, info: info, tree: tree, treeSize: size})
	if code != "" {
		return cReject(o.ID, code)
	}
	enc, _ := receipt.Encode()
	d.Receipt = enc
	items := []store.CItem{c.groupItem(d, sess)}
	for _, wl := range welcomes {
		items = append(items, c.welcomeItems(sess, o.Group, o.Epoch+1, wl.w.ID, wl.w.Data, wl.owners)...)
	}
	if c.store(ctx, items) == nil {
		return cReject(o.ID, wire.ErrCodeUnavailable)
	}
	for _, wl := range welcomes {
		c.welcomed(ctx, o.Group, wl.owners, wl.joiners)
	}
	return cResult{ID: o.ID, Status: "sent", Receipt: enc}
}

// welcomeItems are a Welcome's copies, one per device it's for.
func (c *community) welcomeItems(sess csess, group []byte, epoch uint64, id, data []byte, owners map[string]string) []store.CItem {
	b, _ := wire.Marshal(cDelivery{ID: id, Kind: "mls", From: sess.id, Group: group, Epoch: epoch, MLS: "welcome", Data: data})
	var items []store.CItem
	for dev, owner := range owners {
		items = append(items, store.CItem{TS: now(), ToID: owner, ToDev: unhex(dev), Delivery: b})
	}
	return items
}

// welcomed registers a Welcome's devices for its group, and makes approved joiners members
// and closes their requests (spec/api/community.md).
func (c *community) welcomed(ctx context.Context, group []byte, owners map[string]string, joiners []*store.CRequest) {
	for _, q := range joiners {
		c.hs.logged("adding an approved member", c.st.AddMember(ctx, c.name, store.CommunityMember{ID: q.ID, Home: q.Home, Since: now()}))
		c.hs.logged("closing a join request", c.st.DeleteRequest(ctx, c.name, q.ID))
		c.approvals.mu.Lock()
		delete(c.approvals.m, q.ID)
		c.approvals.mu.Unlock()
	}
	for dev, owner := range owners {
		c.hs.logged("registering a welcomed device", c.st.Register(ctx, c.name, group, owner, unhex(dev)))
	}
}

// sendWelcome is a Welcome sent on its own, after a commit too large to carry it (SPEC §11.6).
func (c *community) sendWelcome(ctx context.Context, sess csess, st *cchain.State, g *store.CGroup, o cOutgoing, d cDelivery) cResult {
	owners, joiners, ok := c.welcomeOK(ctx, sess, st, g, o.To, o.Devs)
	if !ok {
		return cReject(o.ID, wire.ErrCodeNotAllowed)
	}
	if c.store(ctx, c.welcomeItems(sess, o.Group, o.Epoch, o.ID, o.Data, owners)) == nil {
		return cReject(o.ID, wire.ErrCodeUnavailable)
	}
	c.welcomed(ctx, o.Group, owners, joiners)
	return cResult{ID: o.ID, Status: "sent"}
}

// ---- GET inbox, POST inbox/ack ----

func cursorParam(v string) (int64, bool) {
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}

func (c *community) inbox(w http.ResponseWriter, r *http.Request, sess csess) {
	after, ok := cursorParam(r.URL.Query().Get("after"))
	if !ok {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "after")
		return
	}
	limit := limitParam(r, 100, 500)
	ctx := r.Context()
	items, err := c.st.List(ctx, c.name, sess.id, sess.dev, after, limit)
	if err != nil {
		c.hs.unavailableRead(w, "reading a community inbox", err)
		return
	}
	pruned, err := c.st.Pruned(ctx, c.name)
	if err != nil {
		c.hs.unavailableRead(w, "reading a community inbox", err)
		return
	}
	out := make([]map[string]any, len(items))
	for i, it := range items {
		out[i] = render(it, sess.id)
	}
	res := map[string]any{"items": out, "gap": after > 0 && after < pruned}
	if len(items) == limit {
		res["next"] = strconv.FormatInt(items[len(items)-1].Cursor, 10)
	}
	writeBody(w, http.StatusOK, res)
}

func (c *community) inboxAck(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Upto string `json:"upto"`
	}
	if !readBody(w, r, &req) {
		return
	}
	n, ok := cursorParam(req.Upto)
	if !ok {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "upto")
		return
	}
	if err := c.st.Ack(r.Context(), c.name, sess.id, sess.dev, n); err != nil {
		c.hs.unavailableRead(w, "acking", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- GET channels/{channel}/messages ----

// channelFor finds a channel the caller can see, writing the error itself.
func (c *community) channelFor(w http.ResponseWriter, st *cchain.State, sess csess, id uint64, kind string) (*cchain.Channel, bool) {
	ch := st.Channels[id]
	if ch == nil || (kind != "" && ch.Kind != kind) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no such channel")
		return nil, false
	}
	if !st.CanSee(sess.id, ch) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "you can't see that channel")
		return nil, false
	}
	return ch, true
}

func (c *community) channelMessages(w http.ResponseWriter, r *http.Request, sess csess) {
	id, err := strconv.ParseUint(r.PathValue("channel"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "channel")
		return
	}
	from, ok := queryUint(r, "from", 1)
	if !ok {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "from")
		return
	}
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "after")
			return
		}
		from = n + 1
	}
	if _, ok := c.channelFor(w, c.snapshot(), sess, id, "text"); !ok {
		return
	}
	limit := limitParam(r, 100, 500)
	items, err := c.st.ChannelItems(r.Context(), c.name, id, from, limit)
	if err != nil {
		c.hs.unavailableRead(w, "reading a channel", err)
		return
	}
	out := make([]map[string]any, len(items))
	for i, it := range items {
		m := map[string]any{"seq": it.Seq}
		if it.Deleted > 0 {
			m["deleted"] = it.Deleted
		} else {
			m["delivery"] = render(it, sess.id)["delivery"]
		}
		out[i] = m
	}
	res := map[string]any{"items": out}
	if len(items) == limit {
		res["next"] = strconv.FormatUint(items[len(items)-1].Seq, 10)
	}
	writeBody(w, http.StatusOK, res)
}

// ---- GET stream ----

func (c *community) stream(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Upgrade(w, r, "tieroute.v2")
	if err != nil {
		return
	}
	ctx := context.WithoutCancel(r.Context())
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	op, msg, err := conn.Read()
	var auth struct {
		T     string `json:"t"`
		Token string `json:"token"`
		After string `json:"after,omitempty"`
	}
	if err != nil {
		conn.Close(closeUnauthenticated, "")
		return
	}
	if op != ws.OpText || wire.Unmarshal(msg, &auth) != nil || auth.T != "auth" {
		conn.Close(closeUnauthenticated, "the first frame must be auth")
		return
	}
	sum := sha256.Sum256([]byte(auth.Token))
	id, home, dev, err := c.st.LookupToken(ctx, c.name, sum[:], now())
	if err != nil {
		conn.Close(closeUnauthenticated, "")
		return
	}
	if st := c.snapshot(); st != nil && st.Banned(id, home) {
		conn.Close(closeNotAllowed, "banned")
		return
	}
	after, ok := cursorParam(auth.After)
	if !ok {
		conn.Close(closeProtocol, "after")
		return
	}
	s := &stream{id: id, device: dev, out: make(chan []byte, 256), conn: conn, done: make(chan struct{}), replaying: true}
	c.streams.add(s)
	defer func() {
		s.close(ws.CloseNormal, "")
		c.streams.remove(s)
		c.voice.leaveDevice(id, dev)
	}()
	go c.hs.streamWriter(s)
	pruned, err := c.st.Pruned(ctx, c.name)
	if err != nil {
		s.close(closeGoingAway, "storage unavailable; reconnect")
		return
	}
	c.hs.sendFrame(s, map[string]any{"t": "ready", "gap": after > 0 && after < pruned})
	last := after
	for {
		items, err := c.st.List(ctx, c.name, id, dev, last, 500)
		if err != nil {
			s.close(closeGoingAway, "storage unavailable; reconnect")
			return
		}
		for _, it := range items {
			c.hs.sendFrame(s, map[string]any{"t": "item", "item": render(it, id)})
			last = it.Cursor
		}
		if len(items) < 500 {
			break
		}
	}
	if !s.endReplay(last) {
		s.close(closeGoingAway, "too slow; reconnect and replay")
		return
	}
	sess := csess{id: id, home: home, dev: dev, tokenHash: sum[:]}
	for {
		conn.SetReadDeadline(time.Now().Add(streamIdleCommunity))
		op, msg, err := conn.Read()
		if err != nil {
			return
		}
		if op != ws.OpText {
			s.close(closeProtocol, "frames are text")
			return
		}
		var f struct {
			T    string          `json:"t"`
			N    json.RawMessage `json:"n"`
			Upto string          `json:"upto"`
		}
		if wire.Unmarshal(msg, &f) != nil {
			s.close(closeProtocol, "frames are JSON objects")
			return
		}
		switch f.T {
		case "ping":
			c.hs.sendFrame(s, map[string]any{"t": "pong", "n": wire.Raw(f.N)})
		case "pong":
		case "ack":
			if n, ok := cursorParam(f.Upto); ok {
				c.hs.logged("acking from a community stream", c.st.Ack(ctx, c.name, id, dev, n))
			}
		case "voice-join", "voice-leave", "voice-sdp", "voice-ice", "voice-cast":
			c.voice.frame(ctx, s, sess, f.T, msg)
		default:
			c.hs.sendFrame(s, map[string]any{"t": "error", "error": wire.ErrCodeUnknownKind, "ref": wire.Raw(msg)})
		}
	}
}
