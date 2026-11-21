package api

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- sessions (spec/api/community.md, Sessions) ----

// nonceID keeps this community's sign-in nonces apart from the homeserver's and other
// communities', in the same table.
func (c *community) nonceID(id string) string { return "cm|" + c.name + "|" + id }

func (c *community) authChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string     `json:"id"`
		Key  wire.Bytes `json:"key"`
		Home string     `json:"home"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if !wire.ValidIdentityID(req.ID) || len(req.Key) != 32 || req.Home == "" {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if !c.hs.limits.allow("cm-challenge|"+c.name+"|"+req.ID, 30, 3600, now(), true) {
		rateLimited(w, 120)
		return
	}
	ctx := r.Context()
	// A key it doesn't know means the chain may have changed: ask its home (spec/api/community.md).
	// Every sign-in refreshes the server's copy from home, which members read with GET
	// members/{id}/chain. A key it doesn't know means the chain changed: then the fresh copy
	// is required (spec/api/community.md).
	cached, cerr := c.identityChain(ctx, req.ID, req.Home, false)
	ch, err := c.identityChain(ctx, req.ID, req.Home, true)
	if err != nil && cerr == nil && cached.st.HasDevice(req.Key) && cached.st.Home == req.Home {
		ch, err = cached, nil
	}
	if err != nil {
		var es *fed.ErrStatus
		if errors.As(err, &es) && (es.Status == http.StatusNotFound || es.Status == http.StatusGone) || errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
			return
		}
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "couldn't reach the identity's homeserver")
		return
	}
	if ch.st.Home != req.Home {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "the chain names another homeserver")
		return
	}
	c.revokeRemovedDevices(ctx, req.ID, ch.st)
	if !ch.st.HasDevice(req.Key) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not a current device")
		return
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	t := now()
	if err := c.hs.st.Sessions().PutNonce(ctx, c.nonceID(req.ID), req.Key, nonce, t+60); err != nil {
		c.hs.unavailableRead(w, "storing an auth challenge", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"nonce": wire.Bytes(nonce), "expires": t + 60, "now": t})
}

func (c *community) authSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Auth wire.Raw `json:"auth"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := c.srv.decodeSignedField(w, req.Auth)
	if !ok {
		return
	}
	key, err := c.srv.signer(sig, "auth")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var body struct {
		ID     string     `json:"id"`
		Nonce  wire.Bytes `json:"nonce"`
		Server string     `json:"server"`
		TS     int64      `json:"ts"`
		Name   string     `json:"name,omitempty"`
	}
	if err := sig.Open(&body); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, err.Error())
		return
	}
	if body.Server != c.name {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "signed for a different server")
		return
	}
	if absDiff(body.TS, now()) > chain.MaxSkew {
		c.hs.writeClockSkew(w, body.TS, chain.MaxSkew)
		return
	}
	ctx := r.Context()
	ch, err := c.identityChain(ctx, body.ID, "", false)
	if err != nil || !ch.st.HasDevice(key) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "")
		return
	}
	if !c.srv.deviceSigned(ch.st, sig, "auth", key) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	if st := c.snapshot(); st != nil && st.Banned(body.ID, ch.st.Home) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "banned")
		return
	}
	if err := c.hs.st.Sessions().TakeNonce(ctx, c.nonceID(body.ID), key, body.Nonce, now()); err != nil {
		writeError(w, http.StatusGone, wire.ErrCodeExpired, "nonce unknown, used, or expired")
		return
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(tok))
	exp := time.Now().Add(tokenTTL).Unix()
	if err := c.st.CreateToken(ctx, c.name, sum[:], body.ID, ch.st.Home, key, exp); err != nil {
		c.hs.unavailableRead(w, "creating a session", err)
		return
	}
	member, err := c.isMember(ctx, body.ID)
	if err != nil {
		c.hs.unavailableRead(w, "checking membership", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"token": tok, "expires": exp, "member": member})
}

func (c *community) authLogout(w http.ResponseWriter, r *http.Request, sess csess) {
	if err := c.st.RevokeToken(r.Context(), sess.tokenHash); err != nil {
		c.hs.unavailableRead(w, "signing out", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeRemovedDevices ends the sessions, streams, and voice visits of an identity's devices
// that its chain no longer has (spec/api/community.md: as soon as the server sees it).
func (c *community) revokeRemovedDevices(ctx context.Context, id string, st *chain.State) {
	devs, err := c.st.SessionDevices(ctx, c.name, id, now())
	if err != nil {
		return
	}
	for _, d := range devs {
		if st.HasDevice(d) {
			continue
		}
		c.hs.logged("revoking a removed device's community sessions", c.st.RevokeDevice(ctx, c.name, id, d))
		c.voice.leaveDevice(id, d)
		for _, s := range c.streams.of(id) {
			if bytes.Equal(s.device, d) {
				s.close(closeNotAllowed, "this device was removed")
			}
		}
	}
}

// refreshChains re-fetches the chain of every identity with a live session at least once an
// hour (SPEC §16.2.2, spec/api/community.md), and revokes the devices removed from it.
func (c *community) refreshChains(ctx context.Context) {
	ids, err := c.st.SessionIDs(ctx, c.name, now())
	if err != nil {
		return
	}
	for _, id := range ids {
		if t, ok := c.fetched.Load(id); ok && t.(int64) > now()-chainRefresh {
			continue
		}
		home := ""
		if ch, err := c.identityChain(ctx, id, "", false); err == nil {
			home = ch.st.Home
		}
		if ch, err := c.identityChain(ctx, id, home, true); err == nil {
			c.revokeRemovedDevices(ctx, id, ch.st)
		}
	}
}

// chainRefresh is how often, in seconds, a live session's chain is fetched again.
const chainRefresh = 3600

// ---- signers' keys (SPEC §16.2.2, "Which device keys count") ----

// appendKeys is cchain.Keys for an entry appended now: by must be the session's identity,
// and k a current device of it on a copy of its chain fetched from its home as the append
// arrives, not a cached one (SPEC §16.2.2). A home that can't be reached gets 503, and the
// signer tries again later. A device the fresh copy shows removed loses its sessions.
func (c *community) appendKeys(ctx context.Context, sess csess) cchain.Keys {
	return func(by string, k []byte) (cchain.Signer, error) {
		if by != sess.id {
			return cchain.Signer{}, cchain.ErrNotDevice
		}
		ch, err := c.freshChain(ctx, by, sess.home)
		if err != nil {
			var es *fed.ErrStatus
			if errors.Is(err, store.ErrNotFound) || errors.As(err, &es) && (es.Status == http.StatusNotFound || es.Status == http.StatusGone) {
				return cchain.Signer{}, cchain.ErrNotDevice
			}
			c.hs.log.Info("fetching a signer's chain for a community append", "id", by, "home", sess.home, "err", err)
			return cchain.Signer{}, &cchain.Error{Status: http.StatusServiceUnavailable, Code: wire.ErrCodeUnavailable, Msg: "the signer's homeserver can't be reached: try again later"}
		}
		pub := ch.st.DevicePub(k)
		if pub == nil {
			c.revokeRemovedDevices(ctx, by, ch.st)
			return cchain.Signer{}, cchain.ErrNotDevice
		}
		return cchain.Signer{Pub: pub, Home: ch.st.Home}, nil
	}
}

// freshChain is an identity's chain as its home has it now: the copy in this server's store
// when the identity lives here, under the community's name or the homeserver's, and
// otherwise fetched, never a cached copy.
func (c *community) freshChain(ctx context.Context, id, home string) (*chain2, error) {
	if home == "" || home == c.srv.cfg.Name {
		return c.identityChain(ctx, id, home, false)
	}
	if home == c.hs.cfg.Name {
		st, raw, err := c.hs.identity(ctx, id)
		if err == nil && st.Home == home {
			return &chain2{st, raw}, nil
		}
	}
	st, raw, err := c.srv.fetchRemote(ctx, id, home, true)
	if err != nil {
		return nil, err
	}
	c.fetched.Store(id, now())
	return &chain2{st, raw}, nil
}

// importKeys is cchain.Keys for a whole chain moving in (SPEC §16.2.3 set-home): as a client
// checks, k is any device an add-device in by's chain added, removed since or not. homes
// names where to fetch the chains this server doesn't have.
func (c *community) importKeys(ctx context.Context, homes map[string]string) cchain.Keys {
	return func(by string, k []byte) (cchain.Signer, error) {
		ch, err := c.identityChain(ctx, by, homes[by], false)
		if err != nil && homes[by] != "" {
			ch, err = c.identityChain(ctx, by, homes[by], true)
		}
		if err != nil {
			return cchain.Signer{}, &cchain.Error{Status: http.StatusBadRequest, Code: wire.ErrCodeInvalidChain, Msg: "no chain for " + by + ": name its homeserver in homes"}
		}
		pub := everDevice(ch.raw, k)
		if pub == nil {
			return cchain.Signer{}, cchain.ErrNotDevice
		}
		return cchain.Signer{Pub: pub, Home: ch.st.Home}, nil
	}
}

// everDevice finds the composite key of a device an identity chain ever added.
func everDevice(raw [][]byte, k []byte) *wire.CompositePublicKey {
	var st *chain.State
	for i, b := range raw {
		sig, err := wire.DecodeSignedFor(wire.V2, b)
		if err != nil {
			return nil
		}
		if i == 0 {
			if st, _, err = chain.GenesisFor(wire.V2, sig); err != nil {
				return nil
			}
		} else if _, err := st.Apply(sig); err != nil {
			return nil
		}
		if pub := st.DevicePub(k); pub != nil {
			return pub
		}
	}
	return nil
}

// ---- POST create (spec/api/community.md, Creating and moving a community) ----

// groupReg is a group's registration with the hub: at creation, or a hub handoff.
type groupReg struct {
	Group    wire.Bytes `json:"group"`
	Epoch    uint64     `json:"epoch"`
	EpochKey wire.Bytes `json:"epoch-key"`
	Info     wire.Bytes `json:"info"`
	Tree     wire.Bytes `json:"tree"`
}

// check validates a group registration, writing the error itself, and returns the tree's size.
func (c *community) checkReg(w http.ResponseWriter, ctx context.Context, g groupReg) (int64, bool) {
	if len(g.Group) != 32 || !c.srv.epochKeyOK(g.EpochKey) || len(g.Info) == 0 || len(g.Tree) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "group, epoch-key, info, and tree are required")
		return 0, false
	}
	size, err := c.st.TreeSize(ctx, c.name, g.Tree)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "upload the tree first (POST tree/upload)")
		return 0, false
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a tree", err)
		return 0, false
	}
	return size, true
}

func (c *community) create(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Entry   wire.Raw          `json:"entry,omitempty"`
		Chain   []wire.Raw        `json:"chain,omitempty"`
		Group   *groupReg         `json:"group,omitempty"`
		Code    string            `json:"code,omitempty"`
		Homes   map[string]string `json:"homes,omitempty"`
		Members wire.Raw          `json:"members,omitempty"`
		Seqs    []channelSeq      `json:"seqs,omitempty"`
		Check   bool              `json:"check,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if (req.Entry == nil) == (len(req.Chain) == 0) || (req.Group != nil && req.Entry == nil) || (req.Members == nil) == (req.Entry == nil) || (req.Seqs != nil && req.Entry != nil) || (req.Check && req.Entry != nil) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `exactly one of "entry" and "chain"; "group" goes with "entry", and "members", "seqs", and "check" with "chain"`)
		return
	}
	if req.Check && req.Seqs != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `"seqs" come with the move-in, once the old server has the set-home, not with "check"`)
		return
	}
	// Who may create is the operator's choice: a creation code, or open (spec/api/community.md).
	if code := c.hs.cfg.Now().CommunityCode; code != "" && subtle.ConstantTimeCompare([]byte(req.Code), []byte(code)) != 1 {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "creating a community here needs this server's creation code")
		return
	}
	ctx := r.Context()
	c.appending.Lock()
	defer c.appending.Unlock()
	t := now()
	if req.Entry != nil {
		c.createNew(w, ctx, sess, req.Entry, req.Group, t)
		return
	}
	c.moveIn(w, ctx, sess, req.Chain, req.Homes, req.Members, req.Seqs, req.Check, t)
}

// channelSeq is a text channel's last sequence number, which a community server moved away
// from gives the owner with the set-home's append, and the owner gives the new one with the
// move-in, so numbering goes on (SPEC §16.5, §16.6).
type channelSeq struct {
	Channel uint64 `json:"channel"`
	Seq     uint64 `json:"seq"`
}

// channelSeqs is the response's form of every channel's last sequence number.
func channelSeqs(heads map[uint64]uint64) []channelSeq {
	out := make([]channelSeq, 0, len(heads))
	for ch, seq := range heads {
		out = append(out, channelSeq{ch, seq})
	}
	slices.SortFunc(out, func(a, b channelSeq) int { return cmp.Compare(a.Channel, b.Channel) })
	return out
}

func (c *community) createNew(w http.ResponseWriter, ctx context.Context, sess csess, entry wire.Raw, g *groupReg, t int64) {
	if have := c.snapshot(); have != nil {
		// A retry of the create that made it gets the same answer (SPEC §16.1).
		if enc, err := wire.CanonicalSignedFor(wire.V2, entry); err == nil && len(c.ent) > 0 && bytes.Equal(enc, c.ent[0]) {
			writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(have.ID)})
			return
		}
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "this server already hosts a community")
		return
	}
	st, a, err := cchain.Create(entry, c.name, c.appendKeys(ctx, sess), t, cchain.Append)
	if err != nil {
		c.cerr(w, err)
		return
	}
	if st.Owner != sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the create entry's owner must be you")
		return
	}
	var cg *store.CGroup
	if g != nil {
		size, ok := c.checkReg(w, ctx, *g)
		if !ok {
			return
		}
		if g.Epoch != 0 {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "a new members group starts at epoch 0")
			return
		}
		cg = &store.CGroup{Name: c.name, Group: g.Group, Epoch: 0, Key: g.EpochKey, Info: g.Info, Tree: g.Tree, TreeSize: size}
	}
	err = c.st.Create(ctx, store.Community{Name: c.name, ID: st.ID, Created: t}, [][]byte{a.Enc}, [][]byte{a.Hash},
		store.CommunityMember{ID: sess.id, Home: sess.home, Since: t}, cg)
	switch {
	case errors.Is(err, store.ErrExists), errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	case err != nil:
		c.hs.unavailableRead(w, "creating a community", err)
		return
	}
	if cg != nil {
		c.hs.logged("keeping a members group's tree", c.st.UseTree(ctx, c.name, cg.Tree, cg.Group, 0, t+treeKeep))
		c.hs.logged("registering the owner's device", c.st.Register(ctx, c.name, cg.Group, sess.id, sess.dev))
	}
	c.mu.Lock()
	c.state, c.ent = st, [][]byte{a.Enc}
	c.mu.Unlock()
	c.hs.log.Info("community created", "name", c.name, "id", hex.EncodeToString(st.ID), "owner", sess.id)
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(st.ID)})
}

// treeKeep is how long a tree an epoch used is kept (spec/api/community.md).
const treeKeep = 30 * 24 * 3600

// moveIn takes a community moving here: its whole chain, ending in a set-home naming this
// server, checked entry by entry (SPEC §16.2.3, §16.6). With check, the set-home isn't on
// the old server yet: everything is checked as for the move-in, and instead of storing the
// community, the server holds its name for it and signs a reservation, which the old
// server needs before it records the set-home (SPEC §16.6).
func (c *community) moveIn(w http.ResponseWriter, ctx context.Context, sess csess, raws []wire.Raw, homes map[string]string, membersRaw wire.Raw, seqList []channelSeq, check bool, t int64) {
	keys := c.importKeys(ctx, homes)
	var st *cchain.State
	var last *cchain.Applied
	encs, hashes := make([][]byte, len(raws)), make([][]byte, len(raws))
	for i, raw := range raws {
		var a *cchain.Applied
		var err error
		if i == 0 {
			st, a, err = cchain.Create(raw, "", keys, t, cchain.Import)
		} else {
			st, a, err = st.Apply(raw, keys, t, cchain.Import)
		}
		if err != nil {
			c.cerr(w, err)
			return
		}
		encs[i], hashes[i], last = a.Enc, a.Hash, a
	}
	if have := c.snapshot(); have != nil {
		if !check && bytes.Equal(have.ID, st.ID) && len(c.ent) == len(encs) && slices.EqualFunc(c.ent, encs, bytes.Equal) {
			writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(have.ID)})
			return
		}
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "this server already hosts a community")
		return
	}
	movesHere := false
	for _, op := range last.Ops {
		if op.Op == "set-home" && op.Server == c.name {
			movesHere = true
		}
	}
	if !movesHere || st.Server != c.name {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "the chain's newest entry must be a set-home naming this server")
		return
	}
	if st.Owner != sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "only the owner moves a community")
		return
	}
	listed, ok := c.memberList(w, ctx, sess, st, membersRaw, t)
	if !ok {
		return
	}
	// Where each text channel's numbering goes on from: channels of the chain, each once.
	seqs := make(map[uint64]uint64, len(seqList))
	for _, cs := range seqList {
		ch, ok := st.Channels[cs.Channel]
		if _, dup := seqs[cs.Channel]; !ok || dup || ch.Kind != "text" {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "seqs: text channels of the chain, each once")
			return
		}
		seqs[cs.Channel] = cs.Seq
	}
	if check {
		c.reserve(w, ctx, st, last.Hash, t)
		return
	}
	err := c.st.Create(ctx, store.Community{Name: c.name, ID: st.ID, Created: t, Listed: listed, Seqs: seqs}, encs, hashes, store.CommunityMember{ID: sess.id, Home: sess.home, Since: t}, nil)
	switch {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
		return
	case err != nil:
		c.hs.unavailableRead(w, "moving a community in", err)
		return
	}
	c.mu.Lock()
	c.state, c.ent = st, encs
	c.mu.Unlock()
	c.hs.log.Info("community moved in", "name", c.name, "id", hex.EncodeToString(st.ID), "entries", len(encs))
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(st.ID)})
}

// communityReservation is the body of a community-move-reservation (SPEC §16.6).
type communityReservation struct {
	Community wire.Bytes `json:"community"`
	Server    string     `json:"server"`
	Entry     wire.Bytes `json:"entry"`
	Exp       int64      `json:"exp"`
}

// reserve holds this server's name for a community moving in, and answers with a reservation
// for its set-home entry, signed with this server's key (SPEC §16.6).
// It lasts 10 minutes, and the name is held 30 days after, as for an identity's move
// (reservationTTL, reservationHold).
func (c *community) reserve(w http.ResponseWriter, ctx context.Context, st *cchain.State, entry []byte, t int64) {
	exp := t + reservationTTL
	switch err := c.st.Hold(ctx, c.name, st.ID, exp+reservationHold, t); {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "this server hosts a community, or is held for another one moving in")
		return
	case err != nil:
		c.hs.unavailableRead(w, "holding a name for a move", err)
		return
	}
	signed, err := c.srv.fed.SignKID(typeCommunityReservation, communityReservation{Community: st.ID, Server: c.name, Entry: entry, Exp: exp})
	if err != nil {
		writeError(w, http.StatusInternalServerError, wire.ErrCodeUnavailable, "")
		return
	}
	enc, _ := signed.Encode()
	c.hs.log.Info("community move reserved", "name", c.name, "id", hex.EncodeToString(st.ID))
	writeBody(w, http.StatusOK, map[string]any{"id": wire.Bytes(st.ID), "reservation": wire.Raw(enc)})
}

const typeCommunityReservation = "community-move-reservation"

// checkMoveReservation checks the reservation a set-home naming dest needs, for the entry
// with hash `entry` (SPEC §16.6), with §6.6's answers. It returns an HTTP status, error code,
// and message, or code "" if it's valid.
func (c *community) checkMoveReservation(ctx context.Context, raw wire.Raw, id []byte, dest string, entry []byte) (int, string, string) {
	if raw == nil {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "a set-home needs a reservation from " + dest + ": ask it first (POST create with check)"
	}
	sig, err := wire.DecodeSignedV2(raw)
	if err != nil {
		return http.StatusBadRequest, wire.ErrCodeBadRequest, "reservation: " + err.Error()
	}
	_, ok := sig.KeyID()
	var body communityReservation
	if sig.T != typeCommunityReservation || !ok || sig.OpenClosed(&body) != nil {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "that isn't a community move reservation"
	}
	if !bytes.Equal(body.Community, id) || body.Server != dest || !bytes.Equal(body.Entry, entry) {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "the reservation is for another community, server, or entry"
	}
	if body.Exp < now() {
		return http.StatusForbidden, wire.ErrCodeNotAllowed, "the reservation has expired: ask " + dest + " again"
	}
	if _, err := c.srv.fed.ServerDoc(ctx, dest); err != nil {
		return http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "couldn't reach " + dest + " to check its reservation"
	}
	if c.srv.fed.VerifyServerSigned(ctx, dest, sig, typeCommunityReservation, now()) != nil {
		return http.StatusBadRequest, wire.ErrCodeBadSignature, "the reservation isn't signed by " + dest
	}
	return 0, "", ""
}

// maxListed is the most identities a member list can name: the member cap (SPEC §16.1).
const maxListed = memberCap

// memberList checks a move-in's community-members (SPEC §16.6): signed by a current device
// of the owner, for this community, at most 10 minutes from the server's clock, naming each
// identity once. It writes the error itself.
func (c *community) memberList(w http.ResponseWriter, ctx context.Context, sess csess, st *cchain.State, raw wire.Raw, t int64) ([]string, bool) {
	sig, err := wire.DecodeSignedV2(raw)
	if err != nil || sig.T != "community-members" || len(sig.K) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "members must be a community-members signed by the owner's device")
		return nil, false
	}
	var body struct {
		Community wire.Bytes `json:"community"`
		Members   []string   `json:"members"`
		TS        int64      `json:"ts"`
	}
	if sig.OpenClosed(&body) != nil || !bytes.Equal(body.Community, st.ID) || len(body.Members) > maxListed {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "members: a list for this community, of at most 1,000 identities")
		return nil, false
	}
	seen := map[string]bool{}
	for _, id := range body.Members {
		if !wire.ValidIdentityID(id) || seen[id] {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "members: identifiers, each once")
			return nil, false
		}
		seen[id] = true
	}
	if absDiff(body.TS, t) > cchain.ClockSkew {
		c.hs.writeClockSkew(w, body.TS, cchain.ClockSkew)
		return nil, false
	}
	signer, err := c.appendKeys(ctx, sess)(st.Owner, sig.K)
	if err != nil {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "members must be signed by a current device of the owner")
		return nil, false
	}
	if sig.VerifyComposite("community-members", signer.Pub) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "members")
		return nil, false
	}
	return body.Members, true
}

// ---- GET chain, POST chain/append (spec/api/community.md, The community chain) ----

func (c *community) chainRead(w http.ResponseWriter, r *http.Request) {
	st := c.snapshot()
	if st == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "this server hosts no community yet")
		return
	}
	// Members, or code access. A community that moved away keeps serving its chain, ending in
	// the set-home, to its members (spec/api/community.md).
	if _, ok := c.codeAccess(r); !ok {
		var allowed bool
		c.authed(func(w http.ResponseWriter, r *http.Request, sess csess) {
			ok, err := c.isMember(r.Context(), sess.id)
			if err != nil {
				c.hs.unavailableRead(w, "checking membership", err)
				return
			}
			if !ok {
				writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "neither a member nor valid code access")
				return
			}
			allowed = true
		}, movedOK)(w, r)
		if !allowed {
			return
		}
	} else if _, ok := c.authedID(r); !ok {
		writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "")
		return
	}
	after := int64(-1)
	if v := r.URL.Query().Get("after"); v != "" {
		n, ok := queryUint(r, "after", 0)
		if !ok {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "after")
			return
		}
		after = int64(n)
	}
	c.mu.RLock()
	ent := c.ent
	c.mu.RUnlock()
	items := []wire.Raw{}
	for i := after + 1; i >= 0 && i < int64(len(ent)); i++ {
		items = append(items, ent[i])
	}
	writeBody(w, http.StatusOK, map[string]any{"entries": items, "head": st.Seq})
}

// membersList is GET members: the server's membership list, with each member's home, for
// re-creating the community's groups (SPEC §16.5). The route allows the owner and
// members with administrate.
func (c *community) membersList(w http.ResponseWriter, r *http.Request, _ csess) {
	ms, err := c.st.Members(r.Context(), c.name)
	if err != nil {
		c.hs.unavailableRead(w, "listing members", err)
		return
	}
	items := make([]map[string]any, len(ms))
	for i, m := range ms {
		items[i] = map[string]any{"id": m.ID, "home": m.Home}
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// GET members/{id}/chain: the community server's copy of a member's identity chain, as it
// last fetched it, for members and code access. Members can't otherwise find the chains of
// signers and joiners on homeservers they don't know. The chain is self-certifying; a client
// that needs a newer copy asks the home its set-home names, through its own homeserver.
func (c *community) memberChain(w http.ResponseWriter, r *http.Request, sess csess) {
	ctx := r.Context()
	if _, ok := c.codeAccess(r); !ok {
		ok, err := c.isMember(ctx, sess.id)
		if err != nil {
			c.hs.unavailableRead(w, "checking membership", err)
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "neither a member nor valid code access")
			return
		}
	}
	id := r.PathValue("id")
	// Members, former members, and the community chain's signers: a member catching up
	// late checks joins and entries by people who have since gone (SPEC §16.1). Never an
	// identity that wasn't a member.
	m, err := c.st.Member(ctx, c.name, id)
	if errors.Is(err, store.ErrNotFound) {
		m, err = c.st.FormerMember(ctx, c.name, id)
	}
	if errors.Is(err, store.ErrNotFound) && c.signedChain(id) {
		m, err = &store.CommunityMember{ID: id}, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "never a member")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a member", err)
		return
	}
	ch, err := c.identityChain(ctx, id, m.Home, false)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "no copy of that chain, and its homeserver couldn't be reached")
		return
	}
	entries := make([]wire.Raw, len(ch.raw))
	for i, e := range ch.raw {
		entries[i] = e
	}
	writeBody(w, http.StatusOK, map[string]any{"entries": entries, "head": len(ch.raw) - 1})
}

// signedChain reports whether id signed an entry of the community chain.
func (c *community) signedChain(id string) bool {
	c.mu.RLock()
	ent := c.ent
	c.mu.RUnlock()
	for _, e := range ent {
		sig, err := wire.DecodeSignedV2(e)
		if err != nil {
			continue
		}
		var b struct {
			By string `json:"by"`
		}
		if sig.Open(&b) == nil && b.By == id {
			return true
		}
	}
	return false
}

// authedID is the session's identity, for an endpoint that also takes code access.
func (c *community) authedID(r *http.Request) (string, bool) {
	tok, ok := bytesCutBearer(r)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256([]byte(tok))
	id, home, _, err := c.st.LookupToken(r.Context(), c.name, sum[:], now())
	if err != nil {
		return "", false
	}
	if st := c.snapshot(); st != nil && st.Banned(id, home) {
		return "", false
	}
	return id, true
}

func bytesCutBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) <= len(p) || h[:len(p)] != p {
		return "", false
	}
	return h[len(p):], true
}

func (c *community) chainAppend(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Entry       wire.Raw `json:"entry"`
		Reservation wire.Raw `json:"reservation,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Entry == nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "entry")
		return
	}
	ctx := r.Context()
	st := c.snapshot()
	if st == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	// Idempotent: the entry that's already the head gets the same answer, the set-home's
	// seqs included, for an owner whose first answer was lost.
	if enc, err := wire.CanonicalSignedFor(wire.V2, req.Entry); err == nil {
		c.mu.RLock()
		head := c.ent[len(c.ent)-1]
		c.mu.RUnlock()
		if bytes.Equal(enc, head) {
			c.appended(w, ctx, st)
			return
		}
	}
	// After a set-home, the server the chain no longer names refuses appends (SPEC §16.2.3).
	if c.moved(st) {
		writeError(w, http.StatusConflict, wire.ErrCodeWrongHome, "this community moved to "+st.Server)
		return
	}
	// Anyone who can sign in could make the chain grow (SPEC §16.2.2).
	if !c.hs.limits.allow("cm-append|"+c.name+"|"+sess.id, 120, 3600, now(), true) {
		rateLimited(w, 60)
		return
	}
	c.appending.Lock()
	defer c.appending.Unlock()
	st = c.snapshot()
	if c.moved(st) {
		writeError(w, http.StatusConflict, wire.ErrCodeWrongHome, "this community moved to "+st.Server)
		return
	}
	next, a, err := st.Apply(req.Entry, c.appendKeys(ctx, sess), now(), cchain.Append)
	if err != nil {
		c.cerr(w, err)
		return
	}
	// A set-home naming another server needs that server's reservation (SPEC §16.6), and
	// from the moment it's stored, this server numbers no more messages (seqGate).
	if c.moved(next) {
		if status, code, msg := c.checkMoveReservation(ctx, req.Reservation, st.ID, next.Server, a.Hash); code != "" {
			writeError(w, status, code, msg)
			return
		}
		c.seqGate.Lock()
		defer c.seqGate.Unlock()
	}
	members, err := c.st.Members(ctx, c.name)
	if err != nil {
		c.hs.unavailableRead(w, "listing members", err)
		return
	}
	// A ban is a kick too: of the banned identity, and of every member a domain ban covers
	// but the owner (spec/api/community.md).
	var removed []string
	for _, m := range members {
		if !st.Banned(m.ID, m.Home) && next.Banned(m.ID, m.Home) && m.ID != next.Owner {
			removed = append(removed, m.ID)
		}
	}
	if err := c.st.Append(ctx, c.name, a.Seq, a.Enc, a.Hash, removed); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, wire.ErrCodeStaleHead, "")
			return
		}
		c.hs.unavailableRead(w, "appending to a community chain", err)
		return
	}
	c.mu.Lock()
	c.state, c.ent = next, append(slices.Clip(c.ent), a.Enc)
	c.mu.Unlock()
	c.afterAppend(ctx, st, next, a, removed)
	c.appended(w, ctx, next)
}

// appended answers an append with the new head; after a set-home, with every text channel's
// last sequence number too, for the owner to give the new community server (SPEC §16.6).
// Sends are refused from the set-home on, so the numbers are final.
func (c *community) appended(w http.ResponseWriter, ctx context.Context, st *cchain.State) {
	res := map[string]any{"seq": st.Seq, "head": wire.Bytes(st.Head)}
	if c.moved(st) {
		heads, err := c.st.ChannelHeads(ctx, c.name)
		if err != nil {
			c.hs.unavailableRead(w, "reading channel sequence numbers", err)
			return
		}
		for ch := range heads {
			if c, ok := st.Channels[ch]; !ok || c.Kind != "text" {
				delete(heads, ch)
			}
		}
		res["seqs"] = channelSeqs(heads)
	}
	writeBody(w, http.StatusOK, res)
}

// afterAppend does what the server does after an append (spec/api/community.md): tells every
// member, applies a ban's kick, stops delivering restricted groups to identities that lost
// their role in its see list, deletes a removed channel's history, and updates voice.
func (c *community) afterAppend(ctx context.Context, before, st *cchain.State, a *cchain.Applied, removed []string) {
	for _, id := range removed {
		c.removed(ctx, id, "ban")
	}
	notice, _ := wire.Marshal(map[string]any{"t": "community-chain", "seq": a.Seq, "head": wire.Bytes(a.Hash)})
	c.store(ctx, []store.CItem{{TS: now(), Members: true, Notice: notice}})
	for _, op := range a.Ops {
		if op.Op == "remove-channel" {
			c.hs.logged("deleting a removed channel's history", c.st.DeleteSegments(ctx, c.name, op.ID))
			c.hs.logged("deleting a removed channel's read positions", c.st.DeleteChannelReads(ctx, c.name, op.ID))
			c.voice.closeChannel(op.ID)
		}
	}
	c.prune(ctx, st)
	c.voice.regate(st)
}

// prune stops delivering each restricted channel's group to identities without a role in
// its see list (spec/api/community.md, after assign-roles, edit-channel, remove-channel).
func (c *community) prune(ctx context.Context, st *cchain.State) {
	groups, err := c.st.Groups(ctx, c.name)
	if err != nil {
		return
	}
	for _, g := range groups {
		if g.See == "" {
			continue
		}
		regs, err := c.st.Regs(ctx, g.Group)
		if err != nil {
			continue
		}
		done := map[string]bool{}
		for _, reg := range regs {
			if done[reg.ID] || seesList(st, reg.ID, g.See) {
				continue
			}
			done[reg.ID] = true
			c.hs.logged("unregistering an identity from a restricted group", c.st.UnregisterIdentity(ctx, g.Group, reg.ID))
		}
	}
}

// seesList reports whether id holds a role in a see list (cchain.SeeKey form).
func seesList(st *cchain.State, id, see string) bool {
	return st.CanSee(id, &cchain.Channel{See: parseSeeKey(see)})
}
