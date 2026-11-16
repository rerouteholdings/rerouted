package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- key packages (spec/api/community.md, Key packages) ----

// maxCommunityKPs is how many one-time packages a device may keep here.
const maxCommunityKPs = 50

func (c *community) kpUpload(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		Packages []struct {
			KP      wire.Bytes `json:"kp"`
			Binding wire.Raw   `json:"binding"`
		} `json:"packages"`
		LastResort *struct {
			KP      wire.Bytes `json:"kp"`
			Binding wire.Raw   `json:"binding"`
		} `json:"last-resort,omitempty"`
		Replace bool `json:"replace,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	ch, err := c.identityChain(ctx, sess.id, sess.home, false)
	if err != nil || !ch.st.HasDevice(sess.dev) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not a current device")
		return
	}
	pub := ch.st.DevicePub(sess.dev)
	check := func(kp []byte, b wire.Raw) (store.CKeyPackage, string) {
		if len(kp) == 0 || b == nil {
			return store.CKeyPackage{}, wire.ErrCodeBadRequest
		}
		sig, err := wire.DecodeSignedV2(b)
		if err != nil {
			return store.CKeyPackage{}, wire.ErrCodeBadRequest
		}
		if err := wire.VerifyKPBinding(sig, sess.id, pub, kp); err != nil {
			if errors.Is(err, wire.ErrBadSignature) {
				return store.CKeyPackage{}, wire.ErrCodeBadSignature
			}
			return store.CKeyPackage{}, wire.ErrCodeBadRequest
		}
		enc, _ := sig.Encode()
		return store.CKeyPackage{Device: sess.dev, Data: kp, Binding: enc}, ""
	}
	var kps []store.CKeyPackage
	for _, p := range req.Packages {
		k, code := check(p.KP, p.Binding)
		if code != "" {
			writeError(w, http.StatusBadRequest, code, "a key package's binding")
			return
		}
		kps = append(kps, k)
	}
	var lr *store.CKeyPackage
	if req.LastResort != nil {
		k, code := check(req.LastResort.KP, req.LastResort.Binding)
		if code != "" {
			writeError(w, http.StatusBadRequest, code, "the last-resort package's binding")
			return
		}
		lr = &k
	}
	have, _, err := c.st.CountKPs(ctx, c.name, sess.id, sess.dev)
	if err != nil {
		c.hs.unavailableRead(w, "counting key packages", err)
		return
	}
	if req.Replace {
		have = 0
	}
	if have+len(kps) > maxCommunityKPs {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeOverQuota, "at most 50 key packages per device")
		return
	}
	n, err := c.st.UploadKPs(ctx, c.name, sess.id, sess.dev, kps, lr, req.Replace)
	if err != nil {
		c.hs.unavailableRead(w, "storing key packages", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"count": n})
}

func (c *community) kpCount(w http.ResponseWriter, r *http.Request, sess csess) {
	n, lr, err := c.st.CountKPs(r.Context(), c.name, sess.id, sess.dev)
	if err != nil {
		c.hs.unavailableRead(w, "counting key packages", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"count": n, "last-resort": lr})
}

// claim claims one package for each current device of id, or each of devs.
func (c *community) claim(ctx context.Context, id string, ch *chain2, devs [][]byte) ([]map[string]any, error) {
	if devs == nil {
		for k := range ch.st.Devices {
			devs = append(devs, unhex(k))
		}
	}
	kps, err := c.st.ClaimKPs(ctx, c.name, id, devs)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, k := range kps {
		out = append(out, map[string]any{"dev": wire.Bytes(k.Device), "kp": wire.Bytes(k.Data), "binding": wire.Raw(k.Binding), "last-resort": k.LastResort})
	}
	return out, nil
}

func (c *community) kpClaim(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		ID      string       `json:"id"`
		Devices []wire.Bytes `json:"devices,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	m, err := c.st.Member(ctx, c.name, req.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "claims are for members (approvals claim through join/approve)")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "checking membership", err)
		return
	}
	if !c.hs.limits.allow("cm-claim|"+c.name+"|"+sess.id+"|"+req.ID, 50, 24*3600, now(), true) {
		rateLimited(w, 3600)
		return
	}
	ch, err := c.identityChain(ctx, req.ID, m.Home, false)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	var devs [][]byte
	if req.Devices != nil {
		for _, d := range req.Devices {
			if !ch.st.HasDevice(d) {
				writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "not a current device")
				return
			}
			devs = append(devs, d)
		}
	}
	res, err := c.claim(ctx, req.ID, ch, devs)
	if err != nil {
		c.hs.unavailableRead(w, "claiming key packages", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"packages": res})
}

// ---- groups (spec/api/community.md, Groups) ----

// ownGroup finds a group of this community by its base64url ID, writing 404 otherwise.
func (c *community) ownGroup(w http.ResponseWriter, ctx context.Context, group []byte) (*store.CGroup, bool) {
	g, err := c.st.Group(ctx, group)
	if errors.Is(err, store.ErrNotFound) || (err == nil && g.Name != c.name) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no such group here")
		return nil, false
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a group", err)
		return nil, false
	}
	return g, true
}

func (c *community) pathGroup(w http.ResponseWriter, r *http.Request) (*store.CGroup, bool) {
	group, err := base64.RawURLEncoding.DecodeString(r.PathValue("group"))
	if err != nil || len(group) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "group")
		return nil, false
	}
	return c.ownGroup(w, r.Context(), group)
}

// mayReceive: an identity registers for the members group, and for a restricted group
// only with a role in its see list.
func (c *community) mayReceive(st *cchain.State, g *store.CGroup, id string) bool {
	return g.See == "" || seesList(st, id, g.See)
}

func (c *community) groupCreate(w http.ResponseWriter, r *http.Request, sess csess) {
	var req struct {
		groupReg
		See []json.Number `json:"see,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
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
	see := ""
	if req.See == nil {
		// The members group: the owner's, when the server has none, as after a move-in.
		if sess.id != st.Owner {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "only the owner registers the members group")
			return
		}
		if cm, err := c.st.Get(ctx, c.name); err != nil || cm.Group != nil {
			writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "this community has a members group")
			return
		}
	} else {
		if !member || !st.Has(sess.id, cchain.Administrate) {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "needs administrate")
			return
		}
		list := make([]uint64, len(req.See))
		for i, n := range req.See {
			v, err := strconv.ParseUint(string(n), 10, 64)
			if err != nil {
				writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "see")
				return
			}
			list[i] = v
		}
		see = cchain.SeeKey(list)
		carried := false
		for _, ch := range st.Channels {
			if st.Restricted(ch) && cchain.SeeKey(ch.See) == see {
				carried = true
			}
		}
		if !carried {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "no restricted channel has that see list")
			return
		}
		groups, err := c.st.Groups(ctx, c.name)
		if err != nil {
			c.hs.unavailableRead(w, "listing groups", err)
			return
		}
		for _, g := range groups {
			if g.See == see {
				writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "another group carries that see list")
				return
			}
		}
	}
	size, ok := c.checkReg(w, ctx, req.groupReg)
	if !ok {
		return
	}
	g := store.CGroup{Name: c.name, Group: req.Group, See: see, Epoch: req.Epoch, Key: req.EpochKey, Info: req.Info, Tree: req.Tree, TreeSize: size}
	if err := c.st.RegisterGroup(ctx, g); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "")
			return
		}
		c.hs.unavailableRead(w, "registering a group", err)
		return
	}
	c.hs.logged("keeping a group's tree", c.st.UseTree(ctx, c.name, req.Tree, req.Group, req.Epoch, now()+treeKeep))
	// The device that made the group is in it.
	if c.mayReceive(st, &g, sess.id) {
		c.hs.logged("registering a group's creator", c.st.Register(ctx, c.name, req.Group, sess.id, sess.dev))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *community) groupEpochKey(w http.ResponseWriter, r *http.Request, _ csess) {
	var req struct {
		Key wire.Raw `json:"key"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, err := wire.DecodeSignedV2(req.Key)
	if err != nil || sig.T != "epoch-key" {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	reg, err := sig.VerifyCompositeSelf("epoch-key")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var body struct {
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
		Next  wire.Bytes `json:"next"`
	}
	if sig.OpenClosed(&body) != nil || !c.srv.epochKeyOK(body.Next) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	g, ok := c.ownGroup(w, ctx, body.Group)
	if !ok {
		return
	}
	if err := c.st.SetKey(ctx, body.Group, body.Epoch, reg.Bytes(), body.Next); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// A retry of the registration that took effect succeeds (SPEC §11.6).
			if g.Epoch == body.Epoch && !g.Awaiting && bytes.Equal(g.Key, body.Next) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeError(w, http.StatusConflict, wire.ErrCodeStaleEpoch, "")
			return
		}
		c.hs.unavailableRead(w, "registering an epoch key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *community) groupRegister(allow bool) func(http.ResponseWriter, *http.Request, csess) {
	return func(w http.ResponseWriter, r *http.Request, sess csess) {
		var req struct {
			Group wire.Bytes `json:"group"`
		}
		if !readBody(w, r, &req) {
			return
		}
		ctx := r.Context()
		g, ok := c.ownGroup(w, ctx, req.Group)
		if !ok {
			return
		}
		var err error
		if allow {
			member, merr := c.isMember(ctx, sess.id)
			if merr != nil {
				c.hs.unavailableRead(w, "checking membership", merr)
				return
			}
			if !member {
				// After a move-in, the identities on the owner's signed member list join the
				// server's list as they register for the members group (SPEC §16.6).
				listed, lerr := c.st.Listed(ctx, c.name, sess.id)
				if lerr != nil {
					c.hs.unavailableRead(w, "checking the member list", lerr)
					return
				}
				if g.See != "" || !listed {
					writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not a member")
					return
				}
				if err := c.st.AddMember(ctx, c.name, store.CommunityMember{ID: sess.id, Home: sess.home, Since: now()}); err != nil {
					c.hs.unavailableRead(w, "adding a member", err)
					return
				}
			}
			if !c.mayReceive(c.snapshot(), g, sess.id) {
				writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "no role in this group's see list")
				return
			}
			err = c.st.Register(ctx, c.name, req.Group, sess.id, sess.dev)
		} else {
			err = c.st.Unregister(ctx, req.Group, sess.id, sess.dev)
		}
		if err != nil {
			c.hs.unavailableRead(w, "changing a group registration", err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *community) groupCommits(w http.ResponseWriter, r *http.Request, sess csess) {
	g, ok := c.pathGroup(w, r)
	if !ok {
		return
	}
	if !c.mayReceive(c.snapshot(), g, sess.id) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "")
		return
	}
	after := int64(-1)
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < -1 {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "after")
			return
		}
		after = n
	}
	cs, err := c.st.Commits(r.Context(), g.Group, uint64(after+1))
	if err != nil {
		c.hs.unavailableRead(w, "reading commits", err)
		return
	}
	// Commits are kept 30 days: one that's gone can't be fetched (SPEC §11.6).
	if uint64(after+1) < g.Epoch && (len(cs) == 0 || cs[0].Epoch != uint64(after+1)) {
		writeError(w, http.StatusGone, wire.ErrCodeExpired, "")
		return
	}
	items := make([]map[string]any, len(cs))
	for i, cm := range cs {
		items[i] = map[string]any{"epoch": cm.Epoch, "data": wire.Bytes(cm.Data), "receipt": wire.Raw(cm.Receipt)}
		if cm.Proof != nil {
			items[i]["proof"] = wire.Raw(cm.Proof)
		}
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// treeAccess: devices registered for the group, or, for the members group, code access.
func (c *community) treeAccess(w http.ResponseWriter, r *http.Request, sess csess, g *store.CGroup) bool {
	if g.See == "" {
		if _, ok := c.codeAccess(r); ok {
			return true
		}
	}
	ok, err := c.st.Registered(r.Context(), g.Group, sess.id, sess.dev)
	if err != nil {
		c.hs.unavailableRead(w, "checking a registration", err)
		return false
	}
	if !ok {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not registered for this group, and no code access")
	}
	return ok
}

func (c *community) groupInfo(w http.ResponseWriter, r *http.Request, sess csess) {
	g, ok := c.pathGroup(w, r)
	if !ok || !c.treeAccess(w, r, sess, g) {
		return
	}
	// A restricted channel's group may have committed without one (spec/api/community.md):
	// then there's none for this epoch, never an older epoch's (SPEC §16.6).
	if len(g.Info) == 0 {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no GroupInfo for the current epoch")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"epoch": g.Epoch, "info": wire.Bytes(g.Info), "tree": wire.Bytes(g.Tree), "size": g.TreeSize})
}

func (c *community) groupTree(w http.ResponseWriter, r *http.Request, sess csess) {
	g, ok := c.pathGroup(w, r)
	if !ok || !c.treeAccess(w, r, sess, g) {
		return
	}
	epoch, ok := queryUint(r, "epoch", g.Epoch)
	if !ok {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "epoch")
		return
	}
	f, size, err := c.st.TreeFor(r.Context(), g.Group, epoch)
	if errors.Is(err, store.ErrNotFound) {
		if epoch < g.Epoch {
			writeError(w, http.StatusGone, wire.ErrCodeExpired, "no longer kept")
			return
		}
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no tree for that epoch")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "reading a tree", err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	io.Copy(w, f)
}

func (c *community) treeUpload(w http.ResponseWriter, r *http.Request, sess csess) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/octet-stream" {
		writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "use application/octet-stream")
		return
	}
	if r.ContentLength > maxTree {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "at most 32 MiB")
		return
	}
	ctx := r.Context()
	member, err := c.isMember(ctx, sess.id)
	if err != nil {
		c.hs.unavailableRead(w, "checking membership", err)
		return
	}
	// A code joiner uploads its tree before it's a member (spec/api/community.md).
	if !member && !c.hs.limits.allow("cm-tree|"+c.name+"|"+sess.id, 5, 3600, now(), true) {
		rateLimited(w, 3600)
		return
	}
	hash, size, err := c.st.PutTree(ctx, c.name, http.MaxBytesReader(w, r.Body, maxTree+1), maxTree, sess.id, now())
	if errors.Is(err, store.ErrOverQuota) || errors.As(err, new(*http.MaxBytesError)) {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "at most 32 MiB")
		return
	}
	if err != nil {
		c.hs.unavailableRead(w, "storing a tree", err)
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"hash": wire.Bytes(hash), "size": size})
}

// ---- the hub (SPEC §11.6) ----

// crKey is a commit-request's next key, or its one-time reg key.
type crKey struct {
	key      []byte
	awaiting bool
}

// commitRequest decodes a commit-request for group and epoch over data's hash, carrying
// exactly one of next and reg. Its signature is the caller's to check.
func (c *community) commitRequest(raw wire.Raw, group []byte, epoch uint64, data []byte) (wire.Signed, crKey, string) {
	sig, err := wire.DecodeSignedV2(raw)
	if err != nil || sig.T != "commit-request" || len(sig.K) != wire.CompositePublicKeySize {
		return wire.Signed{}, crKey{}, wire.ErrCodeBadRequest
	}
	var cr struct {
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
		Hash  wire.Bytes `json:"hash"`
		Next  wire.Bytes `json:"next,omitempty"`
		Reg   wire.Bytes `json:"reg,omitempty"`
	}
	sum := sha256.Sum256(data)
	if sig.OpenClosed(&cr) != nil || !bytes.Equal(cr.Group, group) || cr.Epoch != epoch || !bytes.Equal(cr.Hash, sum[:]) {
		return wire.Signed{}, crKey{}, wire.ErrCodeBadRequest
	}
	switch {
	case cr.Next != nil && cr.Reg == nil && c.srv.epochKeyOK(cr.Next):
		return sig, crKey{key: cr.Next}, ""
	case cr.Reg != nil && cr.Next == nil && c.srv.epochKeyOK(cr.Reg):
		return sig, crKey{key: cr.Reg, awaiting: true}, ""
	}
	return wire.Signed{}, crKey{}, wire.ErrCodeBadRequest
}

// hubIn is one commit for the hub step.
type hubIn struct {
	group    []byte
	epoch    uint64
	data     []byte
	request  wire.Raw
	sig      *wire.Signed // the commit-request, to check against the epoch key; nil for a code join's
	next     []byte
	awaiting bool
	info     []byte
	tree     []byte
	treeSize int64
	proof    []byte
	join     *store.CJoin
}

// hubStep sequences a commit (SPEC §11.6): the first valid one for its epoch wins, and is
// stored with its new epoch state before the receipt is signed and returned.
func (c *community) hubStep(ctx context.Context, in hubIn) (wire.Signed, string) {
	g, err := c.st.Group(ctx, in.group)
	if err != nil || g.Name != c.name {
		if errors.Is(err, store.ErrNotFound) || err == nil {
			return wire.Signed{}, wire.ErrCodeNotFound
		}
		return wire.Signed{}, wire.ErrCodeUnavailable
	}
	if g.Epoch != in.epoch {
		return c.retried(ctx, in.group, in.epoch, in.request)
	}
	if g.Awaiting {
		return wire.Signed{}, wire.ErrCodeAwaitingKey
	}
	if in.sig != nil && !c.srv.epochSigned(*in.sig, "commit-request", g.Key) {
		return wire.Signed{}, wire.ErrCodeBadSignature
	}
	sum := sha256.Sum256(in.data)
	t := now()
	receipt, err := c.srv.fed.SignKID("commit-receipt", map[string]any{
		"hub": c.name, "group": wire.Bytes(in.group), "epoch": in.epoch, "hash": wire.Bytes(sum[:]), "ts": t,
	})
	if err != nil {
		return wire.Signed{}, wire.ErrCodeUnavailable
	}
	enc, _ := receipt.Encode()
	err = c.st.Accept(ctx, store.CAccept{
		Group: in.group, Epoch: in.epoch, Key: in.next, Awaiting: in.awaiting,
		Commit: store.CCommit{Epoch: in.epoch, Data: in.data, Receipt: enc, Request: in.request, Proof: in.proof, TS: t},
		Info:   in.info, Tree: in.tree, TreeSize: in.treeSize, Join: in.join,
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return c.retried(ctx, in.group, in.epoch, in.request)
	case errors.Is(err, store.ErrOverQuota):
		return wire.Signed{}, wire.ErrCodeNotAllowed
	case err != nil:
		c.hs.log.Error("accepting a commit", "err", err)
		return wire.Signed{}, wire.ErrCodeUnavailable
	}
	return receipt, ""
}

// retried: the very request accepted for that epoch gets its receipt again; anything else
// lost the race (SPEC §11.6).
func (c *community) retried(ctx context.Context, group []byte, epoch uint64, request []byte) (wire.Signed, string) {
	if cs, err := c.st.Commits(ctx, group, epoch); err == nil && len(cs) > 0 && cs[0].Epoch == epoch && bytes.Equal(cs[0].Request, request) {
		sig, err := wire.DecodeSignedV2(cs[0].Receipt)
		if err == nil {
			return sig, ""
		}
	}
	return wire.Signed{}, wire.ErrCodeStaleEpoch
}

// hubStatus is the HTTP status for a hub error code.
func hubStatus(code string) int {
	switch code {
	case wire.ErrCodeStaleEpoch, wire.ErrCodeAwaitingKey, wire.ErrCodeAlreadyExists:
		return http.StatusConflict
	case wire.ErrCodeNotFound:
		return http.StatusNotFound
	case wire.ErrCodeNotAllowed:
		return http.StatusForbidden
	case wire.ErrCodeUnavailable:
		return http.StatusServiceUnavailable
	case wire.ErrCodeRateLimited:
		return http.StatusTooManyRequests
	case wire.ErrCodeTooLarge:
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
