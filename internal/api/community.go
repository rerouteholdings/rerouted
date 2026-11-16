package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/sfu"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Community servers (SPEC §16, spec/api/community.md). rerouted serves any number of server
// names as community servers, each hosting exactly one community (SPEC §16.1), beside its
// homeserver. Each name answers as its own server: its own server document listing the
// "community" role, its own composite server key (community-key-<name>.json), and its own
// API base. A name equal to REROUTED_NAME is also the homeserver, with both roles in one
// document. Requests reach a community by their Host header, or, in dev mode, by a listener
// of its own (CommunityListeners).
//
// The community server speaks only wire version 2. It is the hub for its community's groups
// and their only delivery point: devices sign in to it directly and keep a stream open to it
// (SPEC §16.1). It never processes MLS. What it enforces it reads from the community chain,
// whose structure is readable to it (internal/cchain).

// memberCap is the most members a community can have (SPEC §16.1).
const memberCap = 1000

// community is one community server name.
type community struct {
	name string
	conf config.Community
	key  serverkey.CompositeKey
	// srv is a wire version 2 Server answering as this name: its Fed signs S2S requests as
	// this name with this name's key, and it finds and caches identity chains (SPEC §6.5).
	srv *Server
	hs  *Server // the homeserver's version 2 Server: config, limits, log
	st  store.Communities
	mux *http.ServeMux // for a name that's only a community server

	mu      sync.RWMutex
	state   *cchain.State // nil until the community exists here
	ent     [][]byte      // the stored chain's entries, for idempotent appends
	loadErr error

	appending sync.Mutex // one chain append at a time
	// seqGate: a set-home's append holds it, and sends other than commits share it, so no
	// message is numbered after the seqs the set-home answers with (SPEC §16.6).
	seqGate   sync.RWMutex
	sending   keyLocks // one send per sender and delivery ID
	streams   streams
	approvals approvals
	voice     *voiceRooms
	fetched   sync.Map // identity -> unix time its chain was last fetched
}

// communities is every community name this process serves.
type communities struct {
	byName map[string]*community
	sfu    *sfu.SFU
}

// initCommunities makes the community servers configured, on the version 1 Server s.
func (s *Server) initCommunities() {
	s.comm = &communities{byName: map[string]*community{}}
	if len(s.cfg.Communities) == 0 {
		return
	}
	gone := func(room, key string) {
		name, _, _ := strings.Cut(room, "|")
		if c := s.comm.byName[name]; c != nil {
			c.voice.gone(key)
		}
	}
	v, err := sfu.New(sfu.Config{UDPPort: s.cfg.VoiceUDPPort, PublicIPs: s.cfg.VoicePublicIPs, Loopback: s.cfg.Dev, OnGone: gone, Log: s.log.With("sfu", true)})
	if err != nil {
		s.log.Error("voice channels are off: the SFU didn't start", "err", err)
	}
	s.comm.sfu = v
	for _, cm := range s.cfg.Communities {
		c := &community{name: cm.Name, conf: cm, hs: s.v2, st: s.st.Communities()}
		if cm.Name == s.cfg.Name {
			c.key, c.srv = s.key.V2, s.v2
		} else {
			key, err := serverkey.LoadOrCreateComposite(s.cfg.DataDir, "community-key-"+cm.Name+".json")
			if err != nil {
				s.log.Error("community key", "name", cm.Name, "err", err)
				continue
			}
			c.key = key
			cfg := *s.cfg
			cfg.Name = cm.Name
			k := s.key
			k.V2 = key
			c.srv = newServer(&cfg, k, s.log.With("community", cm.Name), s.st.ForWire(wire.V2), wire.V2, s.limits)
			c.srv.v1 = s
			c.srv.fed.UseNonce = s.st.Sessions().UseNonce
			c.mux = http.NewServeMux()
		}
		c.voice = newVoiceRooms(c, v)
		c.streams = streams{m: map[string]map[*stream]bool{}}
		c.approvals = approvals{m: map[string]approval{}}
		s.comm.byName[cm.Name] = c
		if c.mux != nil {
			c.mux.HandleFunc("GET /.well-known/tieroute/server", c.serverDoc)
			c.routes(c.mux)
			c.mux.HandleFunc(s.cfg.APIPathV2+"s2s/", notImplemented) // SPEC §5.1 needs the base listed
			c.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no such endpoint")
			})
		} else {
			c.routes(s.mux)
		}
		c.load(context.Background())
	}
}

// load reads the community's chain from storage and replays it.
func (c *community) load(ctx context.Context) {
	raw, err := c.st.Entries(ctx, c.name, -1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadErr = err
	if err != nil || len(raw) == 0 {
		c.state, c.ent = nil, nil
		return
	}
	st, err := cchain.ReplayChain(raw, c.name, nil, now(), cchain.Replay)
	if err != nil {
		c.hs.log.Error("a stored community chain doesn't replay", "name", c.name, "err", err)
		c.loadErr = err
		return
	}
	c.state, c.ent = st, raw
}

// snapshot is the community's current state, or nil. States are never changed in place.
func (c *community) snapshot() *cchain.State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// moved: the chain names another community server now (SPEC §16.2.3 set-home).
func (c *community) moved(st *cchain.State) bool { return st != nil && st.Server != c.name }

// hostName is a request's Host without its port, lowercased.
func hostName(r *http.Request) string {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// dispatch sends requests for a community-only name to its own mux.
func (s *Server) dispatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := s.comm.byName[hostName(r)]; c != nil && c.mux != nil {
			c.mux.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CommunityListener is a community name served on an address of its own (dev mode).
type CommunityListener struct {
	Name, Addr string
	Handler    http.Handler
}

// CommunityListeners lists, in dev mode, the communities whose URL has a host:port other than
// the homeserver's, so each can be reached on its own listener without a Host header.
func (s *Server) CommunityListeners() []CommunityListener {
	var out []CommunityListener
	if !s.cfg.Dev {
		return out
	}
	for _, cm := range s.cfg.Communities {
		c := s.comm.byName[cm.Name]
		if c == nil || c.mux == nil {
			continue
		}
		addr := strings.TrimPrefix(strings.TrimPrefix(cm.URL, "http://"), "https://")
		if addr == "" || addr == strings.TrimPrefix(strings.TrimPrefix(s.cfg.PublicURL, "http://"), "https://") || !strings.Contains(addr, ":") {
			continue
		}
		out = append(out, CommunityListener{Name: cm.Name, Addr: addr, Handler: s.cors(c.mux)})
	}
	return out
}

// communityDoc is the community part of a server document's version 2 entry.
func (c *community) keyDoc() serverKeyDoc {
	return serverKeyDoc{KID: c.key.KID, Pub: wire.Bytes(c.key.Priv.Public().Bytes()), NBF: c.key.Created.Unix(), EXP: c.key.Created.Add(serverkey.Lifetime).Unix()}
}

// serverDoc is the server document of a name that's only a community server (SPEC §5.1).
func (c *community) serverDoc(w http.ResponseWriter, r *http.Request) {
	cfg := c.hs.cfg
	doc := serverDoc{
		Name:  c.name,
		Roles: []string{"community"},
		APIs:  []apiBase{{V: wire.V2, S2S: cfg.CommunityS2SBase(c.conf), Community: cfg.CommunityBase(c.conf)}},
		Keys:  []serverKeyDoc{c.keyDoc()},
	}
	w.Header().Set("Cache-Control", "max-age=3600")
	writeBody(w, http.StatusOK, doc)
}

// routes routes the community API (spec/api/community.md) under its base.
func (c *community) routes(mux *http.ServeMux) {
	base := c.hs.cfg.APIPathV2 + "community/"
	for path, h := range map[string]http.HandlerFunc{
		"GET preview":                     c.preview,
		"GET icon/{hash}":                 c.iconGet,
		"POST icon/upload":                c.authed(c.perm(cchain.Administrate, c.iconUpload)),
		"POST auth/challenge":             c.open(c.authChallenge),
		"POST auth/session":               c.open(c.authSession),
		"POST auth/logout":                c.authed(c.authLogout, movedOK),
		"POST create":                     c.authed(c.create, movedOK),
		"POST join":                       c.authed(c.join),
		"POST join/request":               c.authed(c.joinRequest),
		"GET join/requests":               c.authed(c.perm(cchain.Moderate, c.joinRequests)),
		"POST join/approve":               c.authed(c.perm(cchain.Moderate, c.joinApprove)),
		"POST join/decline":               c.authed(c.perm(cchain.Moderate, c.joinDecline)),
		"POST leave":                      c.authed(c.member(c.leave)),
		"GET chain":                       c.chainRead,
		"GET members":                     c.authed(c.perm(cchain.Administrate, c.membersList)),
		"GET members/{id}/chain":          c.authed(c.memberChain),
		"POST chain/append":               c.authed(c.member(c.chainAppend), movedOK),
		"POST keypackages/upload":         c.authed(c.kpUpload),
		"GET keypackages/count":           c.authed(c.kpCount),
		"POST keypackages/claim":          c.authed(c.member(c.kpClaim)),
		"POST groups/create":              c.authed(c.groupCreate),
		"POST groups/epoch-key":           c.authed(c.groupEpochKey, movedOK),
		"POST groups/register":            c.authed(c.groupRegister(true)),
		"POST groups/unregister":          c.authed(c.groupRegister(false), movedOK),
		"GET groups/{group}/commits":      c.authed(c.member(c.groupCommits), movedOK),
		"GET groups/{group}/info":         c.authed(c.groupInfo, movedOK),
		"GET groups/{group}/tree":         c.authed(c.groupTree, movedOK),
		"POST tree/upload":                c.authed(c.treeUpload, movedOK),
		"POST send":                       c.authed(c.member(c.send), movedOK),
		"GET inbox":                       c.authed(c.inbox, movedOK),
		"POST inbox/ack":                  c.authed(c.inboxAck, movedOK),
		"GET stream":                      c.stream,
		"GET channels/{channel}/messages": c.authed(c.member(c.channelMessages)),
		"POST history/put":                c.authed(c.member(c.historyPut)),
		"GET history/list":                c.authed(c.member(c.historyList)),
		"GET history/get":                 c.authed(c.member(c.historyGet)),
		"POST media/upload":               c.authed(c.member(c.mediaUpload)),
		"GET media/{id}":                  c.authed(c.member(c.mediaGet)),
		"POST voice/move":                 c.authed(c.perm(cchain.Moderate, c.voiceMove)),
		"POST messages/delete":            c.authed(c.member(c.messagesDelete)),
		"POST members/kick":               c.authed(c.perm(cchain.Moderate, c.kick)),
		"POST read":                       c.authed(c.member(c.readPut)),
		"GET read":                        c.authed(c.member(c.readGet)),
		"POST report":                     c.authed(c.member(c.report)),
		"GET reports":                     c.authed(c.perm(cchain.Moderate, c.reports)),
		"POST reports/close":              c.authed(c.perm(cchain.Moderate, c.reportClose)),
	} {
		method, p, _ := strings.Cut(path, " ")
		mux.Handle(method+" "+base+p, c.bodyIn(base, h))
	}
}

// Bodies over 1 MiB: files and trees are raw bytes and check their own type and size, and a
// history segment is up to 2 MiB of JSON (spec/api/community.md).
const (
	maxTree          = 32 << 20
	maxHistoryBody   = 2 << 20
	maxSegmentCT     = 1<<20 + 28
	maxCommunityFile = 64<<20 + 16
)

// bodyIn is jsonIn for the community API.
func (c *community) bodyIn(base string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			switch r.URL.Path {
			case base + "media/upload", base + "tree/upload", base + "icon/upload":
			default:
				if mt := r.Header.Get("Content-Type"); !strings.HasPrefix(mt, wire.MediaType) {
					writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "use "+wire.MediaType)
					return
				}
				limit := int64(MaxBody)
				if r.URL.Path == base+"history/put" {
					limit = maxHistoryBody
				}
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// csess is the caller of a community API request.
type csess struct {
	id, home  string
	dev       []byte
	tokenHash []byte
}

const movedOK = true

// open wraps an endpoint that needs no session: a community that moved away answers 410.
func (c *community) open(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.moved(c.snapshot()) && !strings.HasSuffix(r.URL.Path, "/auth/challenge") && !strings.HasSuffix(r.URL.Path, "/auth/session") {
			writeError(w, http.StatusGone, wire.ErrCodeExpired, "this community moved")
			return
		}
		h(w, r)
	}
}

// authed wraps an endpoint that needs a session, for an identity that isn't banned. With
// movedOK it also serves a community that moved away, for the 30 days its hub keeps
// sequencing (spec/api/community.md); everything else there answers 410 expired.
func (c *community) authed(h func(http.ResponseWriter, *http.Request, csess), allowMoved ...bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := c.snapshot()
		if c.moved(st) && len(allowMoved) == 0 {
			writeError(w, http.StatusGone, wire.ErrCodeExpired, "this community moved to "+st.Server)
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "missing bearer token")
			return
		}
		sum := sha256.Sum256([]byte(tok))
		id, home, dev, err := c.st.LookupToken(r.Context(), c.name, sum[:], now())
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				c.hs.unavailableRead(w, "looking up a community session", err)
				return
			}
			writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "")
			return
		}
		if st != nil && st.Banned(id, home) {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "banned")
			return
		}
		h(w, r, csess{id: id, home: home, dev: dev, tokenHash: sum[:]})
	}
}

// member wraps an endpoint for current members (spec/api/community.md).
func (c *community) member(h func(http.ResponseWriter, *http.Request, csess)) func(http.ResponseWriter, *http.Request, csess) {
	return func(w http.ResponseWriter, r *http.Request, sess csess) {
		ok, err := c.isMember(r.Context(), sess.id)
		if err != nil {
			c.hs.unavailableRead(w, "checking membership", err)
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "not a member")
			return
		}
		h(w, r, sess)
	}
}

// perm wraps an endpoint for members whose roles grant p.
func (c *community) perm(p cchain.Perms, h func(http.ResponseWriter, *http.Request, csess)) func(http.ResponseWriter, *http.Request, csess) {
	return c.member(func(w http.ResponseWriter, r *http.Request, sess csess) {
		if st := c.snapshot(); st == nil || !st.Has(sess.id, p) {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "needs a permission your roles don't grant")
			return
		}
		h(w, r, sess)
	})
}

func (c *community) isMember(ctx context.Context, id string) (bool, error) {
	_, err := c.st.Member(ctx, c.name, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// codeAccess checks `code` in the query: the hash of a live add-code's key, with uses left,
// whose creator is still a member (spec/api/community.md, Code access; SPEC §16.2.3).
func (c *community) codeAccess(r *http.Request) (*cchain.Code, bool) {
	q := r.URL.Query().Get("code")
	if q == "" {
		return nil, false
	}
	h, err := base64.RawURLEncoding.DecodeString(q)
	if err != nil || len(h) != sha256.Size {
		return nil, false
	}
	return c.liveCode(r.Context(), h)
}

func (c *community) liveCode(ctx context.Context, hash []byte) (*cchain.Code, bool) {
	st := c.snapshot()
	if st == nil {
		return nil, false
	}
	code := st.Live(hash, now())
	if code == nil {
		return nil, false
	}
	if code.Uses > 0 {
		used, err := c.st.CodeUses(ctx, c.name, hash)
		if err != nil || used >= code.Uses {
			return nil, false
		}
	}
	if ok, err := c.isMember(ctx, code.Creator); err != nil || !ok {
		return nil, false
	}
	return code, true
}

// cerr answers a cchain error with its status and code, and anything else with 503.
func (c *community) cerr(w http.ResponseWriter, err error) {
	var ce *cchain.Error
	if errors.As(err, &ce) {
		if ce.Code == wire.ErrCodeClockSkew {
			writeBody(w, ce.Status, map[string]any{"error": ce.Code, "msg": ce.Msg, "now": now()})
			return
		}
		writeError(w, ce.Status, ce.Code, ce.Msg)
		return
	}
	c.hs.unavailableRead(w, "checking a community chain entry", err)
}

// ---- GET preview ----

func (c *community) preview(w http.ResponseWriter, r *http.Request) {
	st := c.snapshot()
	if st == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "this server hosts no community yet")
		return
	}
	cm, err := c.st.Get(r.Context(), c.name)
	if err != nil {
		c.hs.unavailableRead(w, "reading a community", err)
		return
	}
	if c.moved(st) {
		// The chain, ending in the set-home, says where it went (spec/api/community.md).
		writeBody(w, http.StatusGone, map[string]any{"error": wire.ErrCodeExpired, "msg": "this community moved to " + st.Server})
		return
	}
	files := map[string]any{"days": c.hs.cfg.CommunityFileDays}
	if q := c.hs.cfg.CommunityFileQuota; q > 0 {
		files["quota"] = q
	}
	res := map[string]any{
		"id":       st.ID,
		"head":     st.Head,
		"name":     st.Name,
		"settings": map[string]any{"public-codes": st.Public, "approval": st.Approval},
		"files":    files,
	}
	if cm.Group != nil {
		res["group"] = wire.Bytes(cm.Group)
	}
	if st.Desc != "" {
		res["desc"] = st.Desc
	}
	if ic := st.Icon; ic != nil {
		res["icon"] = map[string]any{"mime": ic.Mime, "hash": wire.Bytes(ic.Hash), "size": ic.Size}
	}
	writeBody(w, http.StatusOK, res)
}

// ---- helpers ----

// queryUint reads a non-negative integer query parameter, def if it's absent.
func queryUint(r *http.Request, name string, def uint64) (uint64, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.ParseUint(v, 10, 64)
	return n, err == nil
}

// limitParam reads `limit`, between 1 and max, default def.
func limitParam(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, max)
}

func rateLimited(w http.ResponseWriter, retry uint64) {
	writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Retry: retry})
}

// identityChain finds an identity's chain through this community's own Server: local, cached,
// or fetched from home (SPEC §6.5). fresh asks home again.
func (c *community) identityChain(ctx context.Context, id, home string, fresh bool) (*chain2, error) {
	if fresh && home != "" && home != c.srv.cfg.Name {
		st, raw, err := c.srv.fetchRemote(ctx, id, home, true)
		if err == nil {
			c.fetched.Store(id, now())
			return &chain2{st, raw}, nil
		}
		var es *fed.ErrStatus
		if errors.As(err, &es) || home == "" {
			return nil, err
		}
	}
	st, raw, err := c.srv.lookup(ctx, id, home)
	if err != nil {
		return nil, err
	}
	return &chain2{st, raw}, nil
}

// chain2 is an identity's chain, validated, with its entries.
type chain2 struct {
	st  *chain.State
	raw [][]byte
}

// streamIdleCommunity is how long a community stream may stay silent.
const streamIdleCommunity = 90 * time.Second
