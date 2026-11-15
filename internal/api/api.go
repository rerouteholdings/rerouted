// Package api serves the Tieroute HTTP APIs (spec/api/).
//
// Wire versions 1 and 2, side by side, each under its own API base (wireversion.go): JSON
// bodies (SPEC §4), API bases published in the server document (SPEC §8.1), invite-only
// contact requests (SPEC §9). Endpoints that aren't built yet are routed and answer 501
// not-implemented.
package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// MaxBody is the largest JSON request body accepted (spec/api/conventions.md).
const MaxBody = 1 << 20

// Server holds what the handlers need.
type Server struct {
	cfg *config.Config
	key serverkey.Key
	log *slog.Logger
	st  store.Store
	fed *fed.Fed
	// localHTTP asks the other instances on this host (REROUTED_TLS_ASK_ALSO). It isn't fed's
	// client, which refuses loopback addresses outside dev mode.
	localHTTP *http.Client
	out       outboxQueues
	mux       *http.ServeMux
	links     linkProofs
	limits    *limiter // shared by both wire versions
	inviteKey []byte
	homeAsker func(ctx context.Context, home, id string) ([][]byte, error) // tests: stands in for previous homes
	retry     destBackoff
	sending   keyLocks // one send at a time per sender and delivery ID
	streams   streams
	presence  presenceBook
	profiles  remoteProfiles
	fire      *firehose // nil unless REROUTED_PUBLIC_FIREHOSE=on
	clock     clockNotes
	wv        int          // the wire version this Server speaks: wire.V1 or wire.V2
	apiPath   string       // where its APIs live, with "client/" and "s2s/" under it
	v2        *Server      // on the version 1 Server, its version 2 sibling (wireversion.go)
	v1        *Server      // on the version 2 Server, its version 1 sibling, for migrations (migrate.go)
	comm      *communities // on the version 1 Server: the community servers it runs (community.go)
}

// New makes the server for both wire versions: the version 1 Server, which serves
// discovery and holds its version 2 sibling. Handler serves both.
func New(cfg *config.Config, key serverkey.Key, log *slog.Logger, st store.Store) *Server {
	cfg.Defaults()
	s := newServer(cfg, key, log, st, wire.V1, &limiter{m: map[string][]int64{}})
	ik := hmac.New(sha256.New, key.Priv.Seed())
	ik.Write([]byte("tieroute invite codes"))
	s.inviteKey = ik.Sum(nil)
	if p := s.limitsPath(); p != "" {
		if err := s.limits.load(p); err != nil {
			log.Warn("rate limits from the last run couldn't be read; starting fresh", "err", err)
		}
	}
	if cfg.PublicFirehose {
		s.fire = newFirehose(s)
	}
	// Wire version 2 shares the mux, the database (its own view of it), the rate limits,
	// and the invite code key, so codes made on either API hash alike.
	s.v2 = newServer(cfg, key, log.With("wire", 2), st.ForWire(wire.V2), wire.V2, s.limits)
	s.v2.mux, s.v2.inviteKey, s.v2.v1 = s.mux, s.inviteKey, s
	s.routes()
	s.v2.apiRoutes()
	s.initCommunities()
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "no such endpoint")
	})
	return s
}

func newServer(cfg *config.Config, key serverkey.Key, log *slog.Logger, st store.Store, v int, limits *limiter) *Server {
	s := &Server{
		cfg:      cfg,
		key:      key,
		log:      log,
		st:       st,
		mux:      http.NewServeMux(),
		out:      newOutboxQueues(),
		links:    linkProofs{m: map[string]*linkProof{}},
		limits:   limits,
		retry:    destBackoff{m: map[string]*backoff{}},
		streams:  streams{m: map[string]map[*stream]bool{}},
		profiles: remoteProfiles{m: map[string]cachedProfile{}},
		presence: presenceBook{local: map[string]presence{}, remote: map[string]presence{}, timers: map[string]*time.Timer{}},
		wv:       v,
		apiPath:  cfg.APIPath,
	}
	if v == wire.V2 {
		s.apiPath = cfg.APIPathV2
	}
	s.localHTTP = &http.Client{Timeout: 15 * time.Second}
	s.fed = fed.New(cfg.Name, key, cfg.Peers)
	if !cfg.Dev {
		s.fed.PublicOnly(cfg.FedAllow)
	}
	s.fed.V = v
	s.fed.OnClock = s.peerClock
	s.fed.UseNonce = st.Sessions().UseNonce
	return s
}

// V2 is the wire version 2 sibling of the version 1 Server New returns.
func (s *Server) V2() *Server { return s.v2 }

// CloseFirehose ends the public firehose's connections, so a graceful shutdown
// doesn't wait on them.
func (s *Server) CloseFirehose() { s.fire.closeAll() }

func (s *Server) Handler() http.Handler { return s.cors(s.dispatch(s.mux)) }

// cors lets browser clients on any origin use the client API and read discovery
// documents, as Reroute's web build does. It's safe to open to every origin: the
// client API authenticates with bearer tokens, never cookies, so a page can only act
// with a token it already holds. The S2S API gets no CORS: browsers never call it.
func (s *Server) cors(next http.Handler) http.Handler {
	client, clientV2, comm := s.cfg.APIPath+"client/", s.cfg.APIPathV2+"client/", s.cfg.APIPathV2+"community/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, client) || strings.HasPrefix(r.URL.Path, clientV2) || strings.HasPrefix(r.URL.Path, comm) || strings.HasPrefix(r.URL.Path, "/.well-known/tieroute/server") || strings.HasPrefix(r.URL.Path, "/.well-known/tieroute/handle") {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Allow-Methods", "GET, POST")
			h.Set("Access-Control-Max-Age", "86400")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientEndpoints lists every client endpoint rerouted routes (SPEC Appendix A).
// Those without a handler answer 501 not-implemented, which the core server tier allows
// for some (SPEC §20.3) and the rest are still to come.
var clientEndpoints = []string{
	"POST register",
	"POST auth/challenge",
	"POST auth/session",
	"POST auth/logout",
	"GET chain/{id}",
	"POST chain/append",
	"GET resolve/{handle}",
	"POST recover",
	"POST link/proof",
	"GET link/proof/{device}",
	"GET servers/{name}",
	"POST keypackages/upload",
	"GET keypackages/count",
	"POST keypackages/claim",
	"POST contacts/request",
	"POST contacts/accept",
	"POST contacts/decline",
	"POST contacts/cancel",
	"POST contacts/remove",
	"POST contacts/block",
	"POST contacts/unblock",
	"GET contacts",
	"POST invites/create",
	"POST invites/revoke",
	"GET invites",
	"POST groups/create",
	"POST groups/epoch-key",
	"POST groups/register",
	"POST groups/unregister",
	"GET groups/{group}/commits",
	"POST send",
	"GET inbox",
	"POST inbox/ack",
	"GET stream",
	"POST presence",
	"POST media/upload",
	"GET media/{server}/{id}",
	"POST profile",
	"GET profile/{id}",
	"POST media/upload-public",
	"GET account/keys",
	"POST account/keys",
	"GET account/data",
	"POST account/data",
	"POST backup/put",
	"GET backup/list",
	"GET backup/get",
	"GET turn",
	"POST report",
}

func (s *Server) routes() {
	// The only fixed paths: discovery (SPEC §5). Everything else hangs off the
	// bases the server document publishes (SPEC §8.1).
	s.mux.HandleFunc("GET /.well-known/tieroute/server", s.serverDoc)
	s.mux.HandleFunc("GET /.well-known/tieroute/handle", s.handleDoc)
	// On-demand TLS helper for the reverse proxy (deployment, not protocol).
	s.mux.HandleFunc("GET /v0/tls-ask", s.tlsAsk)
	// The public firehose (deployment, not protocol): off unless configured, and then
	// unknown paths and this one answer alike.
	if s.fire != nil {
		s.mux.HandleFunc("GET /v0/dev/firehose", s.firehoseStream)
	}
	s.apiRoutes()
}

// apiRoutes routes this Server's wire version's client and S2S APIs, under its API path.
func (s *Server) apiRoutes() {
	impl := map[string]http.HandlerFunc{
		"POST register":              s.register,
		"POST auth/challenge":        s.authChallenge,
		"POST auth/session":          s.authSession,
		"POST auth/logout":           s.authed(s.authLogout),
		"GET chain/{id}":             s.optAuthed(s.getChain),
		"POST chain/append":          s.authed(s.appendChain),
		"GET resolve/{handle}":       s.optAuthed(s.resolve),
		"POST recover":               s.recoverAccount,
		"POST link/proof":            s.postLinkProof,
		"GET link/proof/{device}":    s.authed(s.getLinkProof),
		"GET servers/{name}":         s.authed(s.serverInfo),
		"POST keypackages/upload":    s.authed(s.kpUpload),
		"GET keypackages/count":      s.authed(s.kpCount),
		"POST keypackages/claim":     s.authed(s.kpClaim),
		"POST contacts/request":      s.authed(s.contactRequest),
		"POST contacts/accept":       s.authed(s.contactAccept),
		"POST contacts/decline":      s.authed(s.contactDeclineReq),
		"POST contacts/cancel":       s.authed(s.contactCancel),
		"POST contacts/remove":       s.authed(s.contactRemove),
		"POST contacts/block":        s.authed(s.contactBlock),
		"POST contacts/unblock":      s.authed(s.contactUnblock),
		"GET contacts":               s.authed(s.listContacts),
		"POST invites/create":        s.authed(s.inviteCreate),
		"POST invites/revoke":        s.authed(s.inviteRevoke),
		"GET invites":                s.authed(s.inviteList),
		"POST groups/create":         s.authed(s.groupCreate),
		"POST groups/epoch-key":      s.authed(s.groupEpochKey),
		"POST groups/register":       s.authed(s.groupRegister(true)),
		"POST groups/unregister":     s.authed(s.groupRegister(false)),
		"GET groups/{group}/commits": s.authed(s.groupCommits),
		"POST send":                  s.authed(s.send),
		"GET inbox":                  s.authed(s.getInbox),
		"POST inbox/ack":             s.authed(s.ackInbox),
		"GET stream":                 s.stream,
		"POST presence":              s.authed(s.setPresence),
		"POST profile":               s.authed(s.postProfile),
		"GET profile/{id}":           s.authed(s.getProfile),
		"POST media/upload":          s.authed(s.mediaUpload),
		"POST media/upload-public":   s.authed(s.mediaUploadPublic),
		"GET media/{server}/{id}":    s.authed(s.mediaGet),
		"GET turn":                   s.authed(s.getTurn),
		"POST report":                s.authed(s.postReport),
		"GET account/keys":           s.authed(s.getAccountKeys),
		"POST account/keys":          s.authed(s.postAccountKeys),
		"GET account/data":           s.authed(s.getAccountData),
		"POST account/data":          s.authed(s.postAccountData),
		"POST backup/put":            s.authed(s.backupPut),
		"GET backup/list":            s.authed(s.backupList),
		"GET backup/get":             s.authed(s.backupGet),
	}
	client := s.apiPath + "client/"
	for _, r := range clientEndpoints {
		method, path, _ := strings.Cut(r, " ")
		h, ok := impl[r]
		if !ok {
			h = notImplemented
		}
		s.mux.Handle(method+" "+client+path, s.jsonIn(h))
	}
	// S2S (SPEC Appendix A).
	for path, h := range map[string]func(http.ResponseWriter, *http.Request, string, wire.Raw){
		"identity/fetch":    s.s2sIdentityFetch,
		"keypackages/claim": s.s2sKeyPackageClaim,
		"contacts/request":  s.s2sContactRequest,
		"contacts/decline":  s.s2sContactDecline,
		"deliver":           s.s2sDeliver,
		"commit":            s.s2sCommit,
		"identity/push":     s.s2sIdentityPush,
		"group/epoch-key":   s.s2sGroupEpochKey,
		"commit/fetch":      s.s2sCommitFetch,
		"presence":          s.s2sPresence,
		"profile/fetch":     s.s2sProfileFetch,
		"media/fetch":       s.s2sMediaFetch,
		"report":            s.s2sReport,
		"group/register":    s.s2sGroupRegister,
	} {
		s.mux.Handle("POST "+s.apiPath+"s2s/"+path, s.jsonIn(s.s2s(path, h)))
	}
}

// jsonIn enforces the content type and body limit on POSTs (spec/api/conventions.md).
func (s *Server) jsonIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// File uploads carry raw bytes, and check their own type and size (SPEC §14).
		if r.Method == http.MethodPost && !strings.HasPrefix(r.URL.Path, s.apiPath+"client/media/upload") {
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != wire.MediaType {
				writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "use "+wire.MediaType)
				return
			}
			limit := int64(MaxBody)
			if r.URL.Path == s.apiPath+"client/backup/put" {
				limit = maxBackupBody // a 1 MiB segment, in base64url (spec/api/conventions.md)
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// readBody decodes a request body into v, writing the error response itself on failure.
func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "")
		return false
	}
	if err := wire.Unmarshal(b, v); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, err.Error())
		return false
	}
	return true
}

func writeBody(w http.ResponseWriter, status int, v any) {
	b, err := wire.Marshal(v)
	if err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", wire.MediaType)
	w.WriteHeader(status)
	w.Write(b)
}

// writeRaw passes a JSON body through as it is, such as a hub's answer.
func writeRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", wire.MediaType)
	w.WriteHeader(status)
	w.Write(b)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeBody(w, status, wire.Error{Code: code, Msg: msg})
}

// unavailableRead answers a request whose storage failed with 503, so the client
// retries, instead of an answer that would look complete.
func (s *Server) unavailableRead(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, wire.ErrCodeNotImplemented, r.Method+" "+r.URL.Path)
}
