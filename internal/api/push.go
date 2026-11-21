package api

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rerouteholdings/rerouted/internal/apns"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- push notifications for the Reroute iPhone app (rerouted only, outside the Tieroute spec) ----
//
// A device registers its APNs device token with POST /v0/push/apns. When a delivery worth
// a notification lands in its identity's inbox, and the device has no stream open, the
// device gets an alert that says only "New message": the app fetches and decrypts what
// came when it's opened. Nothing about the delivery, not even who sent it, goes to Apple.

const (
	pushCoalesce = 10 * time.Second // at most one push per device this often
	pushExpiry   = 24 * time.Hour   // how long APNs keeps trying a device that's offline
	pushTimeout  = 15 * time.Second // per notification
	pushQueueLen = 1024             // notifications waiting to go out; more are dropped
	pushWorkers  = 4
	pushMaxBody  = 4 << 10
)

// pushPayload is every notification's payload: content-free. mutable-content lets a
// Notification Service Extension in the app replace the text later.
var pushPayload = []byte(`{"aps":{"alert":{"title":"Reroute","body":"New message"},"sound":"default","mutable-content":1,"thread-id":"messages"}}`)

// pushCollapseID makes a device's notifications replace each other, so it shows one.
const pushCollapseID = "reroute-messages"

// pusher sends APNs notifications for both wire versions' Servers.
type pusher struct {
	c      *apns.Client
	st     store.Push
	log    *slog.Logger
	q      chan pushJob
	window time.Duration // pushCoalesce; tests shorten it

	mu   sync.Mutex
	last map[string]time.Time // by identity and device: when the last push went out

	sent, failed atomic.Int64
}

// pushJob is a delivery that landed in owner's inbox on srv. tokens, if set, are the
// devices to notify, read before the identity's tokens were dropped.
type pushJob struct {
	srv    *Server
	owner  string
	tokens []store.APNSToken
}

// newPusher starts the sender, or returns nil when push is off.
func newPusher(cfg *config.Config, st store.Push, log *slog.Logger) *pusher {
	k := cfg.APNSKey()
	if k == nil {
		return nil
	}
	topic := cfg.APNSTopic
	if topic == "" {
		topic = config.DefaultAPNSTopic
	}
	p := &pusher{
		c: apns.New(k, cfg.APNSKeyID, cfg.APNSTeamID, topic), st: st, log: log,
		q: make(chan pushJob, pushQueueLen), window: pushCoalesce, last: map[string]time.Time{},
	}
	for range pushWorkers {
		go p.work()
	}
	return p
}

// pushNotify queues a notification for owner's devices. It never blocks a delivery: when
// the queue is full, the notification is dropped.
func (s *Server) pushNotify(owner string) {
	if s.pushes == nil {
		return
	}
	select {
	case s.pushes.q <- pushJob{srv: s, owner: owner}:
	default:
		s.pushes.failed.Add(1)
		s.log.Warn("push notification dropped: the queue is full")
	}
}

// chainAlarm tells owner's devices about a change to their chain that they didn't make
// (SPEC §6.4.1): a chain-alert notice in the inbox, and a push notification, so a device
// that isn't open hears of it too. Call it before the identity's push tokens are dropped,
// as after a move or a migration: its devices get this one notification all the same.
func (s *Server) chainAlarm(ctx context.Context, owner, level string, entry []byte) {
	var toks []store.APNSToken
	if s.pushes != nil && level == "alarm" {
		var err error
		if toks, err = s.st.Push().APNS(ctx, owner); err != nil {
			s.log.Warn("reading push tokens", "err", err)
		}
	}
	s.logged("sending a chain alert", s.notify(ctx, owner, map[string]any{"t": "chain-alert", "level": level, "entry": wire.Raw(entry)}))
	if len(toks) == 0 {
		return
	}
	select {
	case s.pushes.q <- pushJob{s, owner, toks}:
	default:
		s.pushes.failed.Add(1)
		s.log.Warn("push notification dropped: the queue is full")
	}
}

// pushWorthy says whether a delivery stored in owner's inbox earns a notification: messages
// and Welcomes (being added to a chat) from someone else. Commits and proposals are group
// upkeep, link bundles and the sender's own copies come from the owner's own devices, and
// ephemeral deliveries (typing, receipts) are never stored. Calls are signaled inside MLS
// application messages, so they can't be told apart here.
func pushWorthy(d delivery, owner string) bool {
	return d.Kind == "mls" && (d.MLS == "app" || d.MLS == "welcome") && d.From != owner && !d.Ephemeral
}

func (p *pusher) work() {
	for j := range p.q {
		p.handle(j)
	}
}

func (p *pusher) handle(j pushJob) {
	toks := j.tokens
	if toks == nil {
		ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
		var err error
		toks, err = p.st.APNS(ctx, j.owner)
		cancel()
		if err != nil {
			p.log.Warn("reading push tokens", "err", err)
			return
		}
	}
	for _, t := range toks {
		// An app with a stream open is in the foreground, and already has the delivery.
		if j.srv.streams.deviceOpen(j.owner, t.Device) || !p.due(j.owner, t.Device) {
			continue
		}
		p.send(t)
	}
}

// due reports whether a device may get a push now, and if so, counts one as sent.
func (p *pusher) due(id string, device []byte) bool {
	key := id + "|" + string(device)
	t := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if last, ok := p.last[key]; ok && t.Sub(last) < p.window {
		return false
	}
	if len(p.last) >= 4096 {
		for k, last := range p.last {
			if t.Sub(last) >= p.window {
				delete(p.last, k)
			}
		}
	}
	p.last[key] = t
	return true
}

func (p *pusher) send(t store.APNSToken) {
	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()
	res, err := p.c.Send(ctx, apns.Notification{
		Token: t.Token, Env: t.Env, Payload: pushPayload, PushType: "alert", Priority: 10,
		CollapseID: pushCollapseID, Expiration: time.Now().Add(pushExpiry),
	})
	short := t.Token[:min(8, len(t.Token))]
	switch {
	case err != nil:
		p.failed.Add(1)
		p.log.Warn("push notification failed", "token", short, "err", err)
	case res.OK():
		p.sent.Add(1)
	case res.TokenGone():
		p.failed.Add(1)
		p.log.Info("push token no longer valid; removed", "token", short, "status", res.Status, "reason", res.Reason)
		ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
		defer cancel()
		if err := p.st.DropAPNSToken(ctx, t.Token); err != nil {
			p.log.Warn("removing a push token", "err", err)
		}
	default:
		p.failed.Add(1)
		p.log.Warn("push notification refused", "token", short, "status", res.Status, "reason", res.Reason)
	}
}

// ---- POST and DELETE /v0/push/apns ----

// anyAuthed is authed for rerouted's own endpoints, which take a session of either wire
// version. h gets the Server whose session it is.
func (s *Server) anyAuthed(h func(http.ResponseWriter, *http.Request, *Server, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "missing bearer token")
			return
		}
		sum := sha256.Sum256([]byte(tok))
		for _, srv := range []*Server{s, s.v2} {
			if srv == nil {
				continue
			}
			if id, dev, err := srv.st.Sessions().LookupToken(r.Context(), sum[:], now()); err == nil {
				h(w, r, srv, session{id: id, device: dev, tokenHash: sum[:]})
				return
			}
		}
		writeError(w, http.StatusUnauthorized, wire.ErrCodeUnauthenticated, "")
	}
}

// pushJSON takes the JSON body of a push request: application/json or Tieroute's type.
func pushJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || (mt != "application/json" && mt != wire.MediaType) {
			writeError(w, http.StatusUnsupportedMediaType, wire.ErrCodeBadContentType, "use application/json")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, pushMaxBody)
		next.ServeHTTP(w, r)
	})
}

// pushToken checks a device token, 32 to 200 hex digits, and lowercases it.
func pushToken(s string) (string, bool) {
	if len(s) < 32 || len(s) > 200 {
		return "", false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", false
		}
	}
	return strings.ToLower(s), true
}

// pushRequest reads and checks a push request, and answers it itself if it fails.
func (s *Server) pushRequest(w http.ResponseWriter, r *http.Request, sess session, needEnv bool) (token, env string, ok bool) {
	if s.pushes == nil {
		writeError(w, http.StatusNotImplemented, wire.ErrCodeNotImplemented, "this homeserver doesn't send push notifications")
		return "", "", false
	}
	var req struct {
		Token string `json:"token"`
		Env   string `json:"env"`
	}
	if !readBody(w, r, &req) {
		return "", "", false
	}
	token, good := pushToken(req.Token)
	if !good {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `"token" must be the device token in hex: 32 to 200 characters`)
		return "", "", false
	}
	if needEnv && req.Env != apns.Sandbox && req.Env != apns.Production {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `"env" must be "sandbox" or "production"`)
		return "", "", false
	}
	if !s.limits.allow("push|"+sess.id, 60, 3600, now(), true) {
		writeError(w, http.StatusTooManyRequests, wire.ErrCodeRateLimited, "")
		return "", "", false
	}
	return token, req.Env, true
}

func (s *Server) pushRegister(w http.ResponseWriter, r *http.Request, srv *Server, sess session) {
	token, env, ok := s.pushRequest(w, r, sess, true)
	if !ok {
		return
	}
	// Only an identity that lives here gets deliveries here to be told about.
	switch here, err := srv.local(r.Context(), sess.id); {
	case err != nil:
		s.unavailableRead(w, "checking an identity for push", err)
		return
	case !here || srv.closedLocal(r.Context(), sess.id):
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "this identity doesn't live on this homeserver")
		return
	}
	if err := s.st.Push().PutAPNS(r.Context(), store.APNSToken{ID: sess.id, Device: sess.device, Token: token, Env: env, Updated: now()}); err != nil {
		s.unavailableRead(w, "storing a push token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pushUnregister(w http.ResponseWriter, r *http.Request, _ *Server, sess session) {
	token, _, ok := s.pushRequest(w, r, sess, false)
	if !ok {
		return
	}
	if err := s.st.Push().DeleteAPNS(r.Context(), sess.id, token); err != nil {
		s.unavailableRead(w, "removing a push token", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// dropPush removes the push tokens of an identity that no longer gets deliveries here: it
// moved away, or migrated to wire version 2. Its devices register again where it went.
func (s *Server) dropPush(ctx context.Context, id string) {
	s.logged("removing the push tokens of an identity that left", s.st.Push().DropAPNSIdentity(ctx, id))
}
