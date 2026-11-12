package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- invite codes (SPEC §9.1) ----

const inviteAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// newInviteCode makes a 10-character code from [A-Za-z0-9] (about 59 bits).
func newInviteCode() string {
	out := make([]byte, 0, 10)
	var b [1]byte
	for len(out) < 10 {
		rand.Read(b[:])
		if int(b[0]) < 248 { // 248 = 4 × 62: no modulo bias
			out = append(out, inviteAlphabet[int(b[0])%62])
		}
	}
	return string(out)
}

// inviteHash is HMAC-SHA256 under a secret outside the database (SPEC §9.1), so a leaked
// database doesn't let anyone brute-force the 59-bit codes. The secret is derived from the
// server's signing key, which lives in its own file.
func (s *Server) inviteHash(code string) []byte {
	m := hmac.New(sha256.New, s.inviteKey)
	m.Write([]byte(code))
	return m.Sum(nil)
}

func (s *Server) inviteCreate(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Public  bool  `json:"public,omitempty"`
		Uses    int   `json:"uses,omitempty"`    // 0 or absent: unlimited
		Expires int64 `json:"expires,omitempty"` // 0 or absent: never
	}
	if !readBody(w, r, &req) {
		return
	}
	if req.Uses < 0 || (req.Expires != 0 && req.Expires <= now()) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "uses must be positive and expires in the future")
		return
	}
	uses := req.Uses
	if uses == 0 {
		uses = -1
	}
	code := newInviteCode()
	inv := store.Invite{Hash: s.inviteHash(code), Owner: sess.id, Public: req.Public, Uses: uses, Expires: req.Expires, Created: now()}
	if err := s.st.Invites().Create(r.Context(), inv); err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	// The code is shown once; the server keeps only its hash.
	writeBody(w, http.StatusOK, map[string]any{"code": code, "hash": inv.Hash})
}

func (s *Server) inviteRevoke(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Code string     `json:"code,omitempty"`
		Hash wire.Bytes `json:"hash,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	hash := []byte(req.Hash)
	if req.Code != "" {
		hash = s.inviteHash(req.Code)
	}
	if len(hash) != 32 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "give the code or its hash")
		return
	}
	if err := s.st.Invites().Revoke(r.Context(), sess.id, hash); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) inviteList(w http.ResponseWriter, r *http.Request, sess session) {
	invs, _ := s.st.Invites().List(r.Context(), sess.id, now())
	items := []map[string]any{}
	for _, inv := range invs {
		m := map[string]any{"hash": inv.Hash, "public": inv.Public, "created": inv.Created}
		if inv.Uses >= 0 {
			m["uses"] = inv.Uses
		}
		if inv.Expires != 0 {
			m["expires"] = inv.Expires
		}
		items = append(items, m)
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// originKey is what per-origin limits count (SPEC §9.5): the registrable domain, not the full
// server name. Anyone with one domain can mint as many server names under it as they like,
// so counting each name separately would let them multiply every per-origin limit.
// Domains on the Public Suffix List (shared hosting that gives out
// subdomains) count separately, as they're meant to.
func originKey(server string) string {
	host := strings.ToLower(strings.TrimSuffix(server, "."))
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i] // a port (dev servers)
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// checkInvite decides whether a contact request may reach `to` (SPEC §9.1, §9.5).
// origin is the requester's homeserver. It returns "" if the request may go through, or
// why not, for the operator's log only: every refusal is silent to the caller.
func (s *Server) checkInvite(ctx context.Context, body contactRequestBody, origin string) string {
	t := now()
	org := originKey(origin)
	if body.Invite == "" || len(body.Invite) > 64 {
		return "no invite code"
	}
	if !s.limits.allow("bad-code|"+org, 20, 3600, t, false) {
		return "too many wrong codes from this server this hour"
	}
	inv, err := s.st.Invites().Use(ctx, body.To, s.inviteHash(body.Invite), t)
	if err != nil {
		s.limits.allow("bad-code|"+org, 20, 3600, t, true)
		return "wrong, used up, revoked, or expired invite code"
	}
	if !inv.Public {
		return "" // a private code reaches only the people it was given to
	}
	// Public codes are readable off a profile, so the per-sender limits apply (SPEC §9.5).
	// The per-server total is far lower for servers none of our users has a contact on.
	originMax := 50
	if known, _ := s.st.Remote().HasContactOn(ctx, origin); known || origin == s.cfg.Name {
		originMax = 1000
	}
	if !s.limits.allowAll(t,
		limit{"origin|" + org, originMax, 24 * 3600},
		limit{"pair|" + body.From + "|" + body.To, 1, 7 * 24 * 3600},
		limit{"sender|" + body.From, 20, 24 * 3600},
		limit{"origin-user|" + org + "|" + body.To, 10, 24 * 3600},
	) {
		return "public code over a rate limit (SPEC §9.5; one request per sender and recipient per 7 days)"
	}
	return ""
}

// ---- a small in-memory rate limiter ----

type limit struct {
	key    string
	max    int
	window int64 // seconds
}

type limiter struct {
	mu sync.Mutex
	m  map[string][]int64 // key -> event times within the window
}

func (l *limiter) prune(key string, window, t int64) []int64 {
	ev := l.m[key]
	i := 0
	for i < len(ev) && ev[i] <= t-window {
		i++
	}
	ev = ev[i:]
	if len(ev) == 0 {
		delete(l.m, key)
	} else {
		l.m[key] = ev
	}
	return ev
}

// allow reports whether key is under max events in the window; with record, it also counts one.
func (l *limiter) allow(key string, max int, window, t int64, record bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev := l.prune(key, window, t)
	if record {
		l.m[key] = append(ev, t)
	}
	return len(ev) < max
}

// sweep forgets keys with no events in the last 30 days, the longest window any limit uses.
func (l *limiter) sweep(t int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.m {
		l.prune(k, 30*24*3600, t)
	}
}

// save writes the limiter's state to path, so limits survive a restart.
func (l *limiter) save(path string) error {
	l.mu.Lock()
	b, err := json.Marshal(l.m)
	l.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// load reads state written by save. A missing file is an empty limiter.
func (l *limiter) load(path string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return json.Unmarshal(b, &l.m)
}

// allowAll counts an event against every limit, but only if all of them allow it.
func (l *limiter) allowAll(t int64, ls ...limit) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, x := range ls {
		if len(l.prune(x.key, x.window, t)) >= x.max {
			return false
		}
	}
	for _, x := range ls {
		l.m[x.key] = append(l.m[x.key], t)
	}
	return true
}
