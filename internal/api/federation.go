package api

import (
	"context"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- finding identities, local or remote ----

// isLocal: the identity lives here. One that moved away is kept only as a tombstone
// (SPEC §6.6), and is remote like any other.
func (s *Server) isLocal(ctx context.Context, id string) bool {
	st, _, err := s.identity(ctx, id)
	return err == nil && st.Home == s.cfg.Name
}

// canonChain re-encodes chain entries received from elsewhere as JCS, so stored
// copies compare byte for byte whatever formatting they arrived in (SPEC §4.3).
func canonChain(in [][]byte) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, e := range in {
		c, err := wire.CanonicalSigned(e)
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

func decodeChain(raw [][]byte) (*chain.State, error) {
	entries := make([]wire.Signed, len(raw))
	for i, b := range raw {
		var err error
		if entries[i], err = wire.DecodeSigned(b); err != nil {
			return nil, err
		}
	}
	return chain.Validate(entries)
}

// lookup finds any identity's chain: local, cached from another server, or fetched
// from homeHint if neither (SPEC §6.5). The returned home is where the chain says it lives.
func (s *Server) lookup(ctx context.Context, id, homeHint string) (*chain.State, [][]byte, error) {
	if st, raw, err := s.identity(ctx, id); err == nil {
		return st, raw, nil
	}
	if home, raw, err := s.st.Remote().Get(ctx, id); err == nil && (homeHint == "" || homeHint == home) {
		if st, err := decodeChain(raw); err == nil {
			return st, raw, nil
		}
	}
	if homeHint == "" || homeHint == s.cfg.Name || s.fed == nil {
		return nil, nil, store.ErrNotFound
	}
	return s.fetchRemote(ctx, id, homeHint, true)
}

// fetchRemote asks a server for a chain, follows one move (set-home), and caches it.
func (s *Server) fetchRemote(ctx context.Context, id, home string, follow bool) (*chain.State, [][]byte, error) {
	raw, err := s.fetchChainRaw(ctx, home, id)
	if err != nil {
		return nil, nil, err
	}
	st, err := decodeChain(raw)
	if err != nil {
		return nil, nil, err
	}
	if st.ID != id {
		return nil, nil, errors.New("fetched chain is for a different identity")
	}
	if st.Home != home && follow && st.Home != s.cfg.Name {
		// The chain says it moved (SPEC §5.3): the new home may have more.
		if st2, raw2, err := s.fetchRemote(ctx, id, st.Home, false); err == nil {
			return st2, raw2, nil
		}
	}
	// What we fetch must extend the cache or be a valid recovery fork, and new
	// device-signed entries need the home before them to vouch for them (SPEC §6.5).
	st, raw, _, err = s.acceptChain(ctx, id, raw, home)
	return st, raw, err
}

// ---- outbox (SPEC §10.5) ----

const outboxExpiry = 72 * 3600

func (s *Server) enqueue(ctx context.Context, dest, path string, body any) {
	b, err := wire.Marshal(body)
	if err != nil {
		s.log.Error("encode s2s body", "err", err)
		return
	}
	if err := s.st.Outbox().Enqueue(ctx, dest, path, b, now()); err != nil {
		s.log.Error("enqueue", "err", err)
		return
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// RunOutbox delivers queued S2S requests until ctx ends.
func (s *Server) RunOutbox(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		s.flushOutbox(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
	}
}

// backoff is the retry schedule for one destination server (SPEC §10.5): every
// delivery queued for a failing server waits on the same schedule.
type backoff struct {
	attempts int
	until    int64
}

type destBackoff struct {
	mu sync.Mutex
	m  map[string]*backoff
}

// waiting returns when dest may next be tried, or 0 if now.
func (d *destBackoff) waiting(dest string, t int64) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if b := d.m[dest]; b != nil && b.until > t {
		return b.until
	}
	return 0
}

// fail records a failure and returns when to try again: min(10 s × 2^(n−1), 1 h),
// times a random factor in [0.75, 1.25], but never sooner than the server's own hint.
func (d *destBackoff) fail(dest string, t, hint int64) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.m[dest]
	if b == nil {
		b = &backoff{}
		d.m[dest] = b
	}
	b.attempts++
	wait := min(int64(10)<<min(b.attempts-1, 9), 3600)
	wait = (wait*int64(750+mrand.IntN(501)) + 999) / 1000 // round up: never below 0.75 × the step
	if hint > wait {
		wait = min(hint, 6*3600)
	}
	b.until = t + wait
	return b.until
}

// ok resets dest's schedule: it answered.
func (d *destBackoff) ok(dest string) {
	d.mu.Lock()
	delete(d.m, dest)
	d.mu.Unlock()
}

func (s *Server) flushOutbox(ctx context.Context) {
	items, err := s.st.Outbox().Due(ctx, now(), 50)
	if err != nil {
		return
	}
	for _, it := range items {
		t := now()
		if t-it.Created > outboxExpiry {
			s.log.Warn("s2s gave up after 72 hours", "dest", it.Dest, "path", it.Path)
			s.st.Outbox().Done(ctx, it.ID)
			s.deliveryFailed(ctx, it, "expired", nil)
			continue
		}
		if until := s.retry.waiting(it.Dest, t); until != 0 {
			s.st.Outbox().Retry(ctx, it.ID, until) // its server is backing off: wait in line
			continue
		}
		_, err := s.fed.Call(ctx, it.Dest, it.Path, it.Body)
		var st *fed.ErrStatus
		isStatus := errors.As(err, &st)
		switch {
		case err == nil:
			s.retry.ok(it.Dest)
			s.st.Outbox().Done(ctx, it.ID)
		case isStatus && st.Status/100 == 4 && !retryable(st.Status):
			// A refusal: the server is up, but won't take this one. Don't retry.
			s.retry.ok(it.Dest)
			s.log.Warn("s2s refused", "dest", it.Dest, "path", it.Path, "err", err)
			s.st.Outbox().Done(ctx, it.ID)
			s.deliveryFailed(ctx, it, st.Code, st.IDs)
		default:
			var hint int64
			if isStatus {
				hint = st.RetryAfter
			}
			s.st.Outbox().Retry(ctx, it.ID, s.retry.fail(it.Dest, t, hint))
		}
	}
}

// deliveryFailed tells the sender's devices about deliveries that will never arrive
// (stream event delivery-failed, SPEC §10.5).
// ids, if given, narrows it to the deliveries the refusal named.
func (s *Server) deliveryFailed(ctx context.Context, it store.OutboxItem, reason string, ids []wire.Bytes) {
	if it.Path != "deliver" {
		return
	}
	var body struct {
		Deliveries []delivery `json:"deliveries"`
	}
	if wire.Unmarshal(it.Body, &body) != nil {
		return
	}
	for _, d := range body.Deliveries {
		if len(ids) > 0 && !containsBytes(plain(ids), d.ID) {
			continue
		}
		if s.isLocal(ctx, d.From) {
			s.notify(ctx, d.From, map[string]any{"t": "delivery-failed", "id": d.ID, "to": d.To, "reason": reason})
		}
	}
}

// retryable reports whether a 4xx is temporary: 408 (timeout) and 429 (rate limited).
// Every other 4xx is a refusal (SPEC §10.5).
func retryable(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
}

// ---- S2S endpoints (spec/api/s2s-stage2.md) ----

// s2s wraps an S2S handler: verifies the signed request, then passes the sender and body.
func (s *Server) s2s(path string, h func(http.ResponseWriter, *http.Request, string, wire.Raw)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "")
			return
		}
		from, body, err := s.fed.Verify(r.Context(), raw, path)
		if err != nil {
			if e, ok := asSkew(err); ok {
				s.writeS2SClockSkew(w, e)
				return
			}
			writeError(w, http.StatusUnauthorized, wire.ErrCodeBadSignature, err.Error())
			return
		}
		s.log.Info("s2s in", "from", from, "path", path)
		h(w, r, from, body)
	}
}

func (s *Server) s2sIdentityFetch(w http.ResponseWriter, r *http.Request, _ string, body wire.Raw) {
	var req struct {
		ID string `json:"id"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	raw, err := s.st.Chains().Entries(r.Context(), req.ID, -1)
	cached := false
	if err != nil {
		// Not ours, but cached: answer with our copy, marked as such. It says where the
		// identity lives; the caller fetches it from there, and only that copy counts (SPEC
		// §6.5). A cached answer never vouches for a move. Group members on servers that
		// never met each other find each other this way.
		if _, c, cerr := s.st.Remote().Get(r.Context(), req.ID); cerr == nil {
			raw, err, cached = c, nil, true
		}
	}
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	entries := make([]wire.Raw, len(raw))
	for i, e := range raw {
		entries[i] = e
	}
	res := map[string]any{"entries": entries, "head": len(raw) - 1}
	if cached {
		res["cached"] = true
	}
	writeBody(w, http.StatusOK, res)
}

// remoteUser checks that an identity really lives on the server that's speaking for it (SPEC §9.2):
// its current home. A move's grace window doesn't count here (see remoteSender).
func (s *Server) remoteUser(ctx context.Context, id, from string) bool {
	return s.speaksFor(ctx, id, from, false)
}

// remoteSender is remoteUser for deliveries: the home an identity moved away from may still
// deliver for it for 72 hours, since it may have had deliveries queued (SPEC §6.6).
func (s *Server) remoteSender(ctx context.Context, id, from string) bool {
	return s.speaksFor(ctx, id, from, true)
}

func (s *Server) speaksFor(ctx context.Context, id, from string, grace bool) bool {
	_, raw, err := s.lookup(ctx, id, from)
	if err == nil && !fromHome(raw, from, now(), grace) {
		// The cache may be stale: re-fetch from the sender once.
		_, raw, err = s.fetchRemote(ctx, id, from, false)
	}
	return err == nil && fromHome(raw, from, now(), grace)
}

func (s *Server) s2sKeyPackageClaim(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		ID       string       `json:"id"`
		Claimant string       `json:"claimant"`
		Group    wire.Bytes   `json:"group,omitempty"`
		Devices  []wire.Bytes `json:"devices,omitempty"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if !s.remoteUser(r.Context(), req.Claimant, from) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "claimant doesn't live on the calling server")
		return
	}
	s.claimFor(w, r, req.ID, req.Claimant, from, req.Group, plain(req.Devices))
}

func (s *Server) s2sContactRequest(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Request wire.Raw   `json:"request"`
		Chain   []wire.Raw `json:"chain"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	raw := make([][]byte, len(req.Chain))
	for i, e := range req.Chain {
		raw[i] = e
	}
	// The requester's chain goes into the cache under the usual rules (SPEC §6.5), and the
	// request has to come from the requester's home.
	ids, err := decodeChain(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	st, accepted, _, err := s.acceptChain(r.Context(), ids.ID, raw, from)
	if err != nil || !fromHome(accepted, from, now(), false) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "requester's chain must name the calling server")
		return
	}
	sig, err := wire.DecodeSigned(req.Request)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	key, err := sig.VerifySelf("contact-request")
	if err != nil || !st.HasDevice(key) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var cr contactRequestBody
	if sig.OpenClosed(&cr) != nil || cr.From != st.ID {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	if s.isLocal(r.Context(), cr.To) {
		s.receiveContactRequest(r.Context(), cr, req.Request, req.Chain, from)
	}
	writeBody(w, http.StatusAccepted, map[string]any{}) // silent either way (SPEC §9.3)
}

func (s *Server) s2sDeliver(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Deliveries []delivery `json:"deliveries"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	var wrong []wire.Bytes
	for _, d := range req.Deliveries {
		if d.Kind != "mls" || !mlsKinds[d.MLS] {
			continue
		}
		// The sender has to live on the server delivering for it (SPEC §10.2).
		if !s.remoteSender(r.Context(), d.From, from) {
			if d.Ephemeral {
				continue // never refused out loud: it isn't retried anyway
			}
			s.log.Warn("refused a delivery from a user whose chain doesn't name the sender", "from", d.From, "server", from)
			wrong = append(wrong, d.ID)
			continue
		}
		if d.Ephemeral {
			s.deliverEphemeral(r.Context(), d, from, false)
			continue
		}
		s.deliverLocal(r.Context(), d, from)
	}
	if len(wrong) > 0 {
		// Not silent: it says nothing about the recipient, only that our copy of the
		// sender's chain is behind, which the sender needs to know (SPEC §10.2, §6.6).
		writeBody(w, http.StatusConflict, wire.Error{Code: wire.ErrCodeWrongHome, Msg: "the sender's chain here doesn't name your server as its home", IDs: wrong})
		return
	}
	writeBody(w, http.StatusAccepted, map[string]any{}) // allowlist drops stay silent
}

// ---- on-demand TLS (deployment helper, not protocol) ----

// tlsAsk answers a reverse proxy's on-demand TLS check: only this server's name
// and real handles get certificates, so nobody can burn the CA's rate limits with
// random subdomains. Caddy: on_demand_tls { ask http://127.0.0.1:PORT/v0/tls-ask }
func (s *Server) tlsAsk(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(r.URL.Query().Get("domain"))
	if domain == s.cfg.Name || slices.Contains(s.cfg.TLSAskAllow, domain) {
		w.WriteHeader(http.StatusOK)
		return
	}
	if _, err := s.st.Chains().ByHandle(r.Context(), domain); err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	// One proxy can only ask one URL, so instances on the same box consult each other.
	if r.URL.Query().Get("local") == "" {
		for _, base := range s.cfg.TLSAskAlso {
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, base+"/v0/tls-ask?local=1&domain="+url.QueryEscape(domain), nil)
			if resp, err := s.fed.HTTP.Do(req); err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

// ---- handle documents (SPEC §5.3) ----

// handleDoc serves GET /.well-known/tieroute/handle for local handles, chosen by Host.
func (s *Server) handleDoc(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	id, err := s.st.Chains().ByHandle(r.Context(), strings.ToLower(host))
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"id": id, "home": s.cfg.Name})
}
