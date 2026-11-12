// Package fed is rerouted's side of server-to-server federation (SPEC §5, §8.3):
// finding other servers, signing and verifying S2S requests, and resolving handles.
package fed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

const (
	MaxSkew  = 5 * 60  // seconds; S2S requests (SPEC §8.3)
	NonceTTL = 10 * 60 // seconds
	docTTL   = time.Hour
)

// Fed holds what federation needs: who we are, and how to reach everyone else.
type Fed struct {
	Name string
	Key  serverkey.Key
	// Peers maps a server name to a base URL, overriding https://{name}.
	// Dev mode only: it lets servers federate over http on localhost (SPEC §5.1).
	Peers map[string]string
	HTTP  *http.Client
	// LookupTXT reads DNS TXT records, one string per record. Nil means the system resolver.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// OnClock, if set, hears how far a peer's clock is from ours, in seconds (theirs minus
	// ours), whenever a peer answers: from its Date header, or from the `now` in a
	// clock-skew refusal (refused = true). The operator is told from there (SPEC §8.4).
	OnClock func(peer string, offset int64, refused bool)

	mu     sync.Mutex
	docs   map[string]cachedDoc
	nonces map[string]int64
}

type cachedDoc struct {
	doc     Doc
	fetched time.Time
}

// Doc is the part of a server document (SPEC §5.1) federation uses.
type Doc struct {
	Name string `json:"name"`
	APIs []struct {
		V      uint   `json:"v"`
		Client string `json:"client,omitempty"`
		S2S    string `json:"s2s"`
	} `json:"apis"`
	Keys []struct {
		KID string     `json:"kid"`
		Pub wire.Bytes `json:"pub"`
		NBF int64      `json:"nbf"`
		EXP int64      `json:"exp"`
	} `json:"keys"`
}

// Version is the wire version rerouted speaks (SPEC §19.1).
const Version = 1

// S2SBase finds a server's S2S API from its document: follow your nose (SPEC §8.1).
func (f *Fed) S2SBase(ctx context.Context, name string) (string, error) {
	d, err := f.ServerDoc(ctx, name)
	if err != nil {
		return "", err
	}
	for _, a := range d.APIs {
		if a.V != Version {
			continue
		}
		u, err := url.Parse(a.S2S)
		dev := false
		if _, ok := f.Peers[name]; ok {
			dev = true // dev peers may use plain http (SPEC §5.1)
		}
		if err != nil || u.Host == "" || !strings.HasSuffix(u.Path, "/") || (u.Scheme != "https" && !(dev && u.Scheme == "http")) {
			return "", fmt.Errorf("%s publishes a bad s2s base %q", name, a.S2S)
		}
		return a.S2S, nil
	}
	return "", fmt.Errorf("%s doesn't speak wire version %d", name, Version)
}

func New(name string, key serverkey.Key, peers map[string]string) *Fed {
	return &Fed{
		Name: name, Key: key, Peers: peers,
		HTTP: &http.Client{Timeout: 15 * time.Second},
		docs: map[string]cachedDoc{}, nonces: map[string]int64{},
	}
}

// base returns the URL prefix for a server or handle domain.
func (f *Fed) base(name string) (url, host string) {
	if u, ok := f.Peers[name]; ok {
		return u, name
	}
	// Dev mode: a handle like kat.a.test is served by the peer a.test.
	for peer, u := range f.Peers {
		if strings.HasSuffix(name, "."+peer) {
			return u, name
		}
	}
	return "https://" + name, name
}

func (f *Fed) get(ctx context.Context, name, path string) ([]byte, error) {
	base, host := f.base(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s%s: %s", name, path, resp.Status)
	}
	return b, nil
}

// ServerDoc fetches (and caches) another server's document.
func (f *Fed) ServerDoc(ctx context.Context, name string) (Doc, error) {
	f.mu.Lock()
	c, ok := f.docs[name]
	f.mu.Unlock()
	if ok && time.Since(c.fetched) < docTTL {
		return c.doc, nil
	}
	b, err := f.get(ctx, name, "/.well-known/tieroute/server")
	if err != nil {
		return Doc{}, err
	}
	var d Doc
	if err := wire.Unmarshal(b, &d); err != nil {
		return Doc{}, err
	}
	if d.Name != name {
		return Doc{}, fmt.Errorf("server document for %s names %q", name, d.Name)
	}
	f.mu.Lock()
	f.docs[name] = cachedDoc{doc: d, fetched: time.Now()}
	f.mu.Unlock()
	return d, nil
}

// KeyFor finds a server's public key by key ID, valid at time t.
func (f *Fed) KeyFor(ctx context.Context, server, kid string, t int64) (ed25519.PublicKey, error) {
	d, err := f.ServerDoc(ctx, server)
	if err != nil {
		return nil, err
	}
	for _, k := range d.Keys {
		if k.KID == kid && t >= k.NBF && t <= k.EXP && len(k.Pub) == ed25519.PublicKeySize {
			return ed25519.PublicKey(k.Pub), nil
		}
	}
	return nil, fmt.Errorf("%s has no valid key %q", server, kid)
}

// s2sRequest is the signed body of every S2S call (SPEC §8.3).
type s2sRequest struct {
	From  string     `json:"from"`
	To    string     `json:"to"`
	Path  string     `json:"path"`
	TS    int64      `json:"ts"`
	Nonce wire.Bytes `json:"nonce"`
	Body  wire.Raw   `json:"body"`
}

// ErrStatus is a non-2xx answer from a peer.
type ErrStatus struct {
	Status     int
	Code       string
	RetryAfter int64        // seconds to wait, from the error's "retry" (0 if none)
	IDs        []wire.Bytes // the deliveries the error is about, if it says
	Now        int64        // the peer's clock, with clock-skew (0 if it didn't say)
}

// SkewError is an incoming request dated too far from our clock (SPEC §8.3, §8.4).
type SkewError struct {
	From    string // who the request says it's from (not verified: the check stops here)
	TS, Now int64
}

func (e *SkewError) Error() string { return "clock-skew" }

func (e *ErrStatus) Error() string { return fmt.Sprintf("s2s: %d %s", e.Status, e.Code) }

// Call makes a signed S2S request. body is the endpoint's JSON body (already encoded).
func (f *Fed) Call(ctx context.Context, dest, path string, body []byte) ([]byte, error) {
	_, b, err := f.Fetch(ctx, dest, path, body)
	return b, err
}

// MaxResponse is the largest S2S response read: a 64 MiB file plus its tag (SPEC §14).
const MaxResponse = 64<<20 + 1024

// Fetch is Call, also returning the response's content type, for media/fetch, whose
// answer is raw bytes rather than JSON.
func (f *Fed) Fetch(ctx context.Context, dest, path string, body []byte) (string, []byte, error) {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	sig, err := wire.SignKID("s2s", s2sRequest{From: f.Name, To: dest, Path: path, TS: time.Now().Unix(), Nonce: nonce, Body: body}, f.Key.Priv, f.Key.KID)
	if err != nil {
		return "", nil, err
	}
	enc, err := sig.Encode()
	if err != nil {
		return "", nil, err
	}
	base, err := f.S2SBase(ctx, dest)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(enc))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", wire.MediaType)
	sent := time.Now()
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	f.noteDate(dest, resp.Header.Get("Date"), sent, time.Now())
	b, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
	if resp.StatusCode/100 != 2 {
		var e wire.Error
		wire.Unmarshal(b, &e)
		if e.Code == wire.ErrCodeClockSkew && e.Now > 0 && f.OnClock != nil {
			f.OnClock(dest, e.Now-time.Now().Unix(), true)
		}
		// The delay is the error body's "retry" (spec/api/conventions.md); accept a
		// Retry-After header too, from proxies in front of the peer.
		retry := int64(e.Retry)
		if h, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64); err == nil && h > retry {
			retry = h
		}
		return "", nil, &ErrStatus{Status: resp.StatusCode, Code: e.Code, RetryAfter: retry, IDs: e.IDs, Now: e.Now}
	}
	return resp.Header.Get("Content-Type"), b, nil
}

// noteDate passes on a peer's clock offset from its response's Date header, measured
// against the middle of the round trip. Date has whole seconds, so differences under a
// minute aren't worth reporting, and the hook only hears about bigger ones.
func (f *Fed) noteDate(peer, date string, sent, got time.Time) {
	if f.OnClock == nil || date == "" {
		return
	}
	t, err := http.ParseTime(date)
	if err != nil {
		return
	}
	mid := sent.Add(got.Sub(sent) / 2)
	if off := int64(t.Sub(mid).Round(time.Second) / time.Second); off > 60 || off < -60 {
		f.OnClock(peer, off, false)
	}
}

// Verify checks an incoming S2S request (SPEC §8.3) and returns the sender and the endpoint body.
func (f *Fed) Verify(ctx context.Context, raw []byte, path string) (from string, body wire.Raw, err error) {
	sig, err := wire.DecodeSigned(raw)
	if err != nil || sig.T != "s2s" {
		return "", nil, errors.New("not a signed s2s request")
	}
	kid, ok := sig.KeyID()
	if !ok {
		return "", nil, errors.New("s2s request must name a server key")
	}
	var req s2sRequest
	if err := sig.OpenClosed(&req); err != nil {
		return "", nil, err
	}
	now := time.Now().Unix()
	switch {
	case req.To != f.Name:
		return "", nil, fmt.Errorf("request is for %q", req.To)
	case req.Path != path:
		return "", nil, fmt.Errorf("request is for path %q", req.Path)
	case req.TS > now+MaxSkew || req.TS < now-MaxSkew:
		return "", nil, &SkewError{From: req.From, TS: req.TS, Now: now}
	case len(req.Nonce) != 16:
		return "", nil, errors.New("bad nonce")
	}
	pub, err := f.KeyFor(ctx, req.From, kid, req.TS)
	if err != nil {
		return "", nil, err
	}
	if err := sig.Verify("s2s", pub); err != nil {
		return "", nil, err
	}
	key := req.From + "|" + string(wire.HexBytes(req.Nonce))
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, exp := range f.nonces {
		if exp < now {
			delete(f.nonces, k)
		}
	}
	if _, seen := f.nonces[key]; seen {
		return "", nil, errors.New("replayed nonce")
	}
	f.nonces[key] = now + NonceTTL
	return req.From, req.Body, nil
}

// HandleDoc is what a handle resolves to (SPEC §5.3).
type HandleDoc struct {
	ID   string `json:"id"`
	Home string `json:"home"`
}

// ResolveHandle fetches the HTTPS handle document. DNS TXT records aren't used: without
// DNSSEC validation they can be spoofed, and Go's resolver doesn't validate (SPEC §5.3).
func (f *Fed) ResolveHandle(ctx context.Context, handle string) (HandleDoc, error) {
	// The HTTPS document first: if it can be fetched, it decides (SPEC §5.3).
	b, err := f.get(ctx, handle, "/.well-known/tieroute/handle")
	if err == nil {
		var d HandleDoc
		if err := wire.Unmarshal(b, &d); err != nil || !wire.ValidIdentityID(d.ID) || d.Home == "" {
			return HandleDoc{}, errors.New("bad handle document")
		}
		return d, nil
	}
	// No document: the DNS record. Plain DNS is accepted without DNSSEC, a risk SPEC §18.1 lists.
	d, dnsErr := f.resolveTXT(ctx, handle)
	if dnsErr != nil {
		return HandleDoc{}, fmt.Errorf("no handle document (%v), and no DNS record (%v)", err, dnsErr)
	}
	return d, nil
}

// resolveTXT reads the handle's DNS record, _tieroute.{handle} (SPEC §5.3): space-separated
// key=value pairs with id and home, unknown keys ignored. Records that disagree don't resolve.
func (f *Fed) resolveTXT(ctx context.Context, handle string) (HandleDoc, error) {
	lookup := f.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	recs, err := lookup(ctx, "_tieroute."+handle)
	if err != nil {
		return HandleDoc{}, err
	}
	var found *HandleDoc
	for _, r := range recs {
		var d HandleDoc
		for _, kv := range strings.Fields(r) {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch k {
			case "id":
				d.ID = v
			case "home":
				d.Home = v
			}
		}
		if d.ID == "" {
			continue // some other TXT record at that name
		}
		if !wire.ValidIdentityID(d.ID) || d.Home == "" {
			return HandleDoc{}, errors.New("bad handle record")
		}
		if found != nil && *found != d {
			return HandleDoc{}, errors.New("handle records disagree")
		}
		found = &d
	}
	if found == nil {
		return HandleDoc{}, errors.New("no handle record")
	}
	return *found, nil
}
