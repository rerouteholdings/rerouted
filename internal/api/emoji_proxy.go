package api

import (
	"container/list"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// GET emoji/{server}/{id} (SPEC §12.2, client API): a custom emoji's encrypted blob, fetched
// from the community server on the client's behalf, so the community server never sees the
// client's address. The fetch is a plain GET of the community API's public emoji/{id}, not
// S2S: a server that's only a community server serves no S2S. The client checks the hash and
// decrypts with the key from the message; this server can't, and doesn't try.
//
// The spec's SHOULD cache: blobs are kept in memory for 24 hours, at most 64 MiB in all, and
// a 404 or 410 for 10 minutes. Its MUSTs: answers over 262,160 bytes are refused, and fetches
// are rate-limited per identity and per community server.

const (
	emojiCacheBytes    = 64 << 20
	emojiCacheTTL      = 24 * time.Hour
	emojiMissTTL       = 10 * time.Minute
	emojiProxyPerID    = 3600 // requests per identity per hour
	emojiProxyPerDest  = 1800 // fetches per community server per hour
	emojiProxyMaxBytes = maxEmojiBlob
)

type emojiEntry struct {
	key     string
	data    []byte // nil for a remembered 404 or 410
	status  int
	expires time.Time
}

// emojiCache is a byte-capped LRU of fetched emoji, shared by both wire versions.
type emojiCache struct {
	mu    sync.Mutex
	ll    *list.List
	m     map[string]*list.Element
	bytes int
}

func newEmojiCache() *emojiCache {
	return &emojiCache{ll: list.New(), m: map[string]*list.Element{}}
}

func (c *emojiCache) get(key string) (*emojiEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*emojiEntry)
	if time.Now().After(e.expires) {
		c.remove(el)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e, true
}

func (c *emojiCache) put(e *emojiEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[e.key]; ok {
		c.remove(el)
	}
	c.m[e.key] = c.ll.PushFront(e)
	c.bytes += len(e.data)
	for c.bytes > emojiCacheBytes {
		c.remove(c.ll.Back())
	}
}

func (c *emojiCache) remove(el *list.Element) {
	e := el.Value.(*emojiEntry)
	c.ll.Remove(el)
	delete(c.m, e.key)
	c.bytes -= len(e.data)
}

func (s *Server) emojiProxy(w http.ResponseWriter, r *http.Request, sess session) {
	server := r.PathValue("server")
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 16 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "id must be 16 bytes of base64url")
		return
	}
	t := now()
	key := "emoji-proxy|" + sess.id
	if !s.limits.allow(key, emojiProxyPerID, 3600, t, true) {
		rateLimited(w, uint64(s.limits.retryAfter(key, 3600, t)))
		return
	}
	// A community this process hosts is read from storage.
	if comm := s.legacy().comm; comm != nil {
		if c := comm.byName[server]; c != nil {
			status, code, data := c.emojiBlob(r.Context(), id)
			switch status {
			case http.StatusOK:
				writeEmoji(w, data, "private, max-age=86400")
			case http.StatusServiceUnavailable:
				s.unavailableRead(w, "reading an emoji", errors.New(code))
			default:
				writeError(w, status, code, "")
			}
			return
		}
	}
	cache := s.legacy().emoji
	ck := server + "|" + string(id)
	if e, ok := cache.get(ck); ok {
		if e.data != nil {
			writeEmoji(w, e.data, "private, max-age=86400")
		} else {
			writeError(w, e.status, codeFor(e.status), "")
		}
		return
	}
	dk := "emoji-proxy-dest|" + server
	if !s.limits.allow(dk, emojiProxyPerDest, 3600, t, true) {
		rateLimited(w, uint64(s.limits.retryAfter(dk, 3600, t)))
		return
	}
	data, err := s.fed.GetCommunity(r.Context(), server, "emoji/"+base64.RawURLEncoding.EncodeToString(id), emojiProxyMaxBytes)
	var es *fed.ErrStatus
	switch {
	case err == nil:
		cache.put(&emojiEntry{key: ck, data: data, status: http.StatusOK, expires: time.Now().Add(emojiCacheTTL)})
		writeEmoji(w, data, "private, max-age=86400")
	case errors.Is(err, fed.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "the community server's answer is over 262160 bytes")
	case errors.Is(err, fed.ErrNoCommunityAPI):
		cache.put(&emojiEntry{key: ck, status: http.StatusNotFound, expires: time.Now().Add(emojiMissTTL)})
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, server+" isn't a community server")
	case errors.As(err, &es) && (es.Status == http.StatusNotFound || es.Status == http.StatusGone):
		cache.put(&emojiEntry{key: ck, status: es.Status, expires: time.Now().Add(emojiMissTTL)})
		writeError(w, es.Status, codeFor(es.Status), "")
	default:
		writeBody(w, http.StatusServiceUnavailable, wire.Error{Code: wire.ErrCodeUnavailable, Msg: "the community server can't be reached", Retry: 60})
	}
}

func codeFor(status int) string {
	if status == http.StatusGone {
		return wire.ErrCodeExpired
	}
	return wire.ErrCodeNotFound
}
