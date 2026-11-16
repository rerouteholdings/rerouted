package fed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Other servers' documents, fetched and cached. Anyone can name a server, in an S2S
// request's "from" or a handle's home, before anything is authenticated, so what a name can
// cost is bounded: it must be a DNS name, a name is fetched once at a time, a failure is
// remembered for a moment, only so many are fetched at once, and the cache has a size.
const (
	// failTTL is how long a failed fetch is remembered, and answered with its error.
	failTTL = 10 * time.Second
	// maxFailed bounds the failures remembered.
	maxFailed = 4096
	// docFetches is how many documents every Fed together fetches at once.
	docFetches = 64
)

// maxDocBytes is how much of other servers' documents is cached, as fetched. Beyond it,
// those fetched longest ago go. (A variable for the tests.)
var maxDocBytes = 16 << 20

var docFetch = make(chan struct{}, docFetches)

var errBusy = errors.New("fed: too many server documents being fetched")

type cachedDoc struct {
	doc     Doc
	fetched time.Time
	size    int
}

type failedDoc struct {
	err   error
	until time.Time
}

// docFetch is a fetch under way, which later callers for the same name wait on.
type docFetching struct {
	done chan struct{}
	doc  Doc
	err  error
}

// ValidName reports whether name is a DNS host name, as a server's or a handle's must be
// (SPEC §5.1): labels of letters, digits, and hyphens, 253 bytes at most. No port, path,
// user, or IP literal: a name goes into a URL as it is.
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// A top-level label of digits only is an IPv4 address, or nothing.
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// ServerDoc fetches (and caches) another server's document. One that's about to expire
// is refreshed in the background, and the cached copy used meanwhile.
func (f *Fed) ServerDoc(ctx context.Context, name string) (Doc, error) {
	if !ValidName(name) {
		return Doc{}, fmt.Errorf("%q isn't a server name", name)
	}
	f.mu.Lock()
	if c, ok := f.docs[name]; ok {
		if age := time.Since(c.fetched); age < docTTL {
			f.mu.Unlock()
			if age >= docTTL-docRefresh {
				f.refreshDoc(name)
			}
			return c.doc, nil
		}
	}
	if fl, ok := f.failed[name]; ok {
		if time.Now().Before(fl.until) {
			f.mu.Unlock()
			return Doc{}, fl.err
		}
		delete(f.failed, name)
	}
	if call := f.fetching[name]; call != nil {
		f.mu.Unlock()
		select {
		case <-call.done:
			return call.doc, call.err
		case <-ctx.Done():
			return Doc{}, ctx.Err()
		}
	}
	call := &docFetching{done: make(chan struct{})}
	if f.fetching == nil {
		f.fetching = map[string]*docFetching{}
	}
	f.fetching[name] = call
	f.mu.Unlock()

	// Others may be waiting on this fetch: it doesn't end with this caller's request.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	call.doc, call.err = f.fetchDoc(fctx, name)
	cancel()
	f.mu.Lock()
	delete(f.fetching, name)
	if call.err != nil && !errors.Is(call.err, errBusy) {
		if f.failed == nil {
			f.failed = map[string]failedDoc{}
		}
		if len(f.failed) >= maxFailed {
			now := time.Now()
			for k, fl := range f.failed {
				if !now.Before(fl.until) {
					delete(f.failed, k)
				}
			}
			for k := range f.failed { // still full: any of them
				if len(f.failed) < maxFailed {
					break
				}
				delete(f.failed, k)
			}
		}
		f.failed[name] = failedDoc{err: call.err, until: time.Now().Add(failTTL)}
	}
	f.mu.Unlock()
	close(call.done)
	return call.doc, call.err
}

// refreshDoc fetches name's document in the background, unless that's already under way.
// If it fails, the cached copy stays until it expires, and is then fetched as usual.
func (f *Fed) refreshDoc(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refreshing[name] {
		return
	}
	if f.refreshing == nil {
		f.refreshing = map[string]bool{}
	}
	f.refreshing[name] = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		f.fetchDoc(ctx, name)
		f.mu.Lock()
		delete(f.refreshing, name)
		f.mu.Unlock()
	}()
}

func (f *Fed) fetchDoc(ctx context.Context, name string) (Doc, error) {
	select {
	case docFetch <- struct{}{}:
		defer func() { <-docFetch }()
	default:
		return Doc{}, errBusy
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
	if f.docs == nil {
		f.docs = map[string]cachedDoc{}
	}
	f.docBytes += len(b) - f.docs[name].size
	f.docs[name] = cachedDoc{doc: d, fetched: time.Now(), size: len(b)}
	for f.docBytes > maxDocBytes {
		oldest, at := "", time.Time{}
		for k, c := range f.docs {
			if k != name && (oldest == "" || c.fetched.Before(at)) {
				oldest, at = k, c.fetched
			}
		}
		if oldest == "" {
			break
		}
		f.docBytes -= f.docs[oldest].size
		delete(f.docs, oldest)
	}
	f.mu.Unlock()
	return d, nil
}
