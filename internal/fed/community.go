package fed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/version"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ErrTooLarge is a response over the cap the caller set.
var ErrTooLarge = errors.New("fed: response over the size cap")

// ErrNoCommunityAPI: the server's document lists no wire version 2 community API.
var ErrNoCommunityAPI = errors.New("fed: no community API")

// CommunityBase finds a community server's community API from its document: the `community`
// base of its wire version 2 entry (SPEC §5.1, §16.1), whichever version this Fed speaks.
func (f *Fed) CommunityBase(ctx context.Context, name string) (string, error) {
	d, err := f.ServerDoc(ctx, name)
	if err != nil {
		return "", err
	}
	for _, a := range d.APIs {
		if a.V != wire.V2 || a.Community == "" {
			continue
		}
		u, err := url.Parse(a.Community)
		_, dev := f.Peers[name]
		if err != nil || u.Host == "" || !strings.HasSuffix(u.Path, "/") || (u.Scheme != "https" && !(dev && u.Scheme == "http")) {
			return "", fmt.Errorf("%s publishes a bad community base %q", name, a.Community)
		}
		return a.Community, nil
	}
	return "", ErrNoCommunityAPI
}

// GetCommunity makes an unsigned GET to path under a community server's community API, and
// reads at most max bytes of a 200 answer (ErrTooLarge past that). Any other answer is an
// *ErrStatus. In dev mode, a peer's base URL takes the place of the document's host.
func (f *Fed) GetCommunity(ctx context.Context, name, path string, max int64) ([]byte, error) {
	base, err := f.CommunityBase(ctx, name)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(base + path)
	host := u.Host
	if peer, ok := f.Peers[name]; ok {
		if pu, err := url.Parse(peer); err == nil {
			u.Scheme, u.Host, host = pu.Scheme, pu.Host, name
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e wire.Error
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		wire.Unmarshal(b, &e)
		return nil, &ErrStatus{Status: resp.StatusCode, Code: e.Code, RetryAfter: int64(e.Retry)}
	}
	if resp.ContentLength > max {
		return nil, ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}
