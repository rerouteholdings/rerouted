package fed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Federation makes requests to names other people choose: the sender an S2S request
// claims, a server in a file reference or an emoji, an API base in someone's server
// document. Nothing here may become a way to reach the server's own network. So outside
// dev mode, a name must be a server name (a DNS name, never an IP address or a port; SPEC
// §5.1), API bases must name their host by DNS name, redirects aren't followed, and the
// transport refuses to connect to an address that isn't public, whatever name led to it.

// errNotServerName is a name federation won't contact.
var errNotServerName = errors.New("fed: not a server name")

// dev reports whether name is reached through a dev-mode peer (SPEC §5.1).
func (f *Fed) dev(name string) bool {
	if _, ok := f.Peers[name]; ok {
		return true
	}
	for peer := range f.Peers {
		if strings.HasSuffix(name, "."+peer) {
			return true
		}
	}
	return false
}

// checkName refuses a name federation must not contact.
func (f *Fed) checkName(name string) error {
	if f.dev(name) || wire.ValidServerName(name) {
		return nil
	}
	return fmt.Errorf("%w: %q", errNotServerName, name)
}

// checkBase checks an API base URL from name's server document (SPEC §8.1): absolute
// https, ending in /, and naming its host by DNS name. Dev-mode peers may use plain http
// and local addresses.
func (f *Fed) checkBase(name, base string) error {
	_, dev := f.Peers[name]
	u, err := url.Parse(base)
	ok := err == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		strings.HasSuffix(u.Path, "/") && (u.Scheme == "https" || dev && u.Scheme == "http") &&
		(dev || wire.ValidServerName(strings.ToLower(u.Hostname())))
	if !ok {
		return fmt.Errorf("%s publishes a bad API base %q", name, base)
	}
	return nil
}

// noRedirects stops the client at a redirect: its answer is returned as it is, and isn't
// a 200 or a 2xx, so callers treat it as a failure.
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// publicDialer returns a DialContext that connects only to public addresses. The check is
// on the address actually dialed, after DNS, so a name that resolves (or re-resolves) to
// an internal address is refused too. The proxy named by HTTPS_PROXY or HTTP_PROXY is
// dialed without the check: it's the operator's own, and where it connects is its call.
// While dev reports true (nil means never), every address is allowed.
func publicDialer(dev func() bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	plain := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	checked := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseInternal}
	proxies := proxyAddrs()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if proxies[addr] || dev != nil && dev() {
			return plain.DialContext(ctx, network, addr)
		}
		return checked.DialContext(ctx, network, addr)
	}
}

// errInternal is an outbound connection to an address that isn't public.
var errInternal = errors.New("fed: refusing to connect to a non-public address")

func refuseInternal(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !publicAddr(ap.Addr()) {
		return fmt.Errorf("%w %s", errInternal, address)
	}
	return nil
}

// notPublic lists special-use ranges (RFC 6890 and its updates) that netip's own tests
// don't already cover.
var notPublic = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "fec0::/10",
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96") // RFC 6052: the IPv4 address is the last 4 bytes
	sixTo4 = netip.MustParsePrefix("2002::/16")    // RFC 3056: the IPv4 address is bytes 2 to 5
)

// publicAddr reports whether a is a public unicast address. One that embeds an IPv4
// address (mapped, NAT64, 6to4) counts as that IPv4 address.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:16]))
	} else if sixTo4.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[2:6]))
	}
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.Zone() != "" {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// proxyAddrs is the host:port of each proxy the environment names, as the transport dials it.
func proxyAddrs() map[string]bool {
	m := map[string]bool{}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		if !strings.Contains(v, "://") {
			v = "http://" + v
		}
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" {
			continue
		}
		port := u.Port()
		if port == "" {
			switch u.Scheme {
			case "https":
				port = "443"
			case "socks5", "socks5h":
				port = "1080"
			default:
				port = "80"
			}
		}
		m[net.JoinHostPort(u.Hostname(), port)] = true
	}
	return m
}
