package fed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// notPublic are networks that aren't private (netip.Addr.IsPrivate) or otherwise
// non-global, but aren't another server on the internet either.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this network"
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT, and overlay networks
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved, and broadcast
}

// nat64 is the well-known NAT64 prefix (RFC 6052): its addresses stand for the IPv4
// address in their last 32 bits, which is what decides.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// ErrNotPublic is a connection refused because its address isn't on the public internet.
var ErrNotPublic = errors.New("not a public address")

// PublicOnly limits f to servers on the public internet, except for the networks in
// allow: a connection to a loopback, link-local (cloud metadata services among them),
// private, or other non-global address is refused when it's made, after DNS, so a name
// that resolves there, or a redirect that points there, can't reach this host's or its
// network's internal services (server-side request forgery). Redirects must stay on
// https. Outside dev mode only: dev peers are local by design.
func (f *Fed) PublicOnly(allow []netip.Prefix) {
	t, ok := f.HTTP.Transport.(*http.Transport)
	if !ok {
		return
	}
	t = t.Clone()
	// As http.DefaultTransport's dialer, with the check added.
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: guard(allow)}
	t.DialContext = d.DialContext
	c := *f.HTTP
	c.Transport = t
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to %s://%s: only https is followed", req.URL.Scheme, req.URL.Host)
		}
		return nil
	}
	f.HTTP = &c
}

// Through sends f's connections and DNS TXT lookups through dial and txt: rerouted-egress's
// (internal/egress), when rerouted runs without a network. rerouted-egress checks each
// address as PublicOnly would, under its own settings. After PublicOnly, redirects still
// stay on https.
func (f *Fed) Through(dial func(ctx context.Context, network, addr string) (net.Conn, error), txt func(ctx context.Context, name string) ([]string, error)) {
	if t, ok := f.HTTP.Transport.(*http.Transport); ok {
		t = t.Clone()
		t.DialContext, t.Proxy = dial, nil
		c := *f.HTTP
		c.Transport = t
		f.HTTP = &c
	}
	f.LookupTXT = txt
}

// guard is a net.Dialer Control function that refuses addresses PublicAddr rejects.
func guard(allow []netip.Prefix) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("connect %s: %w", address, ErrNotPublic)
		}
		if !PublicAddr(ap.Addr(), allow) {
			return fmt.Errorf("connect %s: %w (REROUTED_FED_ALLOW can permit it)", address, ErrNotPublic)
		}
		return nil
	}
}

// PublicAddr reports whether a is a global unicast address outside the private and
// special-purpose networks, or in one of the allow networks.
func PublicAddr(a netip.Addr, allow []netip.Prefix) bool {
	a = a.Unmap().WithZone("")
	for _, p := range allow {
		if p.Contains(a) {
			return true
		}
	}
	if nat64.Contains(a) {
		b := a.As16()
		return PublicAddr(netip.AddrFrom4([4]byte(b[12:])), allow)
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
