// Package egress makes rerouted's connections out for it, in rerouted-egress, so rerouted
// itself can run without a network (REROUTED_EGRESS): federation's HTTPS, the other local
// instances REROUTED_TLS_ASK_ALSO asks, and DNS TXT lookups.
//
// rerouted connects to rerouted-egress's unix socket and sends one request: connect, with
// a host and port, or txt, with a name. For connect, rerouted-egress resolves the host
// itself, connects where its own policy allows, answers, and from then on copies bytes both
// ways: TLS is between rerouted and the other server, end to end. The policy is
// rerouted-egress's, from the operator's settings, never rerouted's to change: public
// addresses (fed.PublicAddr), the networks in REROUTED_FED_ALLOW, and exactly the hosts and
// ports REROUTED_TLS_ASK_ALSO lists. A compromised rerouted can't reach anything else
// through it.
package egress

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/ipc"
)

const maxMessage = 64 << 10

type request struct {
	Op   string `json:"op"` // connect or txt
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	Name string `json:"name,omitempty"`
}

type response struct {
	Err string   `json:"err,omitempty"`
	TXT []string `json:"txt,omitempty"`
}

// Policy is where rerouted-egress connects.
type Policy struct {
	// Allow: networks reachable although they aren't public (REROUTED_FED_ALLOW).
	Allow []netip.Prefix
	// Local: host:port pairs reachable whatever their address (REROUTED_TLS_ASK_ALSO).
	Local map[string]bool
}

// LocalFrom makes Policy.Local from REROUTED_TLS_ASK_ALSO's base URLs.
func LocalFrom(urls []string) map[string]bool {
	m := map[string]bool{}
	for _, u := range urls {
		p, err := url.Parse(u)
		if err != nil || p.Host == "" {
			continue
		}
		port := p.Port()
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[p.Scheme]
		}
		m[net.JoinHostPort(p.Hostname(), port)] = true
	}
	return m
}

// Server is rerouted-egress.
type Server struct {
	Policy Policy
	// UID, unless -1, is the only user that may connect (SO_PEERCRED).
	UID int
	Log *slog.Logger
	// Resolver resolves names and TXT records. Nil is the system's.
	Resolver *net.Resolver
}

// Serve answers connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			s.Log.Warn("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.serve(c)
	}
}

func (s *Server) resolver() *net.Resolver {
	if s.Resolver != nil {
		return s.Resolver
	}
	return net.DefaultResolver
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	if s.UID != -1 {
		uid, err := ipc.PeerUID(c)
		if err != nil || uid != s.UID {
			s.Log.Warn("refused a connection from another user", "uid", uid, "err", err)
			return
		}
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var req request
	if err := ipc.Read(c, &req, maxMessage); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch req.Op {
	case "txt":
		// The one record rerouted reads is a handle's, _tieroute.{handle} (SPEC §5.3):
		// lookups of other names would be a way to send anything out, a query at a time.
		handle, ok := strings.CutPrefix(req.Name, "_tieroute.")
		if !ok || !fed.ValidName(handle) {
			s.Log.Warn("refused a lookup", "name", req.Name)
			ipc.Write(c, response{Err: "egress: only _tieroute.{handle} is looked up"}, maxMessage)
			return
		}
		txt, err := s.resolver().LookupTXT(ctx, req.Name)
		if err != nil {
			ipc.Write(c, response{Err: err.Error()}, maxMessage)
			return
		}
		ipc.Write(c, response{TXT: txt}, maxMessage)
	case "connect":
		out, err := s.dial(ctx, req.Host, req.Port)
		if err != nil {
			s.Log.Info("refused a connection", "host", req.Host, "port", req.Port, "err", err)
			ipc.Write(c, response{Err: err.Error()}, maxMessage)
			return
		}
		defer out.Close()
		if ipc.Write(c, response{}, maxMessage) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		splice(c, out)
	default:
		ipc.Write(c, response{Err: "no such op"}, maxMessage)
	}
}

// dial connects to host:port as the policy allows: an address is checked as it's dialed,
// so a name can't resolve to one address when checked and another when used.
func (s *Server) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if _, err := netip.ParseAddr(host); (err != nil && !fed.ValidName(host)) || port <= 0 || port > 65535 {
		return nil, errors.New("egress: bad host or port")
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Resolver: s.resolver()}
	if !s.Policy.Local[addr] {
		allow := s.Policy.Allow
		d.Control = func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if !fed.PublicAddr(ap.Addr(), allow) {
				return errors.New("egress: " + ap.Addr().String() + " isn't a public address (REROUTED_FED_ALLOW can permit it)")
			}
			return nil
		}
	}
	return d.DialContext(ctx, "tcp", addr)
}

// splice copies both ways until either side is done.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		// Half-close where the socket can, so the other direction finishes; otherwise end both.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
