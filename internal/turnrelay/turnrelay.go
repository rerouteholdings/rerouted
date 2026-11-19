// Package turnrelay is rerouted's built-in call relay: a TURN server (RFC 8656) that takes
// the same time-limited credentials GET turn hands out (SPEC §15.1), so a homeserver can
// relay its users' calls without running coturn beside it.
//
// It listens on UDP and TCP, relays media over UDP only, never relays to private,
// loopback, link-local, or other non-public addresses, and caps allocations per user and
// in total. It has no TLS: it never serves turns: URLs.
package turnrelay

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// Limits on allocations, as deploy/turnserver.conf.example sets for coturn.
const (
	UserQuota  = 12  // allocations at once per user
	TotalQuota = 200 // allocations at once in all
)

// Config sets up a Relay.
type Config struct {
	Listen           string // UDP and TCP address, such as ":3478"
	PublicIP         net.IP // the address clients reach relayed media at
	MinPort, MaxPort int    // the UDP ports relayed media uses
	Realm            string // the server's name
	// Secret returns the shared secret credentials are signed with. It's asked on each
	// request, so a reload can change it.
	Secret func() string
	Log    *slog.Logger
	// AllowLoopback lets tests relay to loopback addresses. Never set it otherwise.
	AllowLoopback bool
}

// Relay is a running relay.
type Relay struct {
	srv *turn.Server
	udp net.PacketConn
	tcp net.Listener

	mu    sync.Mutex
	users map[string]int // allocations by user
}

// Start starts the relay.
func Start(cfg Config) (*Relay, error) {
	if cfg.PublicIP == nil {
		return nil, errors.New("turn relay: no public IP address")
	}
	if cfg.MinPort < 1 || cfg.MaxPort > 65535 || cfg.MinPort > cfg.MaxPort {
		return nil, errors.New("turn relay: bad relay port range")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	r := &Relay{users: map[string]int{}}
	var err error
	if r.udp, err = net.ListenPacket("udp", cfg.Listen); err != nil {
		return nil, fmt.Errorf("turn relay: %w", err)
	}
	if r.tcp, err = net.Listen("tcp", cfg.Listen); err != nil {
		r.udp.Close()
		return nil, fmt.Errorf("turn relay: %w", err)
	}
	bind := "0.0.0.0"
	if cfg.PublicIP.To4() == nil {
		bind = "::"
	}
	permit := func(_ net.Addr, ip net.IP) bool { return Allowed(ip, cfg.AllowLoopback) }
	gen := func() turn.RelayAddressGenerator {
		return &relayGen{
			RelayAddressGeneratorPortRange: turn.RelayAddressGeneratorPortRange{
				RelayAddress: cfg.PublicIP, Address: bind, MinPort: uint16(cfg.MinPort), MaxPort: uint16(cfg.MaxPort),
			},
			cfg: cfg,
		}
	}
	r.srv, err = turn.NewServer(turn.ServerConfig{
		Realm:             cfg.Realm,
		AuthHandler:       authHandler(cfg.Secret, cfg.Log),
		QuotaHandler:      r.quota,
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: r.udp, RelayAddressGenerator: gen(), PermissionHandler: permit}},
		ListenerConfigs:   []turn.ListenerConfig{{Listener: r.tcp, RelayAddressGenerator: gen(), PermissionHandler: permit}},
		LoggerFactory:     pionLogs{cfg.Log},
		EventHandler: turn.EventHandler{
			OnAllocationCreated: func(_, _ net.Addr, _, user, _ string, _ net.Addr, _ int) {
				r.mu.Lock()
				r.users[user]++
				r.mu.Unlock()
			},
			OnAllocationDeleted: func(_, _ net.Addr, _, user, _ string) {
				r.mu.Lock()
				if r.users[user]--; r.users[user] <= 0 {
					delete(r.users, user)
				}
				r.mu.Unlock()
			},
		},
	})
	if err != nil {
		r.udp.Close()
		r.tcp.Close()
		return nil, fmt.Errorf("turn relay: %w", err)
	}
	return r, nil
}

// Close stops the relay and ends every allocation.
func (r *Relay) Close() error { return r.srv.Close() }

// Allocations is how many allocations are open.
func (r *Relay) Allocations() int { return r.srv.AllocationCount() }

// Addr is the UDP address the relay listens on.
func (r *Relay) Addr() net.Addr { return r.udp.LocalAddr() }

func (r *Relay) quota(user, _ string, _ net.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, n := range r.users {
		total += n
	}
	return r.users[user] < UserQuota && total < TotalQuota
}

// Credential is the password for a TURN REST username ("expiry:user"): the HMAC-SHA1 of the
// username under the shared secret, in base64. GET turn hands out the same.
func Credential(secret, username string) string {
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// authHandler checks TURN REST credentials: a username "expiry:user" whose expiry, in Unix
// seconds, hasn't passed, and the password Credential gives it.
func authHandler(secret func() string, log *slog.Logger) turn.AuthHandler {
	return func(ra *turn.RequestAttributes) (string, []byte, bool) {
		user, key, ok := checkUser(ra.Username, ra.Realm, secret(), time.Now())
		if !ok {
			log.Debug("turn relay: refused credentials", "from", ra.SrcAddr)
		}
		return user, key, ok
	}
}

func checkUser(username, realm, secret string, now time.Time) (string, []byte, bool) {
	exp, user, ok := strings.Cut(username, ":")
	if !ok || user == "" || secret == "" {
		return "", nil, false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || t < now.Unix() {
		return "", nil, false
	}
	return user, turn.GenerateAuthKey(username, realm, Credential(secret, username)), true
}

// denied are the networks the relay never sends to: as deploy/turnserver.conf.example
// lists for coturn, plus multicast, broadcast, and reserved ranges.
var denied = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
		"fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// Allowed reports whether the relay may send to ip: only to public unicast addresses.
// loopback lets tests use 127.0.0.1.
func Allowed(ip net.IP, loopback bool) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if loopback && a.IsLoopback() {
		return true
	}
	for _, p := range denied {
		if p.Contains(a) {
			return false
		}
	}
	return a.IsGlobalUnicast()
}

// relayGen makes UDP relay sockets in the port range, and refuses TCP relaying (RFC 6062):
// calls only need UDP, and TCP would let a caller open connections to services.
type relayGen struct {
	turn.RelayAddressGeneratorPortRange
	cfg Config
}

var errNoTCP = errors.New("turn relay: no TCP relaying")

func (g *relayGen) AllocatePacketConn(c turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	conn, addr, err := g.RelayAddressGeneratorPortRange.AllocatePacketConn(c)
	if err != nil {
		return nil, nil, err
	}
	return &guardedConn{PacketConn: conn, cfg: g.cfg}, addr, nil
}

func (g *relayGen) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errNoTCP
}

func (g *relayGen) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) { return nil, errNoTCP }

// guardedConn is a relay socket that drops packets to addresses the relay mustn't reach:
// non-public ones, and this host's public address outside the relay ports. Permissions
// already refuse non-public peers; this is a second check where the packets leave.
type guardedConn struct {
	net.PacketConn
	cfg Config
}

func (c *guardedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	u, ok := addr.(*net.UDPAddr)
	if !ok || !permitted(u, c.cfg) {
		return len(p), nil // dropped, as a network would
	}
	return c.PacketConn.WriteTo(p, addr)
}

// permitted reports whether the relay may send to u.
func permitted(u *net.UDPAddr, cfg Config) bool {
	if !Allowed(u.IP, cfg.AllowLoopback) {
		return false
	}
	if cfg.AllowLoopback {
		return true // tests: peers share the relay's address
	}
	return !u.IP.Equal(cfg.PublicIP) || (u.Port >= cfg.MinPort && u.Port <= cfg.MaxPort)
}

// pionLogs sends pion's logs to slog, at debug level except for warnings and errors.
type pionLogs struct{ log *slog.Logger }

func (f pionLogs) NewLogger(scope string) logging.LeveledLogger {
	return pionLog{f.log.With("pion", scope)}
}

type pionLog struct{ log *slog.Logger }

func (l pionLog) Trace(string)          {}
func (l pionLog) Tracef(string, ...any) {}
func (l pionLog) Debug(m string)        { l.log.Debug(m) }
func (l pionLog) Debugf(f string, a ...any) {
	l.log.Debug(fmt.Sprintf(f, a...))
}
func (l pionLog) Info(m string)             { l.log.Debug(m) }
func (l pionLog) Infof(f string, a ...any)  { l.log.Debug(fmt.Sprintf(f, a...)) }
func (l pionLog) Warn(m string)             { l.log.Warn("turn relay: " + m) }
func (l pionLog) Warnf(f string, a ...any)  { l.log.Warn("turn relay: " + fmt.Sprintf(f, a...)) }
func (l pionLog) Error(m string)            { l.log.Debug("turn relay: " + m) }
func (l pionLog) Errorf(f string, a ...any) { l.log.Debug("turn relay: " + fmt.Sprintf(f, a...)) }
