package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun/v4"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/version"
)

// Checkup's limits.
const (
	certWarnDays  = 14
	skewWarn      = 30 * time.Second
	skewFail      = 5 * time.Minute // SPEC §8.4: a server further off can't federate
	diskWarnBytes = 1 << 30
	diskFailBytes = 200 << 20
)

// checkup runs the checks and prints a line for each.
type checkup struct {
	out          io.Writer
	fails, warns int
	timeout      time.Duration
	now          func() time.Time
}

func (c *checkup) line(level, name, format string, a ...any) {
	switch level {
	case "FAIL":
		c.fails++
	case "WARN":
		c.warns++
	}
	fmt.Fprintf(c.out, "%-4s  %-14s %s\n", level, name, fmt.Sprintf(format, a...))
}
func (c *checkup) pass(name, f string, a ...any) { c.line("PASS", name, f, a...) }
func (c *checkup) warn(name, f string, a ...any) { c.line("WARN", name, f, a...) }
func (c *checkup) fail(name, f string, a ...any) { c.line("FAIL", name, f, a...) }
func (c *checkup) info(name, f string, a ...any) { c.line("INFO", name, f, a...) }

// docSummary is what checkup reads from a server document (SPEC §5.1).
type docSummary struct {
	Name string `json:"name"`
	APIs []struct {
		V int `json:"v"`
	} `json:"apis"`
	Keys []struct {
		KID string `json:"kid"`
		Pub string `json:"pub"`
	} `json:"keys"`
}

// sameKeys reports whether two documents list the same keys: the same server.
func (d *docSummary) sameKeys(o *docSummary) bool {
	if d == nil || o == nil || len(d.Keys) != len(o.Keys) || len(d.Keys) == 0 {
		return false
	}
	for i := range d.Keys {
		if d.Keys[i] != o.Keys[i] {
			return false
		}
	}
	return true
}

// fetchResult is one fetch of a document.
type fetchResult struct {
	doc      *docSummary
	raw      []byte
	status   int
	certEnd  time.Time   // the leaf certificate's NotAfter, for https
	curve    tls.CurveID // the key exchange the TLS handshake settled on, for https
	date     time.Time   // the Date header
	midpoint time.Time   // halfway through the request, to compare Date with
}

// fetch GETs url. dialIP, if set, connects to that address instead of the URL's host's,
// still asking for the host by name (SNI and Host). host, if set, overrides the Host header.
func (c *checkup) fetch(rawURL, dialIP, host string) (*fetchResult, error) {
	d := &net.Dialer{Timeout: c.timeout}
	tr := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: c.timeout,
		DisableKeepAlives:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dialIP != "" {
				_, port, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(dialIP, port)
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
	}
	req.Header.Set("User-Agent", version.UserAgent()+" checkup")
	start := c.now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	end := c.now()
	r := &fetchResult{status: resp.StatusCode, midpoint: start.Add(end.Sub(start) / 2)}
	r.raw, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.certEnd = resp.TLS.PeerCertificates[0].NotAfter
		r.curve = resp.TLS.CurveID
	}
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		r.date = d
	}
	if resp.StatusCode == http.StatusOK {
		var doc docSummary
		if json.Unmarshal(r.raw, &doc) == nil && doc.Name != "" {
			r.doc = &doc
		}
	}
	return r, nil
}

// localAddr turns a listen address into one to connect to.
func localAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

func runCheckup(g *globals, args []string) int {
	fs := flag.NewFlagSet("checkup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	peer := fs.String("peer", "", "also fetch this server's document, to check federation")
	handle := fs.String("handle", "", "a handle on this server, to check its certificate")
	timeout := fs.Duration("timeout", 10*time.Second, "how long each network check may take")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] checkup [--peer NAME] [--handle HANDLE] [--timeout 10s]")
		return 2
	}
	c := &checkup{out: os.Stdout, timeout: *timeout, now: time.Now}
	c.run(g.env, strings.ToLower(strings.TrimPrefix(*peer, "https://")), strings.ToLower(strings.TrimPrefix(*handle, "@")))
	fmt.Fprintf(c.out, "\n%d failed, %d warnings\n", c.fails, c.warns)
	if c.fails > 0 {
		return 1
	}
	return 0
}

func (c *checkup) run(envFile, peer, handle string) {
	// Settings.
	cfg, probs := checkConfig(envFile)
	for _, p := range probs {
		if p.fatal {
			c.fail("config", "%s", p.msg)
		} else {
			c.warn("config", "%s", p.msg)
		}
	}
	if cfg == nil {
		c.fail("config", "can't check more until the settings load")
		return
	}
	if len(probs) == 0 {
		c.pass("config", "%s loads without problems", envFile)
	}

	// Disk.
	if cfg.Store != "temp" {
		dir := cfg.DataDir
		for {
			if _, err := os.Stat(dir); err == nil || filepath.Dir(dir) == dir {
				break
			}
			dir = filepath.Dir(dir)
		}
		if free, total, err := diskSpace(dir); err != nil {
			c.warn("disk", "can't tell the free space on %s: %v", dir, err)
		} else {
			msg := fmt.Sprintf("%s free of %s on %s", humanBytes(int64(free)), humanBytes(int64(total)), dir)
			switch {
			case free < diskFailBytes:
				c.fail("disk", "%s: SQLite needs room to write, and rerouted stops working when it runs out", msg)
			case free < diskWarnBytes:
				c.warn("disk", "%s", msg)
			default:
				c.pass("disk", "%s", msg)
			}
		}
	}

	// The server itself, on its local address.
	local := localAddr(cfg.Listen)
	var localDoc *docSummary
	if r, err := c.fetch("http://"+local+"/.well-known/tieroute/server", "", cfg.Name); err != nil {
		c.fail("listener", "nothing answers on %s: is rerouted running? (%v)", local, shortErr(err))
	} else if r.doc == nil {
		c.fail("listener", "%s answered %d without a server document: is something else on that port?", local, r.status)
	} else if r.doc.Name != cfg.Name {
		c.fail("listener", "%s serves %s's document, not %s's: another rerouted holds this port", local, r.doc.Name, cfg.Name)
	} else {
		localDoc = r.doc
		c.pass("listener", "rerouted answers on %s", local)
	}

	if !strings.HasPrefix(cfg.PublicURL, "https://") {
		c.info("https", "REROUTED_PUBLIC_URL is %s: development mode, so the DNS, certificate, and clock checks are skipped", cfg.PublicURL)
	} else {
		c.checkDNS(cfg, localDoc)
		c.checkPublic(cfg, localDoc)
		c.checkHandle(cfg, handle)
	}
	c.checkNTP()
	c.checkTURN(cfg)
	if cfg.VoiceUDPPort > 0 {
		c.info("voice", "community voice uses UDP port %d: let it through the firewall (checkup can't test that from inside)", cfg.VoiceUDPPort)
	} else if len(cfg.Communities) > 0 {
		c.info("voice", "community voice uses a random UDP port per connection: set REROUTED_VOICE_UDP_PORT to use one port a firewall can allow")
	}
	if peer != "" {
		c.checkPeer(cfg, peer)
	} else {
		c.info("federation", "skipped: checkup --peer NAME fetches another server's document")
	}
}

// checkDNS checks that the name resolves, and that each address reaches this server.
func (c *checkup) checkDNS(cfg *config.Config, localDoc *docSummary) {
	u, _ := url.Parse(cfg.PublicURL)
	host := u.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		c.fail("dns", "%s doesn't resolve: add A (and AAAA) records pointing at this machine (%v)", host, shortErr(err))
		return
	}
	mine := map[string]bool{}
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if ipn, ok := a.(*net.IPNet); ok {
				mine[ipn.IP.String()] = true
			}
		}
	}
	for _, a := range addrs {
		ip := a.IP.String()
		kind := "A"
		if a.IP.To4() == nil {
			kind = "AAAA"
		}
		if a.IP.IsPrivate() || a.IP.IsLoopback() {
			c.warn("dns", "%s %s %s is a private address: other servers can't reach it", host, kind, ip)
			continue
		}
		// The name's own HTTPS answer says whether this address reaches this server, even
		// behind NAT or a proxy, without asking anyone else for our address.
		r, err := c.fetch(cfg.PublicURL+"/.well-known/tieroute/server", ip, "")
		switch {
		case err != nil && mine[ip]:
			c.fail("dns", "%s %s %s is this machine, but HTTPS to it fails: %v", host, kind, ip, shortErr(err))
		case err != nil:
			c.fail("dns", "%s %s %s doesn't answer HTTPS: %v. Is the record stale, or port 443 closed?", host, kind, ip, shortErr(err))
		case localDoc != nil && r.doc != nil && localDoc.sameKeys(r.doc):
			how := "this machine"
			if !mine[ip] {
				how = "this server (through NAT or a proxy)"
			}
			c.pass("dns", "%s %s %s reaches %s", host, kind, ip, how)
		case r.doc != nil && localDoc != nil:
			c.fail("dns", "%s %s %s serves a different server's keys: it points at another machine", host, kind, ip)
		case r.doc == nil:
			c.fail("dns", "%s %s %s answers %d without a server document: check the proxy's routes for /.well-known/tieroute/", host, kind, ip, r.status)
		default:
			c.pass("dns", "%s %s %s serves %s's document (the local listener didn't answer, so the keys weren't compared)", host, kind, ip, r.doc.Name)
		}
	}
	if cfg.Handles != "" {
		probe := "rerouted-checkup-" + randomLabel() + "." + cfg.Handles
		if as, err := net.DefaultResolver.LookupIPAddr(ctx, probe); err != nil || len(as) == 0 {
			c.warn("dns", "*.%s doesn't resolve: handles like kat.%s need a wildcard A (and AAAA) record", cfg.Handles, cfg.Handles)
		} else {
			c.pass("dns", "*.%s resolves, for handle subdomains", cfg.Handles)
		}
	}
}

// checkPublic fetches the server document at the public URL: its certificate, its keys,
// and the clock in its Date header.
func (c *checkup) checkPublic(cfg *config.Config, localDoc *docSummary) {
	docURL := cfg.PublicURL + "/.well-known/tieroute/server"
	r, err := c.fetch(docURL, "", "")
	if err != nil {
		c.fail("https", "%s: %v", docURL, shortErr(err))
		return
	}
	switch {
	case r.doc == nil:
		c.fail("https", "%s answered %d without a server document", docURL, r.status)
	case r.doc.Name != cfg.Name:
		c.fail("https", "%s names %s, not %s", docURL, r.doc.Name, cfg.Name)
	case localDoc != nil && !localDoc.sameKeys(r.doc):
		c.fail("https", "%s lists other keys than the local listener: the proxy reaches another rerouted", docURL)
	default:
		c.pass("https", "%s serves this server's document", docURL)
	}
	// Hybrid key exchange: SPEC §3 makes it a MUST on what servers offer. Go offers it
	// first, so a TLS endpoint that has it picks it.
	switch {
	case r.certEnd.IsZero():
	case r.curve == tls.X25519MLKEM768:
		c.pass("tls", "offers the hybrid post-quantum key exchange X25519MLKEM768")
	default:
		c.warn("tls", "the TLS endpoint picked %s, not X25519MLKEM768: SPEC §3 requires offering the hybrid key exchange. Caddy 2.10 and later offer it unless a curves setting leaves it out", r.curve)
	}
	if !r.certEnd.IsZero() {
		left := r.certEnd.Sub(c.now())
		days := int(left.Hours() / 24)
		if days < certWarnDays {
			c.warn("certificate", "expires in %d days (%s): renewal should have happened by now; check the proxy's logs", days, r.certEnd.UTC().Format("2006-01-02"))
		} else {
			c.pass("certificate", "valid for %d more days", days)
		}
	}
	if r.date.IsZero() {
		c.warn("clock", "%s sent no Date header to compare the clock with", docURL)
		return
	}
	// Date has one-second resolution: allow for it.
	skew := r.midpoint.Sub(r.date)
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	if abs > time.Second {
		abs -= time.Second
	} else {
		abs = 0
	}
	switch {
	case abs > skewFail:
		c.fail("clock", "this clock is %s off the time %s gives: Tieroute refuses signatures that far off (SPEC §8.4); turn on NTP", skew.Round(time.Second), cfg.PublicURL)
	case abs > skewWarn:
		c.warn("clock", "this clock is %s off the time %s gives: turn on NTP before it reaches 5 minutes", skew.Round(time.Second), cfg.PublicURL)
	default:
		c.pass("clock", "within %s of the time %s gives", skewWarn, cfg.PublicURL)
	}
}

// checkHandle checks a handle subdomain's on-demand certificate and handle document.
func (c *checkup) checkHandle(cfg *config.Config, handle string) {
	if handle == "" {
		if cfg.Handles != "" {
			c.info("handles", "skipped: checkup --handle kat.%s checks a handle's certificate", cfg.Handles)
		}
		return
	}
	r, err := c.fetch("https://"+handle+"/.well-known/tieroute/handle", "", "")
	if err != nil {
		c.warn("handles", "https://%s: %v. Is the wildcard site in the proxy, with on-demand TLS asking rerouted?", handle, shortErr(err))
		return
	}
	var doc struct{ ID, Home string }
	if r.status != http.StatusOK || json.Unmarshal(r.raw, &doc) != nil || doc.ID == "" {
		c.warn("handles", "https://%s answered %d without a handle document: is %s a handle here?", handle, r.status, handle)
		return
	}
	days := int(r.certEnd.Sub(c.now()).Hours() / 24)
	if doc.Home != cfg.Name {
		c.warn("handles", "%s's handle document names home %s, not %s", handle, doc.Home, cfg.Name)
	} else if days < certWarnDays {
		c.warn("handles", "%s's certificate expires in %d days", handle, days)
	} else {
		c.pass("handles", "%s has a certificate (%d days left) and resolves to %s", handle, days, doc.ID)
	}
}

// checkNTP asks systemd whether the clock is synchronized, where it can.
func (c *checkup) checkNTP() {
	if _, err := exec.LookPath("timedatectl"); err != nil {
		return
	}
	out, err := exec.Command("timedatectl", "show", "--property=NTPSynchronized", "--value").Output()
	if err != nil {
		return
	}
	switch strings.TrimSpace(string(out)) {
	case "yes":
		c.pass("ntp", "the clock is synchronized")
	case "no":
		c.warn("ntp", "the clock isn't synchronized: turn on NTP (timedatectl set-ntp true)")
	}
}

// checkTURN checks that each call relay URL accepts a connection: a STUN binding request
// over UDP, a TCP connection, or a TLS handshake for turns:.
func (c *checkup) checkTURN(cfg *config.Config) {
	if len(cfg.TurnURLs) == 0 {
		c.info("turn", "no call relay (REROUTED_TURN_URLS): calls between people behind strict NATs may fail")
		return
	}
	for _, raw := range cfg.TurnURLs {
		u, err := stun.ParseURI(raw)
		if err != nil {
			c.fail("turn", "%s: %v", raw, err)
			continue
		}
		addr := net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
		switch {
		case u.Scheme == stun.SchemeTypeTURNS:
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: c.timeout}, "tcp", addr, &tls.Config{ServerName: u.Host})
			if err != nil {
				c.fail("turn", "%s: TLS to %s fails: %v", raw, addr, shortErr(err))
				continue
			}
			days := int(conn.ConnectionState().PeerCertificates[0].NotAfter.Sub(c.now()).Hours() / 24)
			conn.Close()
			if days < certWarnDays {
				c.warn("turn", "%s: certificate expires in %d days", raw, days)
			} else {
				c.pass("turn", "%s accepts TLS (certificate valid for %d days)", raw, days)
			}
		case u.Proto == stun.ProtoTypeTCP:
			conn, err := net.DialTimeout("tcp", addr, c.timeout)
			if err != nil {
				c.fail("turn", "%s: TCP to %s fails: %v", raw, addr, shortErr(err))
				continue
			}
			conn.Close()
			c.pass("turn", "%s accepts TCP connections", raw)
		default:
			if err := stunBinding(addr, c.timeout); err != nil {
				c.fail("turn", "%s: no STUN answer over UDP from %s: %v. Is the relay running, and UDP %d open?", raw, addr, shortErr(err), u.Port)
				continue
			}
			c.pass("turn", "%s answers STUN over UDP", raw)
		}
	}
}

// stunBinding sends a STUN binding request over UDP and waits for the answer.
func stunBinding(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)
	// UDP drops packets: send a few times.
	for try := 0; time.Now().Before(deadline); try++ {
		if try < 3 {
			if _, err := conn.Write(req.Raw); err != nil {
				return err
			}
		}
		conn.SetReadDeadline(time.Now().Add(min(time.Until(deadline), timeout/3+time.Millisecond)))
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		res := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if res.Decode() == nil && res.TransactionID == req.TransactionID {
			return nil
		}
	}
	return errors.New("timed out")
}

// checkPeer fetches another server's document, as federation would.
func (c *checkup) checkPeer(cfg *config.Config, peer string) {
	base := "https://" + peer
	if u, ok := cfg.Peers[peer]; ok && cfg.Dev {
		base = u
	}
	r, err := c.fetch(base+"/.well-known/tieroute/server", "", "")
	if err != nil {
		c.fail("federation", "%s: %v", peer, shortErr(err))
		return
	}
	if r.doc == nil || r.doc.Name != peer {
		c.fail("federation", "%s answered %d without its server document", peer, r.status)
		return
	}
	var vs []string
	for _, a := range r.doc.APIs {
		vs = append(vs, strconv.Itoa(a.V))
	}
	msg := fmt.Sprintf("%s's server document is reachable (wire versions %s)", peer, strings.Join(vs, ", "))
	if !r.date.IsZero() {
		if skew := r.midpoint.Sub(r.date); skew > skewFail || skew < -skewFail {
			c.fail("federation", "%s; but its clock and this one are %s apart, so it refuses this server's requests (SPEC §8.3)", msg, skew.Round(time.Second))
			return
		}
	}
	c.pass("federation", "%s", msg)
}

// shortErr trims Go's nested error text to its useful end.
func shortErr(err error) string {
	if err == nil {
		return "no answer"
	}
	s := err.Error()
	if i := strings.LastIndex(s, ": dial "); i >= 0 {
		s = s[i+2:]
	}
	if bytes.Contains([]byte(s), []byte("x509:")) {
		s = s[strings.Index(s, "x509:"):]
	}
	return s
}

func randomLabel() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}
