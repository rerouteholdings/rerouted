package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/caddysetup"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

// initOptions are init's flags.
type initOptions struct {
	name, handles, listen, dataDir, registration, env string
	yes, noCaddy, caddyOnly, autoUpdates, start       bool
}

func initFlags(o *initOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.StringVar(&o.name, "name", "", "the server's DNS name, like chat.example")
	fs.StringVar(&o.handles, "handles", "", "the domain handles go under (default: the name), so users get @kat.{handles}")
	fs.StringVar(&o.listen, "listen", "", "the local address rerouted listens on (default: a free port on 127.0.0.1)")
	fs.StringVar(&o.dataDir, "data-dir", "", "the data directory (default /var/lib/rerouted as root, else ./data)")
	fs.StringVar(&o.registration, "registration", "", "who can sign up: invite (people you give the code), public (anyone), or closed")
	fs.StringVar(&o.env, "env", "", "the settings file to write (default /etc/rerouted/rerouted.env as root, else ./.env)")
	fs.BoolVar(&o.yes, "yes", false, "don't ask: take the flags and the defaults")
	fs.BoolVar(&o.noCaddy, "no-caddy", false, "don't add the sites to Caddy")
	fs.BoolVar(&o.caddyOnly, "caddy-only", false, "only add an existing settings file's sites to Caddy")
	fs.BoolVar(&o.autoUpdates, "auto-updates", false, "turn on daily package updates of rerouted")
	fs.BoolVar(&o.start, "start", false, "enable and start the systemd service")
	return fs
}

// initDeps are what init touches outside its own files: swapped by tests.
type initDeps struct {
	in        *bufio.Reader
	out, errw io.Writer
	tty       bool
	root      bool
	// Caddy: the binary on PATH ("" if none), its Caddyfile, and the directory for ours.
	caddy, caddyfile, caddyDir string
	etcDir, varLib             string // /etc/rerouted, /var/lib
	systemctl                  func(args ...string) (string, error)
	autoUpdates                func() int
}

func defaultInitDeps() *initDeps {
	fi, _ := os.Stdin.Stat()
	caddy, _ := exec.LookPath("caddy")
	return &initDeps{
		in:        bufio.NewReader(os.Stdin),
		out:       os.Stdout,
		errw:      os.Stderr,
		tty:       fi != nil && fi.Mode()&os.ModeCharDevice != 0,
		root:      isRoot(),
		caddy:     caddy,
		caddyfile: "/etc/caddy/Caddyfile",
		caddyDir:  "/etc/caddy/rerouted",
		etcDir:    filepath.Dir(packagedEnv),
		varLib:    "/var/lib",
		systemctl: func(args ...string) (string, error) {
			out, err := exec.Command("systemctl", args...).CombinedOutput()
			return string(out), err
		},
		autoUpdates: func() int { return autoUpdates(os.Stdout, os.Stderr, []string{"on"}) },
	}
}

func runInit(g *globals, args []string) int {
	var o initOptions
	fs := initFlags(&o)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "init: unexpected %q: everything is a flag (rerouted init -h)\n", fs.Arg(0))
		return 2
	}
	if o.env == "" && g.envGiven {
		o.env = g.env
	}
	return initServer(o, defaultInitDeps())
}

// ask prompts for a line, showing def as the default. Without a terminal, or with --yes,
// it takes def.
func (d *initDeps) ask(o initOptions, prompt, def string) string {
	if o.yes || !d.tty {
		return def
	}
	if def != "" {
		fmt.Fprintf(d.out, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(d.out, "%s: ", prompt)
	}
	line, _ := d.in.ReadString('\n')
	if line = strings.TrimSpace(line); line == "" {
		return def
	}
	return line
}

// confirm asks a yes/no question, default no.
func (d *initDeps) confirm(o initOptions, prompt string) bool {
	if o.yes || !d.tty {
		return false
	}
	a := strings.ToLower(d.ask(o, prompt+" (y/N)", ""))
	return a == "y" || a == "yes"
}

func initServer(o initOptions, d *initDeps) int {
	if o.caddyOnly {
		return initCaddyOnly(o, d)
	}
	fmt.Fprintln(d.out, "Setting up a rerouted homeserver. Ctrl-C stops without changing anything until the settings file is written.")

	// The name, and where handles go.
	for {
		o.name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.name), "."))
		if o.name == "" {
			if o.yes || !d.tty {
				fmt.Fprintln(d.errw, "init: --name is required without a terminal")
				return 2
			}
			o.name = d.ask(o, "Server name, the DNS name people and servers reach it at (like chat.example)", "")
			continue
		}
		if validDNSName(o.name) {
			break
		}
		fmt.Fprintf(d.errw, "%q isn't a DNS name with at least two labels (lowercase letters, digits, hyphens)\n", o.name)
		if o.yes || !d.tty {
			return 2
		}
		o.name = ""
	}
	if o.handles == "" {
		o.handles = d.ask(o, "Handle domain: users get handles like @kat.{this}", o.name)
	}
	o.handles = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.handles), "."))
	if !validDNSName(o.handles) {
		fmt.Fprintf(d.errw, "init: handle domain %q isn't a DNS name\n", o.handles)
		return 2
	}

	// The settings file, never overwritten.
	instance := false
	if o.env == "" {
		if d.root {
			o.env = filepath.Join(d.etcDir, "rerouted.env")
			if _, err := os.Stat(o.env); err == nil {
				o.env = filepath.Join(d.etcDir, o.name+".env") // a second instance: rerouted@{name}
				instance = true
			}
		} else {
			o.env = ".env"
		}
	} else {
		instance = filepath.Dir(o.env) == d.etcDir && filepath.Base(o.env) == o.name+".env"
	}
	if _, err := os.Stat(o.env); err == nil {
		fmt.Fprintf(d.errw, "init: %s already exists, and init never overwrites it. Edit it by hand, check it with\n"+
			"rerouted -env %s config check, or pass --env for a new file.\n", o.env, o.env)
		return 1
	}

	// The data directory.
	if o.dataDir == "" {
		switch {
		case d.root && instance:
			o.dataDir = filepath.Join(d.varLib, "rerouted-"+o.name)
		case d.root:
			o.dataDir = filepath.Join(d.varLib, "rerouted")
		default:
			o.dataDir = "data"
		}
	}
	if abs, err := filepath.Abs(o.dataDir); err == nil {
		o.dataDir = abs
	}
	if _, err := os.Stat(filepath.Join(o.dataDir, dbName)); err == nil {
		fmt.Fprintf(d.errw, "init: %s already holds a database: that's an existing server's data. Pass --data-dir for a new one.\n", o.dataDir)
		return 1
	}

	// The listen address: a free local port no other settings file here claims.
	if o.listen == "" {
		o.listen = freeListen(filepath.Dir(o.env))
	}
	if _, _, err := net.SplitHostPort(o.listen); err != nil {
		fmt.Fprintf(d.errw, "init: --listen %q isn't host:port\n", o.listen)
		return 2
	}

	// Registration.
	if o.registration == "" {
		o.registration = d.ask(o, "Who can sign up: invite (people you give the code), public (anyone), or closed", "invite")
	}
	switch o.registration {
	case "invite", "public", "closed":
	default:
		fmt.Fprintf(d.errw, "init: --registration is invite, public, or closed, not %q\n", o.registration)
		return 2
	}
	code := registrationCode()

	// Write the settings file, then the data directory and keys.
	if err := writeEnvFile(o, code, d.root); err != nil {
		fmt.Fprintln(d.errw, "init:", err)
		return 1
	}
	fmt.Fprintf(d.out, "\nWrote %s.\n", o.env)
	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		fmt.Fprintln(d.errw, "init: data directory:", err)
		return 1
	}
	key, err := serverkey.LoadOrCreate(o.dataDir)
	if err != nil {
		fmt.Fprintln(d.errw, "init: server key:", err)
		return 1
	}
	fmt.Fprintf(d.out, "Created %s, with the server's keys (%s and %s).\n", o.dataDir, key.Current().KID, key.Current().V2.KID)
	if d.root {
		if u, err := user.Lookup("rerouted"); err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			chownTreeTo(o.dataDir, uid, gid)
		} else {
			fmt.Fprintf(d.out, "There's no rerouted user (the packages create one). Run rerouted as its own user, and give it %s.\n", o.dataDir)
		}
	}
	switch o.registration {
	case "invite":
		fmt.Fprintf(d.out, "The registration code is %s: give it to the people you want to sign up.\n", code)
	case "public":
		fmt.Fprintln(d.out, "Registration is public: the server document publishes the code, so anyone can sign up.")
	}

	printDNS(d.out, o.name, o.handles)

	code2 := 0
	if !o.noCaddy {
		code2 = setupCaddy(d, o.env, o.name, o.handles, o.listen)
	}
	if code2 != 0 {
		return code2
	}

	if o.autoUpdates || d.confirm(o, "Turn on automatic updates (rerouted auto-updates on)?") {
		d.autoUpdates()
	}
	unit := ""
	switch {
	case o.env == packagedEnv || o.env == filepath.Join(d.etcDir, "rerouted.env"):
		unit = "rerouted.service"
	case instance:
		unit = "rerouted@" + o.name + ".service"
	}
	if unit == "" {
		fmt.Fprintf(d.out, "\nStart it with: rerouted -env %s\n", o.env)
	} else if o.start || d.confirm(o, "Enable and start "+unit+"?") {
		if out, err := d.systemctl("enable", "--now", unit); err != nil {
			fmt.Fprintf(d.errw, "systemctl enable --now %s: %v\n%s", unit, err, out)
			return 1
		}
		fmt.Fprintf(d.out, "Started %s.\n", unit)
	} else {
		fmt.Fprintf(d.out, "\nStart it with: systemctl enable --now %s\n", unit)
	}
	fmt.Fprintf(d.out, "Once it runs and DNS has spread, check everything with: rerouted -env %s checkup\n", o.env)
	return 0
}

// freeListen picks 127.0.0.1:port for the first port from 8080 that's free now and that no
// settings file in dir claims.
func freeListen(dir string) string {
	claimed := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(dir, "*.env"))
	if f := filepath.Join(dir, ".env"); !contains(files, f) {
		files = append(files, f)
	}
	for _, f := range files {
		entries, _ := readEnvFile(f)
		for _, e := range entries {
			if e.key == "REROUTED_LISTEN" {
				if _, p, err := net.SplitHostPort(e.value); err == nil {
					claimed[p] = true
				}
			}
		}
	}
	for port := 8080; port < 8200; port++ {
		p := strconv.Itoa(port)
		if claimed[p] {
			continue
		}
		l, err := net.Listen("tcp", "127.0.0.1:"+p)
		if err != nil {
			continue
		}
		l.Close()
		return "127.0.0.1:" + p
	}
	return "127.0.0.1:8080"
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// registrationCode makes a random code: 20 characters from an alphabet without lookalikes.
func registrationCode() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 20)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b[:5]) + "-" + string(b[5:10]) + "-" + string(b[10:15]) + "-" + string(b[15:])
}

func writeEnvFile(o initOptions, code string, root bool) error {
	reg, public := o.registration, "off"
	if reg == "public" {
		reg, public = "invite", "on"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# rerouted settings for %s, written by rerouted init on %s.\n", o.name, time.Now().UTC().Format("2006-01-02"))
	b.WriteString("# Every setting: docs/settings.md. Check changes with rerouted config check.\n\n")
	fmt.Fprintf(&b, "# This server's DNS name.\nREROUTED_NAME=%s\n\n", o.name)
	fmt.Fprintf(&b, "# Users get handles under this domain, like kat.%s.\nREROUTED_HANDLES=%s\n\n", o.handles, o.handles)
	fmt.Fprintf(&b, "# The reverse proxy (Caddy) forwards to this local address.\nREROUTED_LISTEN=%s\n\n", o.listen)
	fmt.Fprintf(&b, "REROUTED_DATA_DIR=%s\n\n", o.dataDir)
	b.WriteString("# Who can sign up: invite (with the code), or closed. REROUTED_REGISTRATION_PUBLIC=on\n# publishes the code, so anyone can.\n")
	fmt.Fprintf(&b, "REROUTED_REGISTRATION=%s\nREROUTED_REGISTRATION_CODE=%s\nREROUTED_REGISTRATION_PUBLIC=%s\n", reg, code, public)
	b.WriteString("\n# A call relay (docs/run-a-call-relay.md):\n# REROUTED_TURN_URLS=turn:" + o.name + ":3478?transport=udp,turns:" + o.name + ":5349?transport=tcp\n# REROUTED_TURN_SECRET=\n")
	if err := os.MkdirAll(filepath.Dir(o.env), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(o.env, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The service reads it as the rerouted user: root owns it, the rerouted group reads it.
	if root {
		if g, err := user.LookupGroup("rerouted"); err == nil {
			gid, _ := strconv.Atoi(g.Gid)
			os.Chown(o.env, 0, gid)
		}
	}
	return nil
}

// publicAddrs lists this machine's global addresses, as hints for the DNS records.
func publicAddrs() (v4, v6 []string) {
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range ifs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsPrivate() {
			continue
		}
		if ipn.IP.To4() != nil {
			v4 = append(v4, ipn.IP.String())
		} else {
			v6 = append(v6, ipn.IP.String())
		}
	}
	return v4, v6
}

// printDNS prints the records to add. Handles on this server need no TXT records: rerouted
// serves each one's HTTPS handle document (SPEC §5.3).
func printDNS(w io.Writer, name, handles string) {
	v4, v6 := publicAddrs()
	a, aaaa := "<this machine's IPv4 address>", "<its IPv6 address, if it has one>"
	if len(v4) > 0 {
		a = v4[0]
	}
	if len(v6) > 0 {
		aaaa = v6[0]
	}
	fmt.Fprintln(w, "\nAdd these DNS records:")
	for _, host := range []string{name + ".", "*." + handles + "."} {
		fmt.Fprintf(w, "  %-30s A     %s\n", host, a)
		fmt.Fprintf(w, "  %-30s AAAA  %s\n", host, aaaa)
	}
	if len(v4) == 0 {
		fmt.Fprintln(w, "This machine has no public IPv4 address of its own (NAT?): use the address it's reached at.")
	}
	fmt.Fprintln(w, "Handles here need no TXT records: rerouted serves their handle documents over HTTPS.")
}

// caddySite is the site file: the server's APIs on its name, and handle documents on the
// handle wildcard, which gets certificates on demand.
func caddySite(name, handles, target string) string {
	return fmt.Sprintf(`# rerouted for %[1]s, written by rerouted init. rerouted init never replaces this file:
# edit it as you like. The on-demand TLS ask is in global/%[1]s.caddy.
%[1]s {
	@tieroute path /.well-known/tieroute/* /v0/*
	handle @tieroute {
		reverse_proxy %[3]s
	}
	handle {
		respond 404
	}
}

# Handles: kat.%[2]s. Caddy asks rerouted before getting each certificate.
*.%[2]s {
	tls {
		on_demand
	}
	handle /.well-known/tieroute/handle {
		reverse_proxy %[3]s
	}
	handle {
		respond 404
	}
}
`, name, handles, target)
}

// caddyGlobal is the global options file: Caddy asks rerouted before issuing a handle's
// certificate, so random subdomains can't use up the certificate authority's rate limits.
func caddyGlobal(name, target string) string {
	return fmt.Sprintf(`# rerouted for %s, written by rerouted init: goes in Caddy's global options block.
on_demand_tls {
	ask http://%s/v0/tls-ask
}
`, name, target)
}

func initCaddyOnly(o initOptions, d *initDeps) int {
	if o.env == "" {
		o.env = defaultEnvFile()
	}
	if _, err := os.Stat(o.env); err != nil {
		fmt.Fprintln(d.errw, "init --caddy-only:", err)
		return 1
	}
	cfg, err := config.Load(o.env)
	if err != nil {
		fmt.Fprintln(d.errw, "init --caddy-only: config:", err)
		return 1
	}
	handles := cfg.Handles
	if handles == "" {
		handles = cfg.Name
	}
	return setupCaddy(d, o.env, cfg.Name, handles, cfg.Listen)
}

// setupCaddy adds the sites to Caddy, if it's installed.
func setupCaddy(d *initDeps, envFile, name, handles, listen string) int {
	target := localAddr(listen)
	site, global := caddySite(name, handles, target), caddyGlobal(name, target)
	_, cerr := os.Stat(d.caddyfile)
	if d.caddy == "" || cerr != nil {
		fmt.Fprintf(d.out, "\nCaddy isn't installed here (no caddy, or no %s). Put a reverse proxy with TLS in front\n"+
			"of rerouted. For Caddy, the global options need:\n\n%s\nand the sites:\n\n%s", d.caddyfile, indent(global), indent(site))
		return 0
	}
	if !d.root {
		fmt.Fprintf(d.out, "\nCaddy is installed, but adding the sites to it needs root. Run:\n  sudo rerouted init --caddy-only --env %s\n", envFile)
		return 0
	}
	s := &caddysetup.Setup{
		Caddyfile: d.caddyfile, Dir: d.caddyDir, Name: name, Site: site, Global: global, Caddy: d.caddy,
		Reload: func() error {
			if _, err := exec.LookPath("systemctl"); err == nil {
				if _, err := d.systemctl("is-active", "--quiet", "caddy"); err == nil {
					out, err := d.systemctl("reload", "caddy")
					if err != nil {
						return fmt.Errorf("%v: %s", err, out)
					}
					return nil
				}
			}
			out, err := exec.Command(d.caddy, "reload", "--config", d.caddyfile, "--adapter", "caddyfile").CombinedOutput()
			if err != nil {
				return fmt.Errorf("%v: %s", err, out)
			}
			return nil
		},
	}
	res, err := s.Apply()
	if err != nil {
		fmt.Fprintln(d.errw, "\nCaddy:", err)
		return 1
	}
	fmt.Fprintln(d.out)
	fmt.Fprintf(d.out, "Caddy: the sites are in %s.\n", res.SiteFile)
	if res.SiteNew != "" {
		fmt.Fprintf(d.out, "%s already existed with other contents, so it's kept: the new version is %s. Compare them.\n", res.SiteFile, res.SiteNew)
	}
	if res.GlobalFile != "" {
		fmt.Fprintf(d.out, "Caddy: the on-demand TLS ask is in %s.\n", res.GlobalFile)
	}
	if res.GlobalNew != "" {
		fmt.Fprintf(d.out, "%s already existed with other contents, so it's kept: the new version is %s.\n", res.GlobalFile, res.GlobalNew)
	}
	if res.OtherAsk != "" {
		fmt.Fprintf(d.out, "Caddy already asks %s before issuing on-demand certificates, and it takes only one\n"+
			"ask URL. So that handles here get certificates too, add http://%s to REROUTED_TLS_ASK_ALSO\n"+
			"in the settings of the rerouted that URL belongs to, and restart it: it then asks this one too.\n", res.OtherAsk, target)
	}
	if res.Manual != "" {
		fmt.Fprintf(d.out, "%s. Add these lines to it (or to what generates it), then reload Caddy:\n", res.Manual)
		for _, l := range res.ImportLines {
			fmt.Fprintf(d.out, "  %s\n", l)
		}
		return 0
	}
	if res.Edited {
		fmt.Fprintf(d.out, "Caddy: added import lines to %s (backup: %s).\n", d.caddyfile, res.Backup)
	}
	if res.Reloaded {
		fmt.Fprintln(d.out, "Caddy: validated and reloaded.")
	} else {
		fmt.Fprintln(d.out, "Caddy: validated; nothing changed that needed a reload.")
	}
	return 0
}

func indent(s string) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(s, "\n") {
		if strings.TrimSpace(l) != "" {
			b.WriteString("  ")
		}
		b.WriteString(l)
	}
	return b.String()
}
