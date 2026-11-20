package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/config"
)

// knownKeys are the settings rerouted reads. A test checks that every REROUTED_ name in
// internal/config is here, so a new setting can't be flagged as a typo.
var knownKeys = []string{
	"REROUTED_NAME", "REROUTED_LISTEN", "REROUTED_DATA_DIR", "REROUTED_PUBLIC_URL",
	"REROUTED_API_PATH", "REROUTED_API_PATH_V2", "REROUTED_HANDLES", "REROUTED_REGISTRATION",
	"REROUTED_REGISTRATION_CODE", "REROUTED_REGISTRATION_PUBLIC", "REROUTED_STORE",
	"REROUTED_DEV", "REROUTED_DEV_PEERS", "REROUTED_TLS_ASK_ALSO", "REROUTED_TLS_ASK_ALLOW",
	"REROUTED_TURN_URLS", "REROUTED_TURN_SECRET", "REROUTED_MEDIA_QUOTA", "REROUTED_BACKUP_QUOTA",
	"REROUTED_PUBLIC_FIREHOSE", "REROUTED_PAUSE_MOVES", "REROUTED_COMMUNITIES",
	"REROUTED_COMMUNITY_CODE", "REROUTED_COMMUNITY_OPEN", "REROUTED_COMMUNITY_FILE_DAYS",
	"REROUTED_COMMUNITY_FILE_QUOTA", "REROUTED_COMMUNITY_HISTORY_QUOTA",
	"REROUTED_VOICE_UDP_PORT", "REROUTED_VOICE_PUBLIC_IPS", "REROUTED_LOG_LEVEL", "REROUTED_LOG_FORMAT",
	"REROUTED_METRICS_LISTEN", "REROUTED_TURN_LISTEN", "REROUTED_TURN_PUBLIC_IP",
	"REROUTED_TURN_RELAY_PORTS", "REROUTED_UPDATE_CHECK", "REROUTED_RESTART_MAX_WAIT",
	"REROUTED_APNS_KEY_FILE", "REROUTED_APNS_KEY_ID", "REROUTED_APNS_TEAM_ID", "REROUTED_APNS_TOPIC",
}

// proxyKeys are the standard proxy variables, which rerouted's outbound HTTP honors.
var proxyKeys = map[string]bool{
	"HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true,
	"https_proxy": true, "http_proxy": true, "no_proxy": true,
}

// problem is one finding of config check or checkup.
type problem struct {
	fatal bool // an error: rerouted won't start, or would misbehave
	msg   string
}

// envEntry is one KEY=value line of a settings file.
type envEntry struct {
	key, value string
	line       int
}

// readEnvFile parses a settings file the way config.Load does. A missing file gives no
// entries and no error.
func readEnvFile(path string) ([]envEntry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []envEntry
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return out, fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		out = append(out, envEntry{strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`), n})
	}
	return out, sc.Err()
}

// closestKey suggests the known setting a mistyped one probably meant.
func closestKey(k string) string {
	best, bestD := "", 4
	for _, known := range knownKeys {
		if d := editDistance(k, known); d < bestD {
			best, bestD = known, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// checkConfig checks the settings file and environment: everything config.Load refuses,
// and the mistakes it lets through. It returns the loaded settings if they load.
func checkConfig(path string) (*config.Config, []problem) {
	var probs []problem
	add := func(fatal bool, format string, a ...any) {
		probs = append(probs, problem{fatal, fmt.Sprintf(format, a...)})
	}
	entries, err := readEnvFile(path)
	if err != nil {
		add(true, "%v", err)
		return nil, probs
	}
	if _, err := os.Stat(path); err != nil && path != "" {
		add(false, "no settings file at %s: using the environment only", path)
	}
	known := map[string]bool{}
	for _, k := range knownKeys {
		known[k] = true
	}
	seen := map[string]int{}
	for _, e := range entries {
		if prev, ok := seen[e.key]; ok {
			add(false, "%s:%d: %s is set again (first on line %d); the first one counts", path, e.line, e.key, prev)
		} else {
			seen[e.key] = e.line
		}
		if strings.HasPrefix(e.key, "REROUTED_") && !known[e.key] {
			msg := fmt.Sprintf("%s:%d: %s isn't a rerouted setting", path, e.line, e.key)
			if s := closestKey(e.key); s != "" {
				msg += "; did you mean " + s + "?"
			}
			add(false, "%s", msg)
		} else if !strings.HasPrefix(e.key, "REROUTED_") && !proxyKeys[e.key] {
			add(false, "%s:%d: %s isn't a rerouted setting (they all start with REROUTED_)", path, e.line, e.key)
		}
		if v, set := os.LookupEnv(e.key); set && v != e.value {
			add(false, "%s is set in the environment too, which wins over %s", e.key, path)
		}
	}
	var envOnly []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "REROUTED_") && !known[k] {
			if _, inFile := seen[k]; !inFile {
				envOnly = append(envOnly, k)
			}
		}
	}
	sort.Strings(envOnly)
	for _, k := range envOnly {
		msg := "the environment sets " + k + ", which isn't a rerouted setting"
		if s := closestKey(k); s != "" {
			msg += "; did you mean " + s + "?"
		}
		add(false, "%s", msg)
	}

	cfg, err := config.Load(path)
	if err != nil {
		add(true, "%v", err)
		return nil, probs
	}

	// What config.Load lets through.
	if host, port, err := net.SplitHostPort(cfg.Listen); err != nil {
		add(true, "REROUTED_LISTEN=%s isn't host:port: %v", cfg.Listen, err)
	} else {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			add(true, "REROUTED_LISTEN=%s: %q isn't a port number", cfg.Listen, port)
		}
		if ip := net.ParseIP(host); host == "" || ip != nil && !ip.IsLoopback() && !cfg.Dev {
			add(false, "REROUTED_LISTEN=%s listens beyond this machine: rerouted expects a reverse proxy on the same host (127.0.0.1)", cfg.Listen)
		}
	}
	if !validDNSName(cfg.Name) {
		add(true, "REROUTED_NAME=%s isn't a DNS name with at least two labels (SPEC §5.1)", cfg.Name)
	}
	if cfg.Handles != "" && !validDNSName(cfg.Handles) {
		add(true, "REROUTED_HANDLES=%s isn't a DNS name", cfg.Handles)
	}
	if cfg.Handles == "" {
		add(false, "REROUTED_HANDLES is empty: this server gives out no handles, so its users need their own domains")
	}
	if u, err := url.Parse(cfg.PublicURL); err != nil || u.Host == "" || u.Path != "" {
		add(true, "REROUTED_PUBLIC_URL=%s should be an origin, like https://%s", cfg.PublicURL, cfg.Name)
	}
	if cfg.Registration == "invite" && cfg.RegistrationPublic {
		add(false, "registration is public: REROUTED_REGISTRATION_PUBLIC=on publishes the code, so anyone can sign up")
	}
	for _, u := range cfg.TurnURLs {
		if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
			add(true, "REROUTED_TURN_URLS: %q should start with turn: or turns:", u)
		}
	}
	if len(cfg.TurnURLs) == 0 && cfg.TurnSecret != "" {
		add(false, "REROUTED_TURN_SECRET is set but REROUTED_TURN_URLS is empty: calls can't use a relay")
	}
	for _, u := range cfg.TLSAskAlso {
		if pu, err := url.Parse(u); err != nil || pu.Scheme != "http" || pu.Host == "" {
			add(true, "REROUTED_TLS_ASK_ALSO: %q should be another rerouted's base URL, like http://127.0.0.1:8102", u)
		}
	}
	if cfg.Dev {
		add(false, "REROUTED_DEV=on: development mode, never for a server on the public network")
	}
	if cfg.PublicFirehose {
		add(false, "REROUTED_PUBLIC_FIREHOSE=on publishes every delivery's metadata: only for a public development server")
	}
	if cfg.Store == "temp" {
		add(false, "REROUTED_STORE=temp deletes everything on shutdown: demos only")
	} else {
		probs = append(probs, checkDataDir(cfg.DataDir)...)
	}
	return cfg, probs
}

// checkDataDir checks that the data directory exists and is writable, or can be created.
func checkDataDir(dir string) []problem {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(filepath.Clean(dir))
		if !writable(parent) {
			return []problem{{true, fmt.Sprintf("REROUTED_DATA_DIR=%s doesn't exist, and %s isn't writable to create it", dir, parent)}}
		}
		return []problem{{false, fmt.Sprintf("REROUTED_DATA_DIR=%s doesn't exist yet: rerouted creates it when it starts", dir)}}
	}
	if err != nil {
		return []problem{{true, fmt.Sprintf("REROUTED_DATA_DIR=%s: %v", dir, err)}}
	}
	if !fi.IsDir() {
		return []problem{{true, fmt.Sprintf("REROUTED_DATA_DIR=%s isn't a directory", dir)}}
	}
	if !writable(dir) {
		return []problem{{true, fmt.Sprintf("REROUTED_DATA_DIR=%s isn't writable by this user (run as the user rerouted runs as: sudo -u rerouted rerouted ...)", dir)}}
	}
	return nil
}

// writable reports whether this process can create files in dir.
func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".rerouted-check-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// validDNSName reports whether s is a lowercase DNS name with at least two labels.
func validDNSName(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func runConfig(g *globals, args []string) int {
	if len(args) != 2 || args[1] != "check" {
		fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] config check")
		return 2
	}
	if g.envGiven {
		if _, err := os.Stat(g.env); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	fmt.Printf("checking %s\n", g.env)
	cfg, probs := checkConfig(g.env)
	errs := 0
	for _, p := range probs {
		if p.fatal {
			errs++
			fmt.Println("error:", p.msg)
		} else {
			fmt.Println("warning:", p.msg)
		}
	}
	if errs > 0 {
		fmt.Printf("%d errors: rerouted won't start with these settings\n", errs)
		return 1
	}
	fmt.Printf("ok: %s, listening on %s, data in %s\n", cfg.Name, cfg.Listen, cfg.DataDir)
	return 0
}
