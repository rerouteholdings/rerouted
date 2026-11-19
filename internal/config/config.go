// Package config loads rerouted settings from the environment and an optional .env file.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds every setting. See .env.example for descriptions.
type Config struct {
	Name             string            // REROUTED_NAME: this server's DNS name
	Listen           string            // REROUTED_LISTEN: address to listen on
	DataDir          string            // REROUTED_DATA_DIR
	PublicURL        string            // REROUTED_PUBLIC_URL: origin the APIs are reached at (default https://{name})
	APIPath          string            // REROUTED_API_PATH: where the v1 APIs live (default /.well-known/tieroute/v1/)
	APIPathV2        string            // REROUTED_API_PATH_V2: where the v2 APIs live (default /.well-known/tieroute/v2/)
	Handles          string            // REROUTED_HANDLES: domain to give out handles under
	Registration     string            // REROUTED_REGISTRATION: invite or closed (SPEC §8.2)
	Store            string            // REROUTED_STORE: sqlite (default) or temp
	Dev              bool              // REROUTED_DEV: on allows Peers (http, local addresses)
	Peers            map[string]string // REROUTED_DEV_PEERS: name=http://host:port,... (dev only)
	RegistrationCode string            // REROUTED_REGISTRATION_CODE: the registration invite code
	// REROUTED_REGISTRATION_PUBLIC: on publishes the code in the server document, so anyone can sign up.
	RegistrationPublic bool
	TLSAskAlso         []string // REROUTED_TLS_ASK_ALSO: other local rerouted base URLs to consult for on-demand TLS
	// REROUTED_TLS_ASK_ALLOW: other hostnames on this domain that may get certificates, such as
	// a static site under the handle wildcard (www.chat.example). Comma-separated.
	TLSAskAllow []string
	// REROUTED_TURN_URLS: the call relay's turn: and turns: URLs, comma-separated (SPEC §15.1).
	// Empty: GET turn answers 501, and this server's users can't relay calls.
	TurnURLs []string
	// REROUTED_TURN_SECRET: the static-auth-secret shared with the TURN server (coturn's
	// use-auth-secret), for time-limited credentials.
	TurnSecret string
	// REROUTED_MEDIA_QUOTA and REROUTED_BACKUP_QUOTA: bytes each identity may store in files
	// (SPEC §14) and in backups (SPEC §7.5). Default 1 GiB each.
	MediaQuota, BackupQuota int64
	// REROUTED_PUBLIC_FIREHOSE: on serves GET /v0/dev/firehose, a public, unauthenticated
	// feed of every delivery stored here, metadata included. Off by default. Only for a
	// public development server whose users have agreed to it.
	PublicFirehose bool
	// REROUTED_PAUSE_MOVES: on refuses device-signed moves (SPEC §6.6), here as the old home
	// (chain/append of a set-home) and as the new one (register with a chain, check included),
	// before anything changes. Recovery-signed entries still go through. An operator measure
	// for when clients' move flow is known to be unsafe. Off by default.
	PauseMoves bool

	// Community servers (SPEC §16). REROUTED_COMMUNITIES lists the server names this process
	// serves as community servers, each hosting one community: name or name=url, comma-
	// separated, where url is the origin it's reached at (default https://{name}). A name
	// equal to REROUTED_NAME is also the homeserver. Requests are told apart by their Host
	// header; in dev mode, a community whose url has its own host:port gets its own listener.
	Communities []Community
	// REROUTED_COMMUNITY_CODE: the creation code POST create needs. Without one, creating a
	// community needs REROUTED_COMMUNITY_OPEN=on, which lets anyone who signs in create one
	// on a name that has none yet.
	CommunityCode string
	CommunityOpen bool
	// REROUTED_COMMUNITY_FILE_DAYS (default 30; 0 keeps files until deleted) and
	// REROUTED_COMMUNITY_FILE_QUOTA (default 10G): each community's files (SPEC §16.4).
	CommunityFileDays  int
	CommunityFileQuota int64
	// REROUTED_COMMUNITY_HISTORY_QUOTA (default 10G): each community's history segments.
	CommunityHistoryQuota int64
	// REROUTED_VOICE_UDP_PORT: one UDP port for every voice connection (0, the default:
	// a random port per connection). REROUTED_VOICE_PUBLIC_IPS: the addresses to advertise
	// behind 1:1 NAT, comma-separated.
	VoiceUDPPort   int
	VoicePublicIPs []string

	// REROUTED_LOG_LEVEL: debug, info (the default), warn, or error. REROUTED_LOG_FORMAT:
	// text (the default) or json. See Logger.
	LogLevel, LogFormat string
	// REROUTED_METRICS_LISTEN: the address to serve Prometheus metrics on, such as
	// 127.0.0.1:9101. Empty, the default: no metrics.
	MetricsListen string
	// REROUTED_TURN_LISTEN: the address the built-in call relay listens on, UDP and TCP, such
	// as :3478. Empty, the default: no built-in relay. REROUTED_TURN_RELAY_PORTS (default
	// 49160-49200): the UDP ports relayed media uses. REROUTED_TURN_PUBLIC_IP: the address
	// clients reach relayed media at (default: the first of REROUTED_VOICE_PUBLIC_IPS).
	TurnListen                 string
	TurnRelayMin, TurnRelayMax int
	TurnPublicIP               string
	// REROUTED_UPDATE_CHECK: on checks once a day for a newer rerouted release. Off by default.
	UpdateCheck bool
	// REROUTED_RESTART_MAX_WAIT (default 6h): how long a restart asked for with SIGUSR2
	// waits for voice calls to end.
	RestartMaxWait time.Duration

	envFile        string // the settings file Load read, for Reload
	turnDerived    bool   // TurnURLs were made for the built-in relay
	turnSecretFile bool   // TurnSecret came from the data directory
	live           *live  // the reloadable settings' current values (reload.go)
}

// Community is one server name this process serves as a community server.
type Community struct {
	Name string
	URL  string // the origin it's reached at, without a trailing slash
}

// Load reads .env (if present, without overriding variables already set),
// then the environment. Reload reads the same file again.
func Load(envFile string) (*Config, error) {
	file, err := readDotEnv(envFile)
	if err != nil {
		return nil, err
	}
	fromFile.mu.Lock()
	for k, v := range file {
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v) // for code that reads the environment itself
			fromFile.keys[k] = true
		}
	}
	fromFile.mu.Unlock()
	c, err := parse(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	c.envFile = envFile
	return c, c.finish()
}

// fromFile records the variables Load set from the settings file, so Reload takes them from
// the file again instead of from the environment, where Load put the old values.
var fromFile = struct {
	mu   sync.Mutex
	keys map[string]bool
}{keys: map[string]bool{}}

// parse reads every setting through lookup, without checking how they fit together.
func parse(lookup func(string) (string, bool)) (*Config, error) {
	env := func(key string) string { v, _ := lookup(key); return v }
	get := func(key, def string) string {
		if v, ok := lookup(key); ok {
			return v
		}
		return def
	}
	bytesSetting := func(key string, def int64) (int64, error) { return bytesValue(key, env(key), def) }
	c := &Config{
		Name:               env("REROUTED_NAME"),
		Listen:             get("REROUTED_LISTEN", "127.0.0.1:8080"),
		DataDir:            get("REROUTED_DATA_DIR", "./data"),
		PublicURL:          strings.TrimRight(env("REROUTED_PUBLIC_URL"), "/"),
		APIPath:            get("REROUTED_API_PATH", "/.well-known/tieroute/v1/"),
		APIPathV2:          get("REROUTED_API_PATH_V2", "/.well-known/tieroute/v2/"),
		Handles:            env("REROUTED_HANDLES"),
		Registration:       get("REROUTED_REGISTRATION", "closed"),
		Store:              get("REROUTED_STORE", "sqlite"),
		Dev:                get("REROUTED_DEV", "off") == "on",
		Peers:              map[string]string{},
		RegistrationCode:   env("REROUTED_REGISTRATION_CODE"),
		RegistrationPublic: get("REROUTED_REGISTRATION_PUBLIC", "off") == "on",
		PublicFirehose:     get("REROUTED_PUBLIC_FIREHOSE", "off") == "on",
		PauseMoves:         get("REROUTED_PAUSE_MOVES", "off") == "on",
		LogLevel:           strings.ToLower(get("REROUTED_LOG_LEVEL", "info")),
		LogFormat:          strings.ToLower(get("REROUTED_LOG_FORMAT", "text")),
		MetricsListen:      env("REROUTED_METRICS_LISTEN"),
		TurnListen:         env("REROUTED_TURN_LISTEN"),
		TurnPublicIP:       env("REROUTED_TURN_PUBLIC_IP"),
		UpdateCheck:        get("REROUTED_UPDATE_CHECK", "off") == "on",
	}
	for _, u := range strings.Split(env("REROUTED_TLS_ASK_ALSO"), ",") {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			c.TLSAskAlso = append(c.TLSAskAlso, u)
		}
	}
	for _, h := range strings.Split(env("REROUTED_TLS_ASK_ALLOW"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			c.TLSAskAllow = append(c.TLSAskAllow, h)
		}
	}
	for _, u := range strings.Split(env("REROUTED_TURN_URLS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			c.TurnURLs = append(c.TurnURLs, u)
		}
	}
	c.TurnSecret = env("REROUTED_TURN_SECRET")
	var err error
	if c.MediaQuota, err = bytesSetting("REROUTED_MEDIA_QUOTA", 1<<30); err != nil {
		return nil, err
	}
	if c.BackupQuota, err = bytesSetting("REROUTED_BACKUP_QUOTA", 1<<30); err != nil {
		return nil, err
	}
	for _, p := range strings.Split(env("REROUTED_COMMUNITIES"), ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		name, url, _ := strings.Cut(p, "=")
		c.Communities = append(c.Communities, Community{Name: strings.ToLower(strings.TrimSpace(name)), URL: strings.TrimRight(strings.TrimSpace(url), "/")})
	}
	c.CommunityCode = env("REROUTED_COMMUNITY_CODE")
	c.CommunityOpen = get("REROUTED_COMMUNITY_OPEN", "off") == "on"
	if c.CommunityFileDays, err = strconv.Atoi(get("REROUTED_COMMUNITY_FILE_DAYS", "30")); err != nil || c.CommunityFileDays < 0 {
		return nil, errors.New("REROUTED_COMMUNITY_FILE_DAYS must be a whole number of days")
	}
	if c.CommunityFileQuota, err = bytesSetting("REROUTED_COMMUNITY_FILE_QUOTA", 10<<30); err != nil {
		return nil, err
	}
	if c.CommunityHistoryQuota, err = bytesSetting("REROUTED_COMMUNITY_HISTORY_QUOTA", 10<<30); err != nil {
		return nil, err
	}
	if c.VoiceUDPPort, err = strconv.Atoi(get("REROUTED_VOICE_UDP_PORT", "0")); err != nil || c.VoiceUDPPort < 0 || c.VoiceUDPPort > 65535 {
		return nil, errors.New("REROUTED_VOICE_UDP_PORT must be a port number")
	}
	for _, ip := range strings.Split(env("REROUTED_VOICE_PUBLIC_IPS"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			c.VoicePublicIPs = append(c.VoicePublicIPs, ip)
		}
	}
	for _, p := range strings.Split(env("REROUTED_DEV_PEERS"), ",") {
		if name, url, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			c.Peers[name] = strings.TrimRight(url, "/")
		}
	}
	if c.TurnRelayMin, c.TurnRelayMax, err = portRange(get("REROUTED_TURN_RELAY_PORTS", "49160-49200")); err != nil {
		return nil, err
	}
	if c.RestartMaxWait, err = time.ParseDuration(get("REROUTED_RESTART_MAX_WAIT", "6h")); err != nil || c.RestartMaxWait < 0 {
		return nil, errors.New("REROUTED_RESTART_MAX_WAIT must be a duration, like 6h or 90m")
	}
	return c, nil
}

// portRange reads "low-high", such as 49160-49200.
func portRange(v string) (int, int, error) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(v), "-")
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || a < 1024 || b > 65535 || a > b {
		return 0, 0, errors.New("REROUTED_TURN_RELAY_PORTS must be a range of ports from 1024 to 65535, like 49160-49200")
	}
	return a, b, nil
}

// finish fills in what depends on other settings, and checks them all.
func (c *Config) finish() error {
	c.Defaults()
	if c.TurnListen != "" {
		if c.TurnSecret == "" {
			secret, err := loadOrCreateTurnSecret(c.DataDir)
			if err != nil {
				return fmt.Errorf("REROUTED_TURN_LISTEN: the relay's secret: %w", err)
			}
			c.TurnSecret, c.turnSecretFile = secret, true
		}
		if len(c.TurnURLs) == 0 {
			c.TurnURLs, c.turnDerived = c.builtinTurnURLs(), true
		}
	}
	return c.validate()
}

func (c *Config) validate() error {
	switch {
	case c.Name == "":
		return errors.New("REROUTED_NAME is required (this server's DNS name)")
	case strings.Contains(c.Name, ":") || strings.Contains(c.Name, "/"):
		return errors.New("REROUTED_NAME must be a bare DNS name, never an IP literal or URL (SPEC §5.1)")
	case !strings.HasPrefix(c.PublicURL, "https://") && !c.Dev:
		return errors.New("REROUTED_PUBLIC_URL must be https:// outside dev mode")
	}
	if c.APIPath == c.APIPathV2 {
		return errors.New("REROUTED_API_PATH and REROUTED_API_PATH_V2 must differ: each wire version has its own API base (SPEC §8.1)")
	}
	if len(c.Peers) > 0 && !c.Dev {
		return errors.New("REROUTED_DEV_PEERS needs REROUTED_DEV=on (it disables TLS for those peers)")
	}
	if c.Store != "sqlite" && c.Store != "temp" {
		return fmt.Errorf("REROUTED_STORE must be sqlite or temp, not %q", c.Store)
	}
	switch c.Registration {
	case "invite", "closed":
	case "open":
		return errors.New("REROUTED_REGISTRATION=open is gone in v1: use invite, with REROUTED_REGISTRATION_PUBLIC=on to publish the code (SPEC §8.2)")
	default:
		return fmt.Errorf("REROUTED_REGISTRATION must be invite or closed, not %q", c.Registration)
	}
	if len(c.TurnURLs) > 0 && len(c.TurnSecret) < 16 {
		return errors.New("REROUTED_TURN_URLS needs REROUTED_TURN_SECRET of at least 16 characters")
	}
	seen := map[string]bool{}
	for i, cm := range c.Communities {
		switch {
		case cm.Name == "" || strings.Contains(cm.Name, ":") || strings.Contains(cm.Name, "/"):
			return fmt.Errorf("REROUTED_COMMUNITIES: %q isn't a bare DNS name (SPEC §5.1)", cm.Name)
		case seen[cm.Name]:
			return fmt.Errorf("REROUTED_COMMUNITIES lists %s twice: a name hosts one community (SPEC §16.1)", cm.Name)
		case cm.URL == "" && cm.Name == c.Name:
			c.Communities[i].URL = c.PublicURL
		case cm.URL == "":
			c.Communities[i].URL = "https://" + cm.Name
		case !strings.HasPrefix(cm.URL, "https://") && !c.Dev:
			return fmt.Errorf("REROUTED_COMMUNITIES: %s's url must be https:// outside dev mode", cm.Name)
		}
		seen[cm.Name] = true
	}
	if len(c.Communities) > 0 && c.CommunityCode == "" && !c.CommunityOpen {
		return errors.New("REROUTED_COMMUNITIES needs REROUTED_COMMUNITY_CODE, the code creating a community takes, or REROUTED_COMMUNITY_OPEN=on to let anyone create one")
	}
	if c.CommunityCode != "" && len(c.CommunityCode) < 10 {
		return errors.New("REROUTED_COMMUNITY_CODE must be at least 10 characters")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("REROUTED_LOG_LEVEL must be debug, info, warn, or error, not %q", c.LogLevel)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("REROUTED_LOG_FORMAT must be text or json, not %q", c.LogFormat)
	}
	if c.MetricsListen != "" {
		if _, _, err := net.SplitHostPort(c.MetricsListen); err != nil {
			return errors.New("REROUTED_METRICS_LISTEN must be an address and port, like 127.0.0.1:9101")
		}
	}
	if c.TurnListen != "" {
		if _, port, err := net.SplitHostPort(c.TurnListen); err != nil || port == "" {
			return errors.New("REROUTED_TURN_LISTEN must be an address and port, like :3478")
		}
	}
	if c.TurnPublicIP != "" && net.ParseIP(c.TurnPublicIP) == nil {
		return errors.New("REROUTED_TURN_PUBLIC_IP must be an IP address")
	}
	if c.TurnListen != "" && c.TurnRelayIP() == nil {
		return errors.New("REROUTED_TURN_LISTEN needs REROUTED_TURN_PUBLIC_IP, the public address clients reach relayed media at")
	}
	if c.Registration == "invite" && len(c.RegistrationCode) < 10 {
		return errors.New("REROUTED_REGISTRATION=invite needs REROUTED_REGISTRATION_CODE of at least 10 characters")
	}
	return nil
}

// bytesValue reads a size in bytes, with an optional K, M, or G suffix (powers of 1024).
func bytesValue(key, v string, def int64) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	mult := int64(1)
	switch strings.ToUpper(v[len(v)-1:]) {
	case "K":
		mult, v = 1<<10, v[:len(v)-1]
	case "M":
		mult, v = 1<<20, v[:len(v)-1]
	case "G":
		mult, v = 1<<30, v[:len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a size in bytes, like 512M or 2G", key)
	}
	return n * mult, nil
}

// readDotEnv reads a settings file of KEY=value lines. A missing file reads as empty.
func readDotEnv(path string) (map[string]string, error) {
	out := map[string]string{}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out, sc.Err()
}

// TurnRelayIP is the public address of the built-in relay's media: REROUTED_TURN_PUBLIC_IP,
// else the first of REROUTED_VOICE_PUBLIC_IPS, else the address REROUTED_TURN_LISTEN names
// if it's a public one. It's nil if there's none.
func (c *Config) TurnRelayIP() net.IP {
	if ip := net.ParseIP(c.TurnPublicIP); ip != nil {
		return ip
	}
	for _, s := range c.VoicePublicIPs {
		if ip := net.ParseIP(s); ip != nil {
			return ip
		}
	}
	host, _, _ := net.SplitHostPort(c.TurnListen)
	if ip := net.ParseIP(host); ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
		return ip
	}
	return nil
}

// ClientBase is the client API base URL published in the server document (SPEC §8.1).
func (c *Config) ClientBase() string { return c.PublicURL + c.APIPath + "client/" }

// S2SBase is the S2S API base URL published in the server document (SPEC §8.1).
func (c *Config) S2SBase() string { return c.PublicURL + c.APIPath + "s2s/" }

// ClientBaseV2 and S2SBaseV2 are ClientBase and S2SBase for wire version 2.
func (c *Config) ClientBaseV2() string { return c.PublicURL + c.APIPathV2 + "client/" }
func (c *Config) S2SBaseV2() string    { return c.PublicURL + c.APIPathV2 + "s2s/" }

// CommunityBase is a community's API base URL, published in its server document (SPEC §5.1).
func (c *Config) CommunityBase(cm Community) string { return cm.URL + c.APIPathV2 + "community/" }

// CommunityS2SBase is the S2S base a community-only name lists, as SPEC §5.1 requires; it
// answers 501 there.
func (c *Config) CommunityS2SBase(cm Community) string { return cm.URL + c.APIPathV2 + "s2s/" }

// Defaults fills in the public URL and API path when they're unset.
func (c *Config) Defaults() {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LogFormat == "" {
		c.LogFormat = "text"
	}
	if c.live == nil {
		c.live = &live{}
		c.live.level.Set(levelOf(c.LogLevel))
	}
	if c.MediaQuota == 0 {
		c.MediaQuota = 1 << 30
	}
	if c.BackupQuota == 0 {
		c.BackupQuota = 1 << 30
	}
	if c.CommunityFileQuota == 0 {
		c.CommunityFileQuota = 10 << 30
	}
	if c.CommunityHistoryQuota == 0 {
		c.CommunityHistoryQuota = 10 << 30
	}
	if c.PublicURL == "" {
		c.PublicURL = "https://" + c.Name
	}
	if c.APIPath == "" {
		c.APIPath = "/.well-known/tieroute/v1/"
	}
	if c.APIPathV2 == "" {
		c.APIPathV2 = "/.well-known/tieroute/v2/"
	}
	c.APIPath, c.APIPathV2 = slashed(c.APIPath), slashed(c.APIPathV2)
}

// slashed makes an API path start and end with "/".
func slashed(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}
