// Package config loads rerouted settings from the environment and an optional .env file.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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
}

// Community is one server name this process serves as a community server.
type Community struct {
	Name string
	URL  string // the origin it's reached at, without a trailing slash
}

// Load reads .env (if present, without overriding variables already set),
// then the environment.
func Load(envFile string) (*Config, error) {
	if err := loadDotEnv(envFile); err != nil {
		return nil, err
	}
	c := &Config{
		Name:               os.Getenv("REROUTED_NAME"),
		Listen:             get("REROUTED_LISTEN", "127.0.0.1:8080"),
		DataDir:            get("REROUTED_DATA_DIR", "./data"),
		PublicURL:          strings.TrimRight(os.Getenv("REROUTED_PUBLIC_URL"), "/"),
		APIPath:            get("REROUTED_API_PATH", "/.well-known/tieroute/v1/"),
		APIPathV2:          get("REROUTED_API_PATH_V2", "/.well-known/tieroute/v2/"),
		Handles:            os.Getenv("REROUTED_HANDLES"),
		Registration:       get("REROUTED_REGISTRATION", "closed"),
		Store:              get("REROUTED_STORE", "sqlite"),
		Dev:                get("REROUTED_DEV", "off") == "on",
		Peers:              map[string]string{},
		RegistrationCode:   os.Getenv("REROUTED_REGISTRATION_CODE"),
		RegistrationPublic: get("REROUTED_REGISTRATION_PUBLIC", "off") == "on",
		PublicFirehose:     get("REROUTED_PUBLIC_FIREHOSE", "off") == "on",
		PauseMoves:         get("REROUTED_PAUSE_MOVES", "off") == "on",
	}
	c.Defaults()
	for _, u := range strings.Split(os.Getenv("REROUTED_TLS_ASK_ALSO"), ",") {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			c.TLSAskAlso = append(c.TLSAskAlso, u)
		}
	}
	for _, h := range strings.Split(os.Getenv("REROUTED_TLS_ASK_ALLOW"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			c.TLSAskAllow = append(c.TLSAskAllow, h)
		}
	}
	for _, u := range strings.Split(os.Getenv("REROUTED_TURN_URLS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			c.TurnURLs = append(c.TurnURLs, u)
		}
	}
	c.TurnSecret = os.Getenv("REROUTED_TURN_SECRET")
	var err error
	if c.MediaQuota, err = bytesSetting("REROUTED_MEDIA_QUOTA", 1<<30); err != nil {
		return nil, err
	}
	if c.BackupQuota, err = bytesSetting("REROUTED_BACKUP_QUOTA", 1<<30); err != nil {
		return nil, err
	}
	for _, p := range strings.Split(os.Getenv("REROUTED_COMMUNITIES"), ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		name, url, _ := strings.Cut(p, "=")
		c.Communities = append(c.Communities, Community{Name: strings.ToLower(strings.TrimSpace(name)), URL: strings.TrimRight(strings.TrimSpace(url), "/")})
	}
	c.CommunityCode = os.Getenv("REROUTED_COMMUNITY_CODE")
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
	for _, ip := range strings.Split(os.Getenv("REROUTED_VOICE_PUBLIC_IPS"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			c.VoicePublicIPs = append(c.VoicePublicIPs, ip)
		}
	}
	for _, p := range strings.Split(os.Getenv("REROUTED_DEV_PEERS"), ",") {
		if name, url, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			c.Peers[name] = strings.TrimRight(url, "/")
		}
	}
	return c, c.validate()
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
	if c.Registration == "invite" && len(c.RegistrationCode) < 10 {
		return errors.New("REROUTED_REGISTRATION=invite needs REROUTED_REGISTRATION_CODE of at least 10 characters")
	}
	return nil
}

// bytesSetting reads a size in bytes, with an optional K, M, or G suffix (powers of 1024).
func bytesSetting(key string, def int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(key))
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

func get(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
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
			return fmt.Errorf("%s:%d: expected KEY=value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
	return sc.Err()
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
