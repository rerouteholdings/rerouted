package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Reloadable is the part of the settings a running server takes up again when it reloads
// (SIGHUP), without a restart. Code that runs while the server does reads these through
// Config.Now, never from the Config's own fields, which keep their values from the start.
type Reloadable struct {
	Registration          string
	RegistrationCode      string
	RegistrationPublic    bool
	PauseMoves            bool
	TurnURLs              []string
	TurnSecret            string
	MediaQuota            int64
	BackupQuota           int64
	CommunityCode         string
	CommunityOpen         bool
	CommunityFileDays     int
	CommunityFileQuota    int64
	CommunityHistoryQuota int64
	TLSAskAllow           []string
	LogLevel              string
	UpdateCheck           bool
	RestartMaxWait        time.Duration
}

// live holds a Config's reloadable settings once it has been reloaded. Copies of a Config
// share it, so every part of the server sees a reload.
type live struct {
	mu    sync.Mutex // one Reload at a time
	cur   atomic.Pointer[Reloadable]
	level slog.LevelVar
}

// Now returns the reloadable settings' current values. Until the first reload they're the
// Config's own fields.
func (c *Config) Now() Reloadable {
	if c.live != nil {
		if r := c.live.cur.Load(); r != nil {
			return *r
		}
	}
	return c.reloadable()
}

func (c *Config) reloadable() Reloadable {
	return Reloadable{
		Registration:          c.Registration,
		RegistrationCode:      c.RegistrationCode,
		RegistrationPublic:    c.RegistrationPublic,
		PauseMoves:            c.PauseMoves,
		TurnURLs:              c.TurnURLs,
		TurnSecret:            c.TurnSecret,
		MediaQuota:            c.MediaQuota,
		BackupQuota:           c.BackupQuota,
		CommunityCode:         c.CommunityCode,
		CommunityOpen:         c.CommunityOpen,
		CommunityFileDays:     c.CommunityFileDays,
		CommunityFileQuota:    c.CommunityFileQuota,
		CommunityHistoryQuota: c.CommunityHistoryQuota,
		TLSAskAllow:           c.TLSAskAllow,
		LogLevel:              c.LogLevel,
		UpdateCheck:           c.UpdateCheck,
		RestartMaxWait:        c.RestartMaxWait,
	}
}

// setReloadable sets c's reloadable fields to r's.
func (c *Config) setReloadable(r Reloadable) {
	c.Registration, c.RegistrationCode, c.RegistrationPublic = r.Registration, r.RegistrationCode, r.RegistrationPublic
	c.PauseMoves, c.TurnURLs, c.TurnSecret = r.PauseMoves, r.TurnURLs, r.TurnSecret
	c.MediaQuota, c.BackupQuota = r.MediaQuota, r.BackupQuota
	c.CommunityCode, c.CommunityOpen, c.CommunityFileDays = r.CommunityCode, r.CommunityOpen, r.CommunityFileDays
	c.CommunityFileQuota, c.CommunityHistoryQuota = r.CommunityFileQuota, r.CommunityHistoryQuota
	c.TLSAskAllow, c.LogLevel, c.UpdateCheck, c.RestartMaxWait = r.TLSAskAllow, r.LogLevel, r.UpdateCheck, r.RestartMaxWait
}

// restartOnly names the settings behind each field that only a restart changes.
var restartOnly = map[string]string{
	"Name":           "REROUTED_NAME",
	"Listen":         "REROUTED_LISTEN",
	"DataDir":        "REROUTED_DATA_DIR",
	"PublicURL":      "REROUTED_PUBLIC_URL",
	"APIPath":        "REROUTED_API_PATH",
	"APIPathV2":      "REROUTED_API_PATH_V2",
	"Handles":        "REROUTED_HANDLES",
	"Store":          "REROUTED_STORE",
	"Dev":            "REROUTED_DEV",
	"Peers":          "REROUTED_DEV_PEERS",
	"TLSAskAlso":     "REROUTED_TLS_ASK_ALSO",
	"PublicFirehose": "REROUTED_PUBLIC_FIREHOSE",
	"Communities":    "REROUTED_COMMUNITIES",
	"VoiceUDPPort":   "REROUTED_VOICE_UDP_PORT",
	"VoicePublicIPs": "REROUTED_VOICE_PUBLIC_IPS",
	"LogFormat":      "REROUTED_LOG_FORMAT",
	"MetricsListen":  "REROUTED_METRICS_LISTEN",
	"TurnListen":     "REROUTED_TURN_LISTEN",
	"TurnRelayMin":   "REROUTED_TURN_RELAY_PORTS",
	"TurnRelayMax":   "REROUTED_TURN_RELAY_PORTS",
	"TurnPublicIP":   "REROUTED_TURN_PUBLIC_IP",
	"APNSKeyFile":    "REROUTED_APNS_KEY_FILE",
	"APNSKeyID":      "REROUTED_APNS_KEY_ID",
	"APNSTeamID":     "REROUTED_APNS_TEAM_ID",
	"APNSTopic":      "REROUTED_APNS_TOPIC",
}

// Reload reads the settings file Load read again, with the environment, and applies the
// reloadable settings (Reloadable). It returns the settings that changed but need a restart,
// which keep their old values. On an error nothing changes.
func (c *Config) Reload() (needRestart []string, err error) {
	if c.live == nil {
		c.Defaults()
	}
	c.live.mu.Lock()
	defer c.live.mu.Unlock()
	file, err := readDotEnv(c.envFile)
	if err != nil {
		return nil, err
	}
	fromFile.mu.Lock()
	keys := fromFile.keys
	lookup := func(k string) (string, bool) {
		if !keys[k] {
			if v, ok := os.LookupEnv(k); ok {
				return v, true
			}
		}
		v, ok := file[k]
		return v, ok
	}
	n, err := parse(lookup)
	fromFile.mu.Unlock()
	if err != nil {
		return nil, err
	}
	n.envFile = c.envFile
	if err := n.finish(); err != nil {
		return nil, err
	}
	return c.apply(n)
}

// apply takes n's reloadable settings, and lists the settings n changes that need a restart.
func (c *Config) apply(n *Config) ([]string, error) {
	var needRestart []string
	ov, nv := reflect.ValueOf(c).Elem(), reflect.ValueOf(n).Elem()
	for field, env := range restartOnly {
		if !reflect.DeepEqual(ov.FieldByName(field).Interface(), nv.FieldByName(field).Interface()) && !slices.Contains(needRestart, env) {
			needRestart = append(needRestart, env)
		}
	}
	slices.Sort(needRestart)
	r := n.reloadable()
	// A relay URL rerouted made for its built-in relay follows the relay that's running.
	if n.turnDerived || n.turnSecretFile {
		old := c.Now()
		if c.TurnListen == "" {
			if n.turnDerived {
				r.TurnURLs = nil
			}
			if n.turnSecretFile {
				r.TurnSecret = ""
			}
		} else {
			if n.turnDerived {
				r.TurnURLs = c.builtinTurnURLs()
			}
			if n.turnSecretFile {
				r.TurnSecret = old.TurnSecret
			}
		}
	}
	eff := *c
	eff.setReloadable(r)
	eff.Communities = append([]Community(nil), c.Communities...)
	if err := eff.validate(); err != nil {
		return nil, err
	}
	c.live.cur.Store(&r)
	c.live.level.Set(levelOf(r.LogLevel))
	return needRestart, nil
}

// builtinTurnURLs are the URLs advertised for the built-in relay.
func (c *Config) builtinTurnURLs() []string {
	_, port, err := net.SplitHostPort(c.TurnListen)
	if err != nil || port == "" {
		return nil
	}
	return []string{
		"turn:" + c.Name + ":" + port + "?transport=udp",
		"turn:" + c.Name + ":" + port + "?transport=tcp",
	}
}

// levelOf turns a REROUTED_LOG_LEVEL value into a slog level.
func levelOf(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// turnSecretName is the file in the data directory that holds the built-in relay's secret
// when REROUTED_TURN_SECRET isn't set.
const turnSecretName = "turn-secret"

// loadOrCreateTurnSecret reads the built-in relay's secret from the data directory, making
// a random one the first time.
func loadOrCreateTurnSecret(dir string) (string, error) {
	p := filepath.Join(dir, turnSecretName)
	b, err := os.ReadFile(p)
	if err == nil {
		if s := strings.TrimSpace(string(b)); len(s) >= 16 {
			return s, nil
		}
		return "", fmt.Errorf("%s holds less than 16 characters", p)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	buf := make([]byte, 32)
	rand.Read(buf)
	s := hex.EncodeToString(buf)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateTurnSecret(dir) // made at the same moment by another start
	}
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(s + "\n"); err != nil {
		f.Close()
		return "", err
	}
	return s, f.Close()
}
