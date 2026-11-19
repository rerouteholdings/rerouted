package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// loadFile writes body to a settings file and loads it, undoing what Load put in the
// environment when the test ends.
func loadFile(t *testing.T, body string) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "rerouted.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		fromFile.mu.Lock()
		for k := range fromFile.keys {
			os.Unsetenv(k)
		}
		fromFile.keys = map[string]bool{}
		fromFile.mu.Unlock()
	})
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

const baseEnv = `REROUTED_NAME=chat.example
REROUTED_REGISTRATION=invite
REROUTED_REGISTRATION_CODE=first-code-123
REROUTED_MEDIA_QUOTA=1G
`

func TestReload(t *testing.T) {
	c, p := loadFile(t, baseEnv)
	var logs bytes.Buffer
	log := c.Logger(&logs)
	log.Debug("hidden")
	if logs.Len() != 0 {
		t.Fatal("debug logged at the default level")
	}
	os.WriteFile(p, []byte(`REROUTED_NAME=other.example
REROUTED_LISTEN=127.0.0.1:9000
REROUTED_REGISTRATION=invite
REROUTED_REGISTRATION_CODE=second-code-456
REROUTED_REGISTRATION_PUBLIC=on
REROUTED_MEDIA_QUOTA=2G
REROUTED_PAUSE_MOVES=on
REROUTED_LOG_LEVEL=debug
REROUTED_UPDATE_CHECK=on
`), 0o600)
	need, err := c.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"REROUTED_LISTEN", "REROUTED_NAME", "REROUTED_PUBLIC_URL"}; !slices.Equal(need, want) {
		t.Fatalf("needs a restart: %v, want %v", need, want)
	}
	now := c.Now()
	if now.RegistrationCode != "second-code-456" || !now.RegistrationPublic || now.MediaQuota != 2<<30 || !now.PauseMoves || !now.UpdateCheck {
		t.Fatalf("reloaded settings: %+v", now)
	}
	if c.Name != "chat.example" || c.Listen != "127.0.0.1:8080" {
		t.Fatalf("restart-only settings changed: %s %s", c.Name, c.Listen)
	}
	log.Debug("shown")
	if !strings.Contains(logs.String(), "shown") {
		t.Fatal("the log level didn't follow the reload")
	}

	// A file that doesn't check out keeps everything as it was.
	os.WriteFile(p, []byte(baseEnv+"REROUTED_REGISTRATION_CODE=short\nREROUTED_LOG_LEVEL=loud\n"), 0o600)
	if _, err := c.Reload(); err == nil {
		t.Fatal("a bad file reloaded")
	}
	os.WriteFile(p, []byte("not a setting\n"), 0o600)
	if _, err := c.Reload(); err == nil {
		t.Fatal("an unreadable file reloaded")
	}
	if now := c.Now(); now.RegistrationCode != "second-code-456" || now.LogLevel != "debug" {
		t.Fatalf("a failed reload changed settings: %+v", now)
	}
}

// The environment still wins over the file on a reload, as it does at the start.
func TestReloadEnvironmentWins(t *testing.T) {
	t.Setenv("REROUTED_BACKUP_QUOTA", "5M")
	c, p := loadFile(t, baseEnv+"REROUTED_BACKUP_QUOTA=1M\n")
	if c.Now().BackupQuota != 5<<20 {
		t.Fatal("the file won over the environment")
	}
	os.WriteFile(p, []byte(baseEnv+"REROUTED_BACKUP_QUOTA=2M\n"), 0o600)
	if _, err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := c.Now().BackupQuota; got != 5<<20 {
		t.Fatalf("BackupQuota = %d after reload", got)
	}
}

func TestBuiltinRelayURLsAndSecret(t *testing.T) {
	dir := t.TempDir()
	c, p := loadFile(t, baseEnv+"REROUTED_DATA_DIR="+dir+"\nREROUTED_TURN_LISTEN=:3478\nREROUTED_TURN_PUBLIC_IP=203.0.113.7\n")
	want := []string{"turn:chat.example:3478?transport=udp", "turn:chat.example:3478?transport=tcp"}
	if !slices.Equal(c.Now().TurnURLs, want) {
		t.Fatalf("TurnURLs = %v", c.Now().TurnURLs)
	}
	secret := c.Now().TurnSecret
	if len(secret) < 32 {
		t.Fatalf("secret %q", secret)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, turnSecretName)); strings.TrimSpace(string(b)) != secret {
		t.Fatal("the secret wasn't kept in the data directory")
	}
	// A reload that moves the relay keeps advertising the one that's running.
	os.WriteFile(p, []byte(baseEnv+"REROUTED_DATA_DIR="+dir+"\nREROUTED_TURN_LISTEN=:3479\nREROUTED_TURN_PUBLIC_IP=203.0.113.7\n"), 0o600)
	need, err := c.Reload()
	if err != nil || !slices.Equal(need, []string{"REROUTED_TURN_LISTEN"}) {
		t.Fatal(need, err)
	}
	if !slices.Equal(c.Now().TurnURLs, want) || c.Now().TurnSecret != secret {
		t.Fatalf("after reload: %v", c.Now().TurnURLs)
	}
}

func TestLogFormat(t *testing.T) {
	c := &Config{LogFormat: "json", LogLevel: "warn"}
	var b bytes.Buffer
	l := c.Logger(&b)
	l.Info("no")
	l.Warn("yes")
	if !strings.HasPrefix(b.String(), "{") || strings.Contains(b.String(), `"no"`) {
		t.Fatalf("log: %s", b.String())
	}
	if l.Enabled(t.Context(), slog.LevelInfo) {
		t.Fatal("info enabled at warn")
	}
}

// Every setting is either reloadable or named as needing a restart.
func TestEverySettingClassified(t *testing.T) {
	rt := reflect.TypeFor[Reloadable]()
	for f := range reflect.TypeFor[Config]().Fields() {
		if !f.IsExported() {
			continue
		}
		if _, ok := rt.FieldByName(f.Name); ok {
			continue
		}
		if restartOnly[f.Name] == "" {
			t.Errorf("Config.%s is neither in Reloadable nor in restartOnly", f.Name)
		}
	}
	// reloadable and setReloadable cover every field.
	c := &Config{}
	r := Reloadable{}
	rv := reflect.ValueOf(&r).Elem()
	for i := range rv.NumField() {
		switch f := rv.Field(i); f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64:
			f.SetInt(7)
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"x"}))
		}
	}
	c.setReloadable(r)
	if got := c.reloadable(); !reflect.DeepEqual(got, r) {
		t.Fatalf("round trip: %+v", got)
	}
}
