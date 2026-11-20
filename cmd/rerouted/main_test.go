package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// capture runs f with stdout and stderr redirected, and returns what it printed.
func capture(t *testing.T, f func() int) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	code := f()
	os.Stdout, os.Stderr = oldOut, oldErr
	w.Close()
	return code, <-done
}

// clearRerouted unsets REROUTED_ variables, which config.Load sets from settings files,
// before and after a test.
func clearRerouted(t *testing.T) {
	t.Helper()
	clear := func() {
		for _, kv := range os.Environ() {
			if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "REROUTED_") {
				os.Unsetenv(k)
			}
		}
	}
	clear()
	t.Cleanup(clear)
}

// writeEnv writes a settings file for a server with its data in dir.
func writeEnv(t *testing.T, dir string, extra ...string) string {
	t.Helper()
	path := filepath.Join(dir, "test.env")
	lines := append([]string{
		"REROUTED_NAME=chat.example",
		"REROUTED_HANDLES=chat.example",
		"REROUTED_LISTEN=127.0.0.1:1",
		"REROUTED_DATA_DIR=" + filepath.Join(dir, "data"),
	}, extra...)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHelpListsEveryCommand(t *testing.T) {
	code, out := capture(t, func() int { return run([]string{"help"}) })
	if code != 0 {
		t.Fatal(code)
	}
	for _, c := range commands {
		if !strings.Contains(out, "  "+c.usage) {
			t.Errorf("help is missing %s", c.name)
		}
	}
	if code, out2 := capture(t, func() int { return run([]string{"-h"}) }); code != 0 || out2 != out {
		t.Fatal("-h differs from help")
	}
	if code, _ := capture(t, func() int { return run([]string{"no-such-command"}) }); code != 2 {
		t.Fatalf("unknown command: exit %d", code)
	}
}

func TestVersion(t *testing.T) {
	code, out := capture(t, func() int { return run([]string{"version"}) })
	if code != 0 || !strings.Contains(out, "schema:   ") || !strings.Contains(out, "wire:     1, 2") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestEnvFileSearch(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	old := envSearch
	defer func() { envSearch = old }()
	packaged := filepath.Join(dir, "etc-rerouted.env")
	envSearch = []string{".env", packaged}
	if got := defaultEnvFile(); got != ".env" {
		t.Fatalf("nothing there: %q", got)
	}
	os.WriteFile(packaged, nil, 0o600)
	if got := defaultEnvFile(); got != packaged {
		t.Fatalf("packaged only: %q", got)
	}
	os.WriteFile(".env", nil, 0o600)
	if got := defaultEnvFile(); got != ".env" {
		t.Fatalf(".env first: %q", got)
	}
}

func TestEnvFlagMustExist(t *testing.T) {
	clearRerouted(t)
	code, out := capture(t, func() int { return run([]string{"-env", filepath.Join(t.TempDir(), "missing.env"), "accounts"}) })
	if code == 0 || !strings.Contains(out, "missing.env") {
		t.Fatalf("%d %s", code, out)
	}
}

// TestKnownKeys makes sure every setting internal/config reads is known to config check.
func TestKnownKeys(t *testing.T) {
	files, _ := filepath.Glob("../../internal/config/*.go")
	re := regexp.MustCompile(`"(REROUTED_[A-Z0-9_]+)"`)
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			found++
			if !slices.Contains(knownKeys, m[1]) {
				t.Errorf("%s reads %s: add it to knownKeys in configcheck.go", f, m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("found no settings in internal/config")
	}
}

func TestConfigCheckProxyKeys(t *testing.T) {
	clearRerouted(t)
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("NO_PROXY", "chat.example")
	dir := t.TempDir()
	env := writeEnv(t, dir, "HTTPS_PROXY=http://proxy.example:3128", "NO_PROXY=chat.example", "HTTPS_PROXI=x")
	code, out := capture(t, func() int { return run([]string{"-env", env, "config", "check"}) })
	if code != 0 || strings.Contains(out, "HTTPS_PROXY isn't") || strings.Contains(out, "NO_PROXY isn't") || !strings.Contains(out, "HTTPS_PROXI isn't") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestConfigCheck(t *testing.T) {
	clearRerouted(t)
	dir := t.TempDir()
	env := writeEnv(t, dir, "REROUTED_REGISTRATON=invite")
	code, out := capture(t, func() int { return run([]string{"-env", env, "config", "check"}) })
	if code != 0 || !strings.Contains(out, "did you mean REROUTED_REGISTRATION?") {
		t.Fatalf("%d %s", code, out)
	}

	clearRerouted(t)
	bad := filepath.Join(dir, "bad.env")
	os.WriteFile(bad, []byte("REROUTED_LISTEN=8080\n"), 0o600)
	code, out = capture(t, func() int { return run([]string{"-env", bad, "config", "check"}) })
	if code != 1 || !strings.Contains(out, "REROUTED_NAME is required") {
		t.Fatalf("missing name: %d %s", code, out)
	}

	clearRerouted(t)
	os.WriteFile(bad, []byte("REROUTED_NAME=chat.example\nREROUTED_LISTEN=8080\n"), 0o600)
	code, out = capture(t, func() int { return run([]string{"-env", bad, "config", "check"}) })
	if code != 1 || !strings.Contains(out, "isn't host:port") {
		t.Fatalf("bad listen: %d %s", code, out)
	}

	clearRerouted(t)
	os.WriteFile(bad, []byte("REROUTED_NAME=chat.example\nREROUTED_TURN_URLS=turn:chat.example:3478\n"), 0o600)
	code, out = capture(t, func() int { return run([]string{"-env", bad, "config", "check"}) })
	if code != 1 || !strings.Contains(out, "REROUTED_TURN_SECRET") {
		t.Fatalf("TURN without a secret: %d %s", code, out)
	}
}

func TestEditDistance(t *testing.T) {
	if d := editDistance("REROUTED_LISTN", "REROUTED_LISTEN"); d != 1 {
		t.Fatal(d)
	}
	if s := closestKey("REROUTED_COMPLETELY_ELSE"); s != "" {
		t.Fatalf("suggested %s for something unlike any setting", s)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	clearRerouted(t)
	ctx := context.Background()
	dir := t.TempDir()
	env := writeEnv(t, dir)
	data := filepath.Join(dir, "data")
	os.MkdirAll(filepath.Join(data, "media", "community", "c.example", "media"), 0o700)
	st, err := sqlite.Open(filepath.Join(data, dbName))
	if err != nil {
		t.Fatal(err)
	}
	addVectorChain(t, st)
	os.WriteFile(filepath.Join(data, "server-key.json"), []byte(`{"k":1}`), 0o600)
	os.WriteFile(filepath.Join(data, "server-key-v2.json"), []byte(`{"k":2}`), 0o600)
	os.WriteFile(filepath.Join(data, "media", "abcd"), []byte("file bytes"), 0o600)
	os.WriteFile(filepath.Join(data, "media", "community", "c.example", "media", "ef"), []byte("community file"), 0o600)
	os.WriteFile(filepath.Join(data, "limits.json"), []byte("{}"), 0o600)

	// Backed up while the store is open, as it is while the server runs.
	dest := filepath.Join(dir, "backups")
	os.Mkdir(dest, 0o700)
	code, out := capture(t, func() int { return run([]string{"-env", env, "backup", dest}) })
	st.Close()
	if code != 0 {
		t.Fatalf("backup: %d %s", code, out)
	}
	archives, _ := filepath.Glob(filepath.Join(dest, "rerouted-backup-chat.example-*.tar.gz"))
	if len(archives) != 1 {
		t.Fatalf("archives: %v", archives)
	}
	if fi, _ := os.Stat(archives[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode %v", fi.Mode().Perm())
	}
	if left, _ := filepath.Glob(filepath.Join(dest, ".*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}

	// Into a new, empty data directory.
	clearRerouted(t)
	dir2 := t.TempDir()
	env2 := writeEnv(t, dir2)
	data2 := filepath.Join(dir2, "data")
	code, out = capture(t, func() int { return run([]string{"-env", env2, "restore", archives[0]}) })
	if code != 0 {
		t.Fatalf("restore: %d %s", code, out)
	}
	for rel, want := range map[string]string{
		"server-key.json":                    `{"k":1}`,
		"server-key-v2.json":                 `{"k":2}`,
		"media/abcd":                         "file bytes",
		"media/community/c.example/media/ef": "community file",
	} {
		if b, err := os.ReadFile(filepath.Join(data2, rel)); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", rel, b, err)
		}
	}
	for _, gone := range []string{"limits.json", settingsName, manifestName} {
		if _, err := os.Stat(filepath.Join(data2, gone)); err == nil {
			t.Errorf("%s was restored into the data directory", gone)
		}
	}
	ro, err := sqlite.OpenReadOnly(filepath.Join(data2, dbName))
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := loadAccounts(ctx, ro)
	ro.Close()
	if err != nil || len(accounts) != 1 || accounts[0].Handle != "kat.chat.example" || accounts[0].Devices != 1 {
		t.Fatalf("restored accounts %+v %v", accounts, err)
	}

	// Again: there's a database now.
	code, out = capture(t, func() int { return run([]string{"-env", env2, "restore", archives[0]}) })
	if code == 0 || !strings.Contains(out, "--force") {
		t.Fatalf("restore over a database: %d %s", code, out)
	}

	// Not while the server runs.
	writeStatus(t, data2, time.Now(), 0)
	code, out = capture(t, func() int { return run([]string{"-env", env2, "restore", "--force", archives[0]}) })
	if code == 0 || !strings.Contains(out, "running") {
		t.Fatalf("restore while running: %d %s", code, out)
	}

	// --force moves the current data aside first.
	writeStatus(t, data2, time.Now().Add(-time.Hour), 0)
	os.WriteFile(filepath.Join(data2, "server-key.json"), []byte("newer"), 0o600)
	code, out = capture(t, func() int { return run([]string{"-env", env2, "restore", archives[0], "--force"}) })
	if code != 0 {
		t.Fatalf("restore --force: %d %s", code, out)
	}
	aside, _ := filepath.Glob(filepath.Join(data2, asidePrefix+"*", "server-key.json"))
	if len(aside) != 1 {
		t.Fatal("current data not moved aside")
	}
	if b, _ := os.ReadFile(aside[0]); string(b) != "newer" {
		t.Fatal("moved-aside key differs")
	}
	if b, _ := os.ReadFile(filepath.Join(data2, "server-key.json")); string(b) != `{"k":1}` {
		t.Fatal("key not restored")
	}

	// A later backup leaves the moved-aside data out.
	code, _ = capture(t, func() int { return run([]string{"-env", env2, "backup", filepath.Join(dir2, "again.tar.gz")}) })
	if code != 0 {
		t.Fatal("second backup failed")
	}
	tarList, _ := exec.Command("tar", "-tzf", filepath.Join(dir2, "again.tar.gz")).Output()
	if strings.Contains(string(tarList), asidePrefix) || strings.Contains(string(tarList), "status.json") {
		t.Fatalf("second backup holds:\n%s", tarList)
	}
}

func TestRestoreRefusesEscapes(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tar.gz")
	// A tar holding ../escape, made with Go's own writer.
	if err := writeTestArchive(archive, map[string]string{manifestName: `{"format":1}`, "../escape": "x"}); err != nil {
		t.Fatal(err)
	}
	if err := restore(archive, filepath.Join(dir, "data"), "chat.example", false, time.Now()); err == nil {
		t.Fatal("restored an archive with ../")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape")); err == nil {
		t.Fatal("wrote outside the data directory")
	}
}

func writeStatus(t *testing.T, dataDir string, updated time.Time, pid int) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"version": "0.0.1", "pid": pid, "started": updated.Add(-time.Hour).Unix(), "updated": updated.Format(time.RFC3339), "name": "chat.example"})
	if err := os.WriteFile(filepath.Join(dataDir, "status.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunning(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if yes, _, _ := running(dir, now); yes {
		t.Fatal("running without status.json")
	}
	writeStatus(t, dir, now.Add(-10*time.Second), 0)
	if yes, s, _ := running(dir, now); !yes || s.Version != "0.0.1" || s.Started.IsZero() {
		t.Fatalf("fresh status: %v %+v", yes, s)
	}
	writeStatus(t, dir, now.Add(-5*time.Minute), 0)
	if yes, _, _ := running(dir, now); yes {
		t.Fatal("stale status counted as running")
	}
	writeStatus(t, dir, now.Add(-5*time.Minute), os.Getpid())
	if yes, _, why := running(dir, now); !yes || !strings.Contains(why, "alive") {
		t.Fatal("a live process not noticed")
	}
}

func TestStatusAndAccounts(t *testing.T) {
	clearRerouted(t)
	dir := t.TempDir()
	env := writeEnv(t, dir, "REROUTED_COMMUNITIES=talk.example", "REROUTED_COMMUNITY_CODE=0123456789")
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	st, err := sqlite.Open(filepath.Join(data, dbName))
	if err != nil {
		t.Fatal(err)
	}
	addVectorChain(t, st)
	st.Close()
	writeStatus(t, data, time.Now(), os.Getpid())

	code, out := capture(t, func() int { return run([]string{"-env", env, "status"}) })
	if code != 0 || !strings.Contains(out, "running:          yes") || !strings.Contains(out, "restart rerouted to run it") ||
		!strings.Contains(out, "identities:       1, with 1 devices") {
		t.Fatalf("status: %d\n%s", code, out)
	}
	code, out = capture(t, func() int { return run([]string{"-env", env, "status", "--json"}) })
	var r statusReport
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || !r.Running || !r.RestartDue || r.Database.Accounts != 1 {
		t.Fatalf("status --json: %d\n%s", code, out)
	}
	code, out = capture(t, func() int { return run([]string{"-env", env, "accounts"}) })
	if code != 0 || !strings.Contains(out, "@kat.chat.example") || !strings.Contains(out, "tr:") {
		t.Fatalf("accounts: %d\n%s", code, out)
	}
	code, out = capture(t, func() int { return run([]string{"-env", env, "communities"}) })
	if code != 0 || !strings.Contains(out, "talk.example") || !strings.Contains(out, "not created yet") {
		t.Fatalf("communities: %d\n%s", code, out)
	}
}

func TestCompletion(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		code, out := capture(t, func() int { return run([]string{"completion", shell}) })
		if code != 0 {
			t.Fatal(shell, code)
		}
		for _, c := range commands {
			if !strings.Contains(out, c.name) {
				t.Errorf("%s completion is missing %s", shell, c.name)
			}
		}
		if bin, err := exec.LookPath(shell); err == nil {
			f := filepath.Join(t.TempDir(), "completion")
			os.WriteFile(f, []byte(out), 0o600)
			args := []string{"-n", f}
			if shell == "fish" {
				args = []string{"--no-execute", f}
			}
			if msg, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
				t.Errorf("%s -n: %v %s", shell, err, msg)
			}
		}
	}
}
