package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
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
