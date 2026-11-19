package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
)

// fakeSystem swaps auto-updates' view of the system, and records the commands it runs.
type fakeSystem struct {
	ran   []string
	owned string // "dpkg", "rpm", or ""
	timer bool   // the timer unit is installed
}

func withSystem(t *testing.T, osRelease, exe string, root bool, f *fakeSystem) {
	t.Helper()
	dir := t.TempDir()
	rel := filepath.Join(dir, "os-release")
	os.WriteFile(rel, []byte(osRelease), 0o644)
	oldRel, oldExe, oldRun, oldRoot, oldBin := osReleaseFile, executable, sysRun, sysRoot, packagedBinary
	t.Cleanup(func() {
		osReleaseFile, executable, sysRun, sysRoot, packagedBinary = oldRel, oldExe, oldRun, oldRoot, oldBin
	})
	osReleaseFile = rel
	packagedBinary = filepath.Join(dir, "rerouted")
	os.WriteFile(packagedBinary, nil, 0o755)
	if exe == "packaged" {
		exe = packagedBinary
	}
	executable = func() (string, error) { return exe, nil }
	sysRoot = func() bool { return root }
	sysRun = func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		f.ran = append(f.ran, cmd)
		switch {
		case name == "dpkg" || name == "rpm":
			if f.owned == name {
				return "rerouted: " + packagedBinary, nil
			}
			return "", errors.New("not owned")
		case strings.HasPrefix(cmd, "systemctl cat"):
			if f.timer {
				return "[Timer]", nil
			}
			return "", errors.New("no such unit")
		case strings.HasPrefix(cmd, "systemctl show "+updateTimer):
			return "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nLastTriggerUSec=Tue 2026-11-17 04:12:00 UTC\nNextElapseUSecRealtime=Wed 2026-11-18 04:10:00 UTC\n", nil
		case strings.HasPrefix(cmd, "systemctl show "+updateService):
			return "Result=success\nExecMainStatus=0\n", nil
		}
		return "", nil
	}
}

func TestAutoUpdatesOn(t *testing.T) {
	f := &fakeSystem{owned: "dpkg", timer: true}
	withSystem(t, "ID=debian\n", "packaged", true, f)
	var out, errw bytes.Buffer
	if code := autoUpdates(&out, &errw, []string{"on"}); code != 0 {
		t.Fatalf("%d %s", code, errw.String())
	}
	if f.ran[len(f.ran)-1] != "systemctl enable --now "+updateTimer {
		t.Fatalf("ran %v", f.ran)
	}
	out.Reset()
	if code := autoUpdates(&out, &errw, []string{"off"}); code != 0 || f.ran[len(f.ran)-1] != "systemctl disable --now "+updateTimer {
		t.Fatalf("off: %d %v", code, f.ran)
	}
	out.Reset()
	if code := autoUpdates(&out, &errw, []string{"status"}); code != 0 || !strings.Contains(out.String(), "automatic updates: on") ||
		!strings.Contains(out.String(), "(success)") {
		t.Fatalf("status: %d %s", code, out.String())
	}
}

func TestAutoUpdatesRefusals(t *testing.T) {
	for _, c := range []struct {
		name, osRelease, exe string
		owned                string
		root                 bool
		want                 string
	}{
		{"arch", "ID=arch\n", "packaged", "", true, "pacman -Syu"},
		{"manjaro", "ID=manjaro\nID_LIKE=arch\n", "packaged", "", true, "pacman -Syu"},
		{"gentoo", "ID=gentoo\n", "packaged", "", true, "Gentoo"},
		{"not packaged", "ID=debian\n", "/usr/local/bin/rerouted", "dpkg", true, "not the package's"},
		{"no owner", "ID=fedora\n", "packaged", "", true, "No package owns"},
		{"not root", "ID=fedora\n", "packaged", "rpm", false, "sudo rerouted auto-updates on"},
	} {
		f := &fakeSystem{owned: c.owned, timer: true}
		withSystem(t, c.osRelease, c.exe, c.root, f)
		var out, errw bytes.Buffer
		if code := autoUpdates(&out, &errw, []string{"on"}); code == 0 || !strings.Contains(errw.String(), c.want) {
			t.Errorf("%s: %d %s", c.name, code, errw.String())
		}
		for _, r := range f.ran {
			if strings.Contains(r, "enable") {
				t.Errorf("%s: ran %s", c.name, r)
			}
		}
	}
}

// testInitDeps sets init up in temporary directories, with a fake caddy.
func testInitDeps(t *testing.T, root bool, caddyfile string) (*initDeps, *bytes.Buffer, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a shell")
	}
	dir := t.TempDir()
	out := &bytes.Buffer{}
	d := &initDeps{
		in:  bufio.NewReader(strings.NewReader("")),
		out: out, errw: out,
		root:      root,
		caddyfile: filepath.Join(dir, "caddy", "Caddyfile"),
		caddyDir:  filepath.Join(dir, "caddy", "rerouted"),
		etcDir:    filepath.Join(dir, "etc"),
		varLib:    filepath.Join(dir, "var"),
		systemctl: func(args ...string) (string, error) { return "", errors.New("no systemd here") },
	}
	if caddyfile != "" {
		os.MkdirAll(filepath.Dir(d.caddyfile), 0o755)
		os.WriteFile(d.caddyfile, []byte(caddyfile), 0o644)
		d.caddy = filepath.Join(dir, "caddy-bin")
		os.WriteFile(d.caddy, []byte("#!/bin/sh\ncase \"$1\" in validate) exit 0;; reload) exit 0;; esac\nexit 2\n"), 0o755)
	}
	return d, out, dir
}

func TestInitNonInteractive(t *testing.T) {
	clearRerouted(t)
	d, out, dir := testInitDeps(t, false, "")
	t.Chdir(dir)
	o := initOptions{name: "chat.example", handles: "chat.example", yes: true, registration: "invite"}
	if code := initServer(o, d); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	cfg, err := config.Load(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatalf("the written settings don't load: %v", err)
	}
	if cfg.Name != "chat.example" || cfg.Registration != "invite" || len(cfg.RegistrationCode) < 10 || cfg.DataDir != filepath.Join(dir, "data") {
		t.Fatalf("settings %+v", cfg)
	}
	if fi, _ := os.Stat(filepath.Join(dir, ".env")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("settings mode %v", fi.Mode().Perm())
	}
	for _, f := range []string{"server-key.json", "server-key-v2.json"} {
		if _, err := os.Stat(filepath.Join(dir, "data", f)); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "*.chat.example.") || !strings.Contains(out.String(), "Caddy isn't installed") {
		t.Fatalf("output:\n%s", out)
	}

	// Never over an existing settings file.
	before, _ := os.ReadFile(filepath.Join(dir, ".env"))
	out.Reset()
	if code := initServer(o, d); code == 0 || !strings.Contains(out.String(), "never overwrites") {
		t.Fatalf("second init: %d %s", code, out)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, ".env")); !bytes.Equal(before, after) {
		t.Fatal("settings file changed")
	}

	// A name is required without a terminal.
	out.Reset()
	if code := initServer(initOptions{yes: true}, d); code != 2 {
		t.Fatalf("no name: %d", code)
	}
}

func TestInitAsRootWithCaddy(t *testing.T) {
	clearRerouted(t)
	d, out, dir := testInitDeps(t, true, "example.org {\n\trespond hi\n}\n")
	o := initOptions{name: "chat.example", yes: true, registration: "public"}
	if code := initServer(o, d); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	env := filepath.Join(d.etcDir, "rerouted.env")
	cfg, err := config.Load(env)
	if err != nil || !cfg.RegistrationPublic || cfg.DataDir != filepath.Join(d.varLib, "rerouted") || cfg.Handles != "chat.example" {
		t.Fatalf("settings %+v %v", cfg, err)
	}
	site, err := os.ReadFile(filepath.Join(d.caddyDir, "chat.example.caddy"))
	if err != nil || !strings.Contains(string(site), "reverse_proxy "+cfg.Listen) || !strings.Contains(string(site), "*.chat.example {") {
		t.Fatalf("site file: %s %v", site, err)
	}
	if g, _ := os.ReadFile(filepath.Join(d.caddyDir, "global", "chat.example.caddy")); !strings.Contains(string(g), "ask http://"+cfg.Listen+"/v0/tls-ask") {
		t.Fatalf("global file: %s", g)
	}
	main, _ := os.ReadFile(d.caddyfile)
	if !strings.Contains(string(main), "import "+filepath.Join(d.caddyDir, "*.caddy")) {
		t.Fatalf("Caddyfile:\n%s", main)
	}
	if !strings.Contains(out.String(), "Enable") && !strings.Contains(out.String(), "systemctl enable --now rerouted.service") {
		t.Fatalf("no service hint:\n%s", out)
	}

	// A second instance on the same machine: its own settings file and data, its own port,
	// and Caddy's single ask stays the first instance's.
	clearRerouted(t)
	out.Reset()
	if code := initServer(initOptions{name: "talk.example", yes: true, registration: "closed"}, d); code != 0 {
		t.Fatalf("second instance: %d\n%s", code, out)
	}
	env2 := filepath.Join(d.etcDir, "talk.example.env")
	clearRerouted(t)
	cfg2, err := config.Load(env2)
	if err != nil || cfg2.DataDir != filepath.Join(d.varLib, "rerouted-talk.example") || cfg2.Listen == cfg.Listen {
		t.Fatalf("second settings %+v %v", cfg2, err)
	}
	if !strings.Contains(out.String(), "REROUTED_TLS_ASK_ALSO") || !strings.Contains(out.String(), "rerouted@talk.example.service") {
		t.Fatalf("output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(d.caddyDir, "global", "talk.example.caddy")); err == nil {
		t.Fatal("a second on_demand_tls was written")
	}
	_ = dir
}

func TestInitNotRootWithCaddy(t *testing.T) {
	clearRerouted(t)
	d, out, dir := testInitDeps(t, false, "example.org {\n}\n")
	before, _ := os.ReadFile(d.caddyfile)
	o := initOptions{name: "chat.example", yes: true, registration: "closed", env: filepath.Join(dir, "r.env"), dataDir: filepath.Join(dir, "data")}
	if code := initServer(o, d); code != 0 {
		t.Fatalf("%d\n%s", code, out)
	}
	if after, _ := os.ReadFile(d.caddyfile); !bytes.Equal(before, after) {
		t.Fatal("Caddyfile edited without root")
	}
	if _, err := os.Stat(d.caddyDir); err == nil {
		t.Fatal("wrote into Caddy's directory without root")
	}
	if !strings.Contains(out.String(), "sudo rerouted init --caddy-only --env "+o.env) {
		t.Fatalf("output:\n%s", out)
	}
}

func TestRegistrationCode(t *testing.T) {
	a, b := registrationCode(), registrationCode()
	if a == b || len(a) != 23 {
		t.Fatalf("%q %q", a, b)
	}
}
