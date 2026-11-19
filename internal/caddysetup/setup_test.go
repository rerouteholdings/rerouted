package caddysetup

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const site = "chat.example {\n\treverse_proxy 127.0.0.1:8080\n}\n"
const global = "on_demand_tls {\n\task http://127.0.0.1:8080/v0/tls-ask\n}\n"

// fakeCaddy writes a caddy that fails validation when FAIL_VALIDATE appears in the
// Caddyfile's directory, and otherwise passes.
func fakeCaddy(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a shell")
	}
	bin := filepath.Join(t.TempDir(), "caddy")
	script := "#!/bin/sh\n[ \"$1\" = validate ] || exit 2\nif grep -rq FAIL_VALIDATE \"$(dirname \"$3\")\"; then echo 'Error: adapting config: FAIL_VALIDATE'; exit 1; fi\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

type env struct {
	setup    *Setup
	reloads  int
	original string
}

func newEnv(t *testing.T, caddyfile string) *env {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(caddyfile), 0o640); err != nil {
		t.Fatal(err)
	}
	e := &env{original: caddyfile}
	e.setup = &Setup{
		Caddyfile: path,
		Dir:       filepath.Join(dir, "rerouted"),
		Name:      "chat.example",
		Site:      site,
		Global:    global,
		Caddy:     fakeCaddy(t),
		Reload:    func() error { e.reloads++; return nil },
		Now:       func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
	}
	return e
}

func (e *env) caddyfile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(e.setup.Caddyfile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withoutAdded removes the lines Apply adds, which must give back the original exactly.
func withoutAdded(s string, setup *Setup) string {
	var keep []string
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		switch {
		case strings.Contains(t, "(rerouted init)"), strings.Contains(t, "rerouted init added this block"):
			continue
		case t == setup.SiteImport(), t == setup.GlobalImport():
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func TestNoGlobalBlock(t *testing.T) {
	orig := "# My sites\nexample.org {\n\troot * /srv/www\n\tfile_server\n}\n"
	e := newEnv(t, orig)
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	got := e.caddyfile(t)
	if !res.Edited || !res.Reloaded || e.reloads != 1 {
		t.Fatalf("result %+v, reloads %d", res, e.reloads)
	}
	l := parse(got)
	if l.global != 0 || !l.hasImport(filepath.Join(e.setup.Dir, "global", "*.caddy"), true) || !l.hasImport(filepath.Join(e.setup.Dir, "*.caddy"), false) {
		t.Fatalf("imports missing:\n%s", got)
	}
	// The new global block has the import only, then a blank line, then the old file.
	if !strings.Contains(got, "{\n\t"+e.setup.GlobalImport()+"\n}\n\n# My sites\n") {
		t.Fatalf("global block not at the top:\n%s", got)
	}
	if b, _ := os.ReadFile(res.Backup); string(b) != orig {
		t.Fatalf("backup %q", b)
	}
	if fi, _ := os.Stat(e.setup.Caddyfile); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640 kept", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(res.Backup); fi.Mode().Perm() != 0o640 {
		t.Fatalf("backup mode %v", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(res.SiteFile); string(b) != site {
		t.Fatal("site file not written")
	}
	if b, _ := os.ReadFile(res.GlobalFile); string(b) != global {
		t.Fatal("global file not written")
	}
}

func TestExistingGlobalBlock(t *testing.T) {
	orig := "{\n\temail ops@example.org # for ACME\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n\nexample.org {\n\trespond \"{ not a brace\"\n}\n"
	e := newEnv(t, orig)
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	got := e.caddyfile(t)
	if !strings.HasPrefix(got, "{\n\t# rerouted's on-demand TLS ask (rerouted init)\n\t"+e.setup.GlobalImport()+"\n\temail") {
		t.Fatalf("global import not inserted after {:\n%s", got)
	}
	if strings.Count(got, "\n{\n") != 0 || strings.Count(got, "{\n") != strings.Count(orig, "{\n") {
		t.Fatalf("a second global block was added:\n%s", got)
	}
	if withoutAdded(got, e.setup) != strings.TrimRight(orig, "\n")+"\n" && withoutAdded(got, e.setup) != orig+"\n" && withoutAdded(got, e.setup) != orig {
		t.Fatalf("original text changed:\n%q\nvs\n%q", withoutAdded(got, e.setup), orig)
	}
	if res.GlobalFile == "" || res.OtherAsk != "" {
		t.Fatalf("result %+v", res)
	}
}

func TestExistingOnDemandTLS(t *testing.T) {
	orig := "{\n\ton_demand_tls {\n\t\task http://127.0.0.1:8101/v0/tls-ask\n\t}\n}\n\nother.example {\n\trespond hi\n}\n"
	e := newEnv(t, orig)
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if res.OtherAsk != "http://127.0.0.1:8101/v0/tls-ask" || res.GlobalFile != "" {
		t.Fatalf("result %+v", res)
	}
	got := e.caddyfile(t)
	if strings.Contains(got, e.setup.GlobalImport()) {
		t.Fatal("global import added despite an existing on_demand_tls")
	}
	if !strings.Contains(got, e.setup.SiteImport()) {
		t.Fatal("site import missing")
	}
	if exists(filepath.Join(e.setup.Dir, "global", "chat.example.caddy")) {
		t.Fatal("global file written")
	}
}

func TestAnotherInstanceAsks(t *testing.T) {
	e := newEnv(t, "example.org {\n\trespond hi\n}\n")
	gdir := filepath.Join(e.setup.Dir, "global")
	os.MkdirAll(gdir, 0o755)
	os.WriteFile(filepath.Join(gdir, "first.example.caddy"), []byte("on_demand_tls {\n\task http://127.0.0.1:8101/v0/tls-ask\n}\n"), 0o644)
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if res.OtherAsk != "http://127.0.0.1:8101/v0/tls-ask" || res.GlobalFile != "" {
		t.Fatalf("result %+v", res)
	}
}

func TestAlreadyImported(t *testing.T) {
	e := newEnv(t, "example.org {\n\trespond hi\n}\n")
	if _, err := e.setup.Apply(); err != nil {
		t.Fatal(err)
	}
	after := e.caddyfile(t)
	backups, _ := filepath.Glob(e.setup.Caddyfile + ".bak-rerouted-*")
	e.setup.Now = func() time.Time { return time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC) }
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if res.Edited || res.Backup != "" || res.Reloaded || e.reloads != 1 {
		t.Fatalf("second run changed something: %+v, reloads %d", res, e.reloads)
	}
	if e.caddyfile(t) != after {
		t.Fatal("second run edited the Caddyfile")
	}
	if b2, _ := filepath.Glob(e.setup.Caddyfile + ".bak-rerouted-*"); len(b2) != len(backups) {
		t.Fatal("second run made another backup")
	}
}

func TestImportedByHand(t *testing.T) {
	e := newEnv(t, "")
	orig := "{\n\timport " + filepath.Join(e.setup.Dir, "global", "*.caddy") + "\n}\nimport " + filepath.Join(e.setup.Dir, "*.caddy") + "\n"
	os.WriteFile(e.setup.Caddyfile, []byte(orig), 0o640)
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if res.Edited || e.caddyfile(t) != orig || !res.Reloaded {
		t.Fatalf("result %+v", res)
	}
}

func TestExistingSiteFileKept(t *testing.T) {
	e := newEnv(t, "example.org {\n\trespond hi\n}\n")
	os.MkdirAll(e.setup.Dir, 0o755)
	mine := "# edited by the operator\n" + site
	path := filepath.Join(e.setup.Dir, "chat.example.caddy")
	os.WriteFile(path, []byte(mine), 0o644)
	res, err := e.setup.Apply()
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != mine {
		t.Fatal("existing site file replaced")
	}
	if res.SiteNew != path+".new" {
		t.Fatalf("SiteNew %q", res.SiteNew)
	}
	if b, _ := os.ReadFile(path + ".new"); string(b) != site {
		t.Fatal(".new not written")
	}
}

func TestGeneratedCaddyfile(t *testing.T) {
	for _, header := range []string{
		"# This file is generated by deploy/caddy-config.sh. Do not edit.\n",
		"# Caddyfile\n# managed by Ansible\n",
		"example.org {\n}\n# managed by puppet\n",
	} {
		orig := header + "example.org {\n\trespond hi\n}\n"
		e := newEnv(t, orig)
		res, err := e.setup.Apply()
		if err != nil {
			t.Fatal(err)
		}
		if res.Manual == "" || res.Edited || len(res.ImportLines) != 2 || e.caddyfile(t) != orig || res.Reloaded {
			t.Fatalf("%q: result %+v", header, res)
		}
		if !exists(res.SiteFile) || !exists(res.GlobalFile) {
			t.Fatal("files not written for the operator to import")
		}
		if bk, _ := filepath.Glob(e.setup.Caddyfile + ".bak-*"); len(bk) != 0 {
			t.Fatal("backup made for a file that wasn't edited")
		}
	}
}

func TestValidationFailureRollsBack(t *testing.T) {
	orig := "{\n\temail ops@example.org\n}\nexample.org {\n\trespond hi\n}\n"
	e := newEnv(t, orig)
	e.setup.Site = "# FAIL_VALIDATE\n" + site
	_, err := e.setup.Apply()
	var ve *ValidationError
	if !errors.As(err, &ve) || !strings.Contains(ve.Output, "FAIL_VALIDATE") {
		t.Fatalf("err %v", err)
	}
	if e.caddyfile(t) != orig {
		t.Fatal("Caddyfile not restored")
	}
	if fi, _ := os.Stat(e.setup.Caddyfile); fi.Mode().Perm() != 0o640 {
		t.Fatal("mode not kept on restore")
	}
	if exists(e.setup.Dir) {
		t.Fatal("added files and directories not removed")
	}
	if bk, _ := filepath.Glob(e.setup.Caddyfile + ".bak-*"); len(bk) != 0 {
		t.Fatal("backup left behind after restoring")
	}
	if e.reloads != 0 {
		t.Fatal("reloaded after a failed validation")
	}
}

func TestValidationFailureKeepsExistingFiles(t *testing.T) {
	e := newEnv(t, "example.org {\n\trespond hi\n}\n")
	os.MkdirAll(e.setup.Dir, 0o755)
	theirs := filepath.Join(e.setup.Dir, "other.caddy")
	os.WriteFile(theirs, []byte("# FAIL_VALIDATE\n"), 0o644)
	if _, err := e.setup.Apply(); err == nil {
		t.Fatal("validation should fail")
	}
	if !exists(theirs) || exists(filepath.Join(e.setup.Dir, "chat.example.caddy")) {
		t.Fatal("rollback removed the wrong files")
	}
}

func TestTokenize(t *testing.T) {
	src := "# { comment\n{\n\tdebug\n}\nsite {\n\trespond \"}\" 200\n\trespond `{` \n\theader X {http.request.host}\n\trespond <<EOF\n\t}\n\tEOF\n}\n"
	l := parse(src)
	if l.odd != "" || l.global != 0 || l.toks[l.globalEnd].line != 3 {
		t.Fatalf("parse: %+v", l)
	}
	if odd := parse("{ debug }\n").odd; odd == "" {
		t.Fatal("a one-line global block should be left alone")
	}
	if odd := parse("site {\n").odd; odd == "" {
		t.Fatal("unbalanced braces not noticed")
	}
}
