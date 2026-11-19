package caddysetup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Setup describes one rerouted instance's addition to Caddy.
type Setup struct {
	Caddyfile string // the main Caddyfile, normally /etc/caddy/Caddyfile
	Dir       string // rerouted's directory beside it, normally /etc/caddy/rerouted
	Name      string // the instance's server name: its files are {Dir}/{Name}.caddy and {Dir}/global/{Name}.caddy
	Site      string // the site blocks
	Global    string // what goes in the global options block: the on_demand_tls block
	Caddy     string // the caddy binary, for caddy validate (default "caddy")
	// Reload reloads Caddy after a change that validated. Nil: Apply doesn't reload.
	Reload func() error
	Now    func() time.Time // default time.Now
}

// Result says what Apply did, for the operator.
type Result struct {
	SiteFile string // the site file, written or already in place
	// SiteNew: a different SiteFile was already there, and is kept; Site went to SiteNew
	// for the operator to compare.
	SiteNew    string
	GlobalFile string // the global file, written or already in place; "" if skipped
	GlobalNew  string // as SiteNew, for the global file
	// OtherAsk is set when Caddy's global options already have an on_demand_tls that isn't
	// this instance's: Caddy takes one ask URL, so no global file was written. It's that
	// ask's URL, or "(no ask URL)".
	OtherAsk string
	Backup   string // the Caddyfile's backup, if it was edited
	Edited   bool   // the Caddyfile gained import lines
	// Manual is set when Apply didn't edit the Caddyfile because a tool generates it, or
	// its layout isn't safe to edit: the reason. ImportLines are then the lines the
	// operator has to add, each with where it goes.
	Manual      string
	ImportLines []string
	Reloaded    bool
}

// SiteImport and GlobalImport are the import lines for Dir.
func (s *Setup) SiteImport() string   { return "import " + filepath.Join(s.Dir, "*.caddy") }
func (s *Setup) GlobalImport() string { return "import " + filepath.Join(s.Dir, "global", "*.caddy") }

// ValidationError is caddy validate failing, with its output. Apply has undone its changes.
type ValidationError struct{ Output string }

func (e *ValidationError) Error() string {
	return "caddy validate failed, and the changes were undone:\n" + strings.TrimSpace(e.Output)
}

// Apply writes rerouted's files and adds the imports to the Caddyfile, validates, and
// reloads. It never replaces a file it didn't write: an existing site or global file with
// other contents stays, and the new one is written beside it as .new. On a validation
// failure it restores the Caddyfile from its backup and removes the files it added.
func (s *Setup) Apply() (*Result, error) {
	if s.Caddy == "" {
		s.Caddy = "caddy"
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	raw, err := os.ReadFile(s.Caddyfile)
	if err != nil {
		return nil, err
	}
	src := string(raw)
	l := parse(src)
	res := &Result{SiteFile: filepath.Join(s.Dir, s.Name+".caddy")}
	var undo undoList
	globalDir := filepath.Join(s.Dir, "global")
	ourGlobal := filepath.Join(globalDir, s.Name+".caddy")

	// Caddy has one on-demand ask URL. If someone else's is set, in the Caddyfile or in
	// another instance's global file, skip ours.
	if found, ask := l.onDemandAsk(); found {
		res.OtherAsk = orNone(ask)
	}
	if res.OtherAsk == "" {
		others, _ := filepath.Glob(filepath.Join(globalDir, "*.caddy"))
		for _, f := range others {
			if f == ourGlobal {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if found, ask := findAsk(tokenize(string(b))); found {
				res.OtherAsk = orNone(ask)
				break
			}
		}
	}

	if err := undo.mkdir(s.Dir); err != nil {
		return nil, err
	}
	if res.SiteNew, err = undo.place(res.SiteFile, s.Site); err != nil {
		undo.run()
		return nil, err
	}
	if res.OtherAsk == "" {
		if err := undo.mkdir(globalDir); err != nil {
			undo.run()
			return nil, err
		}
		res.GlobalFile = ourGlobal
		if res.GlobalNew, err = undo.place(ourGlobal, s.Global); err != nil {
			undo.run()
			return nil, err
		}
	}

	needSite := !l.hasImport(filepath.Join(s.Dir, "*.caddy"), false)
	needGlobal := res.GlobalFile != "" && !l.hasImport(filepath.Join(globalDir, "*.caddy"), true)
	if needSite || needGlobal {
		switch {
		case IsGenerated(src):
			res.Manual = s.Caddyfile + " says a tool generates it, so it wasn't edited"
		case l.odd != "":
			res.Manual = s.Caddyfile + " wasn't edited: " + l.odd
		}
		if res.Manual != "" {
			if needGlobal {
				res.ImportLines = append(res.ImportLines, s.GlobalImport()+"   (inside the global options block, the { } at the top)")
			}
			if needSite {
				res.ImportLines = append(res.ImportLines, s.SiteImport()+"   (at the top level, outside any block)")
			}
			return res, nil
		}
		edited := src
		// Append the site import first: inserting at the top shifts line numbers.
		if needSite {
			edited = insertLines(edited, len(strings.SplitAfter(edited, "\n")),
				"\n# rerouted's sites, one file per instance (rerouted init)\n"+s.SiteImport()+"\n")
		}
		if needGlobal {
			if l.global >= 0 {
				edited = insertLines(edited, l.toks[l.global].line+1,
					"\t# rerouted's on-demand TLS ask (rerouted init)\n\t"+s.GlobalImport()+"\n")
			} else {
				edited = insertLines(edited, 0,
					"# Global options. rerouted init added this block for its on-demand TLS ask.\n{\n\t"+s.GlobalImport()+"\n}\n\n")
			}
		}
		res.Backup = s.Caddyfile + ".bak-rerouted-" + s.Now().UTC().Format("20060102T150405Z")
		if err := copyFile(s.Caddyfile, res.Backup); err != nil {
			undo.run()
			return nil, fmt.Errorf("backing up %s: %w", s.Caddyfile, err)
		}
		if err := replaceKeepingMode(s.Caddyfile, []byte(edited)); err != nil {
			undo.run()
			return nil, err
		}
		undo.add(func() {
			replaceKeepingMode(s.Caddyfile, raw)
			os.Remove(res.Backup)
		})
		res.Edited = true
	}

	if out, err := exec.Command(s.Caddy, "validate", "--config", s.Caddyfile, "--adapter", "caddyfile").CombinedOutput(); err != nil {
		undo.run()
		if len(out) == 0 {
			out = []byte(err.Error())
		}
		return nil, &ValidationError{Output: string(out)}
	}
	if undo.changed() && s.Reload != nil {
		if err := s.Reload(); err != nil {
			return res, fmt.Errorf("the new configuration is valid, but reloading Caddy failed: %w", err)
		}
		res.Reloaded = true
	}
	return res, nil
}

func orNone(ask string) string {
	if ask == "" {
		return "(no ask URL)"
	}
	return ask
}

// undoList records what Apply changed, to take back in reverse order.
type undoList struct {
	steps []func()
	// writes counts changes that need a reload: new files and the Caddyfile edit, not .new
	// files, which Caddy doesn't load.
	writes int
}

func (u *undoList) add(f func())  { u.steps = append(u.steps, f); u.writes++ }
func (u *undoList) changed() bool { return u.writes > 0 }

func (u *undoList) run() {
	for i := len(u.steps) - 1; i >= 0; i-- {
		u.steps[i]()
	}
	u.steps = nil
}

// mkdir creates dir (0755) if it's missing, and records removing it.
func (u *undoList) mkdir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	u.steps = append(u.steps, func() { os.Remove(dir) })
	return nil
}

// place writes content to path if nothing's there. If the same content is there, it does
// nothing. If something else is, it keeps it, writes path.new, and returns that name.
func (u *undoList) place(path, content string) (newFile string, err error) {
	have, err := os.ReadFile(path)
	switch {
	case err == nil && bytes.Equal(have, []byte(content)):
		return "", nil
	case err == nil:
		newFile = path + ".new"
		return newFile, os.WriteFile(newFile, []byte(content), 0o644)
	case !errors.Is(err, os.ErrNotExist):
		return "", err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	u.add(func() { os.Remove(path) })
	return "", nil
}

// copyFile copies src to dst with src's mode and owner.
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, fi.Mode().Perm()); err != nil {
		return err
	}
	os.Chmod(dst, fi.Mode().Perm())
	return chownLike(dst, fi)
}

// replaceKeepingMode replaces path's contents through a temporary file and a rename, so a
// crash leaves the old or the new file whole, with path's mode and owner.
func replaceKeepingMode(path string, b []byte) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".rerouted-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmp.Name(), fi.Mode().Perm()); err != nil {
		return err
	}
	if err := chownLike(tmp.Name(), fi); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
