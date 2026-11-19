package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/version"
)

// backupManifest is backup.json, the archive's first member.
type backupManifest struct {
	Format  int    `json:"format"` // 1
	Name    string `json:"name"`
	Version string `json:"version"` // the rerouted that made it
	Schema  int    `json:"schema"`  // the database's schema version
	Created string `json:"created"`
	// Settings: the archive holds the settings file as settings.env. Restore leaves it
	// there, since it may hold paths for the old machine.
	Settings bool `json:"settings"`
}

const (
	manifestName = "backup.json"
	settingsName = "settings.env"
	dbName       = "rerouted-v1.db"
	asidePrefix  = "before-restore-"
)

// skipInBackup reports whether a data directory entry stays out of backups: the live
// database (the archive has a consistent copy), state that's only meaningful to a running
// process, and earlier restores' leftovers.
func skipInBackup(rel string, isDir bool) bool {
	base := filepath.Base(rel)
	if rel == dbName || strings.HasPrefix(rel, dbName+"-") {
		return true
	}
	switch rel {
	case "status.json", "limits.json":
		return true
	}
	return strings.HasPrefix(base, asidePrefix) || strings.HasPrefix(base, ".rerouted-") || strings.HasPrefix(base, ".status-") ||
		!isDir && strings.HasPrefix(base, "rerouted-backup-") && strings.HasSuffix(base, ".tar.gz")
}

func runBackup(g *globals, args []string) int {
	if len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] backup [DEST]")
		return 2
	}
	cfg, err := loadConfig(g)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	dest := "."
	if len(args) == 2 {
		dest = args[1]
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	out := dest
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		out = filepath.Join(dest, "rerouted-backup-"+cfg.Name+"-"+stamp+".tar.gz")
	} else if !strings.HasSuffix(dest, ".tar.gz") {
		fmt.Fprintf(os.Stderr, "backup: %s isn't a directory, or a file name ending in .tar.gz\n", dest)
		return 2
	}
	if _, err := os.Stat(out); err == nil {
		fmt.Fprintf(os.Stderr, "backup: %s already exists\n", out)
		return 1
	}
	st, err := openReadOnly(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 1
	}
	defer st.Close()
	n, size, err := writeBackup(cfg.DataDir, cfg.Name, g.env, out, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 1
	}
	fmt.Printf("backed up %d files to %s (%s)\n", n, out, humanBytes(size))
	fmt.Println("It holds the server's private keys and settings: keep it as safe as the server.")
	return 0
}

// writeBackup writes the archive to out (mode 0600) through a temporary file beside it, so
// a failure never leaves a partial archive under the final name.
func writeBackup(dataDir, name, envFile, out string, st *sqlite.Store) (files int, size int64, err error) {
	tmpDB := filepath.Join(filepath.Dir(out), ".rerouted-backup-"+filepath.Base(out)+".db")
	os.Remove(tmpDB)
	// Created first, so the copy is never readable by others, even for a moment.
	tf, err := os.OpenFile(tmpDB, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, 0, err
	}
	tf.Close()
	if err := st.BackupTo(tmpDB); err != nil {
		os.Remove(tmpDB)
		return 0, 0, fmt.Errorf("copying the database: %w", err)
	}
	defer os.Remove(tmpDB)
	schema := 0
	if cp, err := sqlite.OpenReadOnly(tmpDB); err == nil {
		schema, _ = cp.SchemaVersion()
		cp.Close()
	}

	partial := out + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, 0, err
	}
	defer os.Remove(partial)
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	now := time.Now().UTC()
	man := backupManifest{Format: 1, Name: name, Version: version.Number, Schema: schema, Created: now.Format(time.RFC3339)}
	settings, serr := os.ReadFile(envFile)
	man.Settings = serr == nil && len(settings) > 0 && envFile != os.DevNull
	mb, _ := json.MarshalIndent(man, "", "  ")
	add := func(name string, mode int64, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := add(manifestName, 0o600, append(mb, '\n')); err != nil {
		f.Close()
		return 0, 0, err
	}
	if man.Settings {
		if err := add(settingsName, 0o600, settings); err != nil {
			f.Close()
			return 0, 0, err
		}
	}
	if err := addFile(tw, tmpDB, dbName); err != nil {
		f.Close()
		return 0, 0, err
	}
	files = 1
	walkErr := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dataDir, path)
		if err != nil || rel == "." {
			return err
		}
		if skipInBackup(rel, d.IsDir()) || path == partial || path == tmpDB || path == out {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel) + "/", Mode: int64(info.Mode().Perm()), ModTime: info.ModTime(), Typeflag: tar.TypeDir})
		case info.Mode().IsRegular():
			files++
			return addFile(tw, path, filepath.ToSlash(rel))
		}
		return nil // sockets, links: not rerouted's
	})
	if walkErr != nil {
		f.Close()
		return 0, 0, walkErr
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return 0, 0, err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return 0, 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, 0, err
	}
	fi, _ := f.Stat()
	if err := f.Close(); err != nil {
		return 0, 0, err
	}
	if err := os.Rename(partial, out); err != nil {
		return 0, 0, err
	}
	return files, fi.Size(), nil
}

func addFile(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(fi.Mode().Perm()), Size: fi.Size(), ModTime: fi.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	// A file that grows while it's copied (a media upload) is cut at the size in the header.
	_, err = io.CopyN(tw, f, fi.Size())
	return err
}

func runRestore(g *globals, args []string) int {
	fset := flag.NewFlagSet("restore", flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	force := fset.Bool("force", false, "replace an existing database, moving the current data aside first")
	var file string
	rest := args[1:]
	for len(rest) > 0 {
		if err := fset.Parse(rest); err != nil {
			fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] restore FILE [--force]")
			return 2
		}
		rest = fset.Args()
		if len(rest) > 0 {
			if file != "" {
				fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] restore FILE [--force]")
				return 2
			}
			file, rest = rest[0], rest[1:]
		}
	}
	if file == "" {
		fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] restore FILE [--force]")
		return 2
	}
	cfg, err := loadConfig(g)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	if cfg.Store == "temp" {
		fmt.Fprintln(os.Stderr, "restore: REROUTED_STORE=temp keeps no database to restore into")
		return 1
	}
	if yes, _, why := running(cfg.DataDir, time.Now()); yes {
		fmt.Fprintf(os.Stderr, "restore: rerouted is running on %s (%s). Stop it first, for example with systemctl stop rerouted.\n", cfg.DataDir, why)
		return 1
	}
	if err := restore(file, cfg.DataDir, cfg.Name, *force, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "restore:", err)
		return 1
	}
	return 0
}

// restore unpacks a backup into dataDir. It stages everything in a directory inside
// dataDir first, so a damaged archive changes nothing, then moves it into place. Files it
// replaces go to dataDir/before-restore-{time}.
func restore(file, dataDir, name string, force bool, now time.Time) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	dbPath := filepath.Join(dataDir, dbName)
	if _, err := os.Stat(dbPath); err == nil && !force {
		return fmt.Errorf("%s already has a database. Restoring over a server that's still in use breaks its groups (docs/administer-a-homeserver.md). To replace it anyway, run again with --force, which first moves the current data to %s%s",
			dataDir, filepath.Join(dataDir, asidePrefix), "{time}")
	}
	stamp := now.UTC().Format("20060102T150405Z")
	staging := filepath.Join(dataDir, ".rerouted-restore-"+stamp)
	if err := os.Mkdir(staging, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	man, err := unpack(file, staging)
	if err != nil {
		return err
	}
	if man.Name != "" && man.Name != name {
		fmt.Printf("note: the backup is of %s; these settings are for %s\n", man.Name, name)
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	aside := filepath.Join(dataDir, asidePrefix+stamp)
	moveAside := func(rel string) error {
		if err := os.MkdirAll(aside, 0o700); err != nil {
			return err
		}
		return os.Rename(filepath.Join(dataDir, rel), filepath.Join(aside, rel))
	}
	if force {
		current, err := os.ReadDir(dataDir)
		if err != nil {
			return err
		}
		for _, e := range current {
			n := e.Name()
			if filepath.Join(dataDir, n) == staging || strings.HasPrefix(n, asidePrefix) {
				continue
			}
			if err := moveAside(n); err != nil {
				return err
			}
		}
	}
	owner, _ := os.Stat(dataDir)
	moved := 0
	for _, e := range entries {
		n := e.Name()
		if n == manifestName || n == settingsName {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dataDir, n)); err == nil {
			if err := moveAside(n); err != nil {
				return err
			}
		}
		if err := os.Rename(filepath.Join(staging, n), filepath.Join(dataDir, n)); err != nil {
			return err
		}
		chownTree(filepath.Join(dataDir, n), owner)
		moved++
	}
	fmt.Printf("restored the backup of %s from %s (rerouted %s, schema %d) into %s\n", man.Name, man.Created, man.Version, man.Schema, dataDir)
	if _, err := os.Stat(aside); err == nil {
		fmt.Printf("the data it replaced is in %s\n", aside)
	}
	if man.Settings {
		fmt.Printf("the backup also holds its settings file: tar -xzf %s %s\n", file, settingsName)
	}
	fmt.Println("Start rerouted to use it.")
	return nil
}

// unpack extracts a backup into dir, refusing anything outside it, and returns its manifest.
func unpack(file, dir string) (*backupManifest, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s isn't a rerouted backup: %w", file, err)
	}
	tr := tar.NewReader(zr)
	var man *backupManifest
	haveDB := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", file, err)
		}
		name := filepath.FromSlash(strings.TrimSuffix(h.Name, "/"))
		if !filepath.IsLocal(name) {
			return nil, fmt.Errorf("%s holds %q, outside the data directory: not restoring it", file, h.Name)
		}
		if man == nil && h.Name != manifestName {
			return nil, fmt.Errorf("%s isn't a rerouted backup: it doesn't start with %s", file, manifestName)
		}
		path := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o700); err != nil {
				return nil, err
			}
			continue
		case tar.TypeReg:
		default:
			continue
		}
		if h.Name == manifestName {
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return nil, err
			}
			man = new(backupManifest)
			if err := json.Unmarshal(b, man); err != nil {
				return nil, fmt.Errorf("%s: %w", manifestName, err)
			}
			if man.Format != 1 {
				return nil, fmt.Errorf("backup format %d is newer than this rerouted knows", man.Format)
			}
			if man.Schema > sqlite.SchemaVersion {
				return nil, fmt.Errorf("the backup's database has schema %d, newer than this rerouted's %d: restore it with rerouted %s or later", man.Schema, sqlite.SchemaVersion, man.Version)
			}
			continue
		}
		if name == dbName {
			haveDB = true
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(h.Mode).Perm()|0o600)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return nil, err
		}
		if err := out.Close(); err != nil {
			return nil, err
		}
	}
	if man == nil || !haveDB {
		return nil, fmt.Errorf("%s isn't a complete rerouted backup: it has no database", file)
	}
	return man, nil
}
