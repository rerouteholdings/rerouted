// Command rerouted-keyd holds rerouted's server keys and signs for it over a unix socket,
// so the main process never has them (internal/keyd, deploy/README.md).
//
//	rerouted-keyd [-env FILE] [-keys DIR] [-listen PATH] [-allow-user USER]
//	                        serve: on the socket systemd passes, or on -listen PATH
//	rerouted-keyd [-env FILE] [-import DIR]... [-imported FILE] bundle <old >new
//	                        bring a key bundle up to date (deploy/rerouted-keyd-seal)
//	rerouted-keyd unbundle DIR <bundle
//	                        write a bundle's key files into DIR
//
// It reads the keys from $CREDENTIALS_DIRECTORY/keys, a bundle systemd decrypts for it,
// if there is one, and from -keys DIR otherwise, creating any that are missing there.
// The settings file is rerouted's: it needs REROUTED_NAME and REROUTED_COMMUNITIES.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/keyd"
)

type dirs []string

func (d *dirs) String() string     { return strings.Join(*d, ",") }
func (d *dirs) Set(s string) error { *d = append(*d, s); return nil }

func main() {
	envFile := flag.String("env", ".env", "path to rerouted's .env file")
	keysDir := flag.String("keys", "", "directory of key files (default $STATE_DIRECTORY, or ./keyd)")
	listen := flag.String("listen", "", "unix socket to listen on, without systemd's")
	allow := flag.String("allow-user", "", "the only user that may connect (rerouted's)")
	imported := flag.String("imported", "", "bundle: file to list the imported key files in")
	var imports dirs
	flag.Var(&imports, "import", "bundle: a directory of key files to add (repeatable)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	restrictUmask()

	if flag.Arg(0) == "unbundle" {
		if flag.NArg() != 2 {
			fail(log, "usage: rerouted-keyd unbundle DIR <bundle", nil, 2)
		}
		b, err := io.ReadAll(os.Stdin)
		if err == nil {
			err = keyd.Unbundle(b, flag.Arg(1))
		}
		if err != nil {
			fail(log, "unbundle", err, 1)
		}
		return
	}
	cfg, err := config.Load(*envFile)
	if err != nil {
		fail(log, "config", err, 2)
	}
	var cms []string
	for _, c := range cfg.Communities {
		cms = append(cms, c.Name)
	}
	switch flag.Arg(0) {
	case "bundle":
		old, err := io.ReadAll(os.Stdin)
		if err != nil {
			fail(log, "bundle", err, 1)
		}
		b, done, err := keyd.MakeBundle(old, imports, cfg.Name, cms)
		if err != nil {
			fail(log, "bundle", err, 1)
		}
		if *imported != "" {
			list := ""
			for _, f := range done {
				list += f + "\n"
			}
			if err := os.WriteFile(*imported, []byte(list), 0o600); err != nil {
				fail(log, "bundle", err, 1)
			}
		}
		if _, err := os.Stdout.Write(b); err != nil {
			fail(log, "bundle", err, 1)
		}
		return
	case "", "serve":
	default:
		fail(log, "unknown command "+flag.Arg(0), nil, 2)
	}

	var keys *keyd.Keys
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" && exists(filepath.Join(cd, "keys")) {
		b, err := os.ReadFile(filepath.Join(cd, "keys"))
		if err == nil {
			keys, err = keyd.LoadBundle(b, cfg.Name, cms)
		}
		if err != nil {
			fail(log, "keys", err, 1)
		}
		log.Info("keys from the encrypted bundle")
	} else {
		dir := *keysDir
		if dir == "" {
			dir = firstOr(os.Getenv("STATE_DIRECTORY"), "keyd")
		}
		if keys, err = keyd.LoadDir(dir, cfg.Name, cms); err != nil {
			fail(log, "keys", err, 1)
		}
		log.Info("keys from files", "dir", dir)
	}
	uid := -1
	if *allow != "" {
		if !ipc.PeerCheckSupported {
			fail(log, "-allow-user isn't supported on this system", nil, 2)
		}
		u, err := user.Lookup(*allow)
		if err != nil {
			fail(log, "-allow-user", err, 2)
		}
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			fail(log, "-allow-user", err, 2)
		}
	}
	l, err := ipc.Listen(*listen)
	if err != nil {
		fail(log, "listen", err, 1)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		l.Close()
	}()
	log.Info("rerouted-keyd serving", "name", cfg.Name, "communities", cms, "allow_uid", uid)
	if err := (&keyd.Server{Keys: keys, UID: uid, Log: log}).Serve(l); err != nil {
		fail(log, "serve", err, 1)
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func firstOr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func fail(log *slog.Logger, msg string, err error, code int) {
	if err != nil {
		log.Error(msg, "err", err)
	} else {
		fmt.Fprintln(os.Stderr, "rerouted-keyd:", msg)
	}
	os.Exit(code)
}
