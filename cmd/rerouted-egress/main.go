// Command rerouted-egress makes rerouted's connections out, so rerouted can run without a
// network (internal/egress, deploy/README.md).
//
//	rerouted-egress [-env FILE] [-listen PATH] [-allow-user USER]
//
// It serves on the socket systemd passes, or on -listen PATH. Its policy is its own, from
// rerouted's settings file, which rerouted can't change: public addresses, the networks in
// REROUTED_FED_ALLOW, and the hosts and ports REROUTED_TLS_ASK_ALSO lists.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/egress"
	"github.com/rerouteholdings/rerouted/internal/ipc"
)

func main() {
	envFile := flag.String("env", ".env", "path to rerouted's .env file")
	listen := flag.String("listen", "", "unix socket to listen on, without systemd's")
	allow := flag.String("allow-user", "", "the only user that may connect (rerouted's)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	restrictUmask()
	cfg, err := config.Load(*envFile)
	if err != nil {
		fail("config: " + err.Error())
	}
	uid := -1
	if *allow != "" {
		if !ipc.PeerCheckSupported {
			fail("-allow-user isn't supported on this system")
		}
		u, err := user.Lookup(*allow)
		if err != nil {
			fail("-allow-user: " + err.Error())
		}
		if uid, err = strconv.Atoi(u.Uid); err != nil {
			fail("-allow-user: " + err.Error())
		}
	}
	l, err := ipc.Listen(*listen)
	if err != nil {
		fail("listen: " + err.Error())
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		l.Close()
		os.Exit(0) // connections in progress end with the process
	}()
	p := egress.Policy{Allow: cfg.FedAllow, Local: egress.LocalFrom(cfg.TLSAskAlso)}
	log.Info("rerouted-egress serving", "fed_allow", cfg.FedAllow, "tls_ask_also", cfg.TLSAskAlso, "allow_uid", uid)
	if err := (&egress.Server{Policy: p, UID: uid, Log: log}).Serve(l); err != nil {
		fail("serve: " + err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "rerouted-egress:", msg)
	os.Exit(1)
}
