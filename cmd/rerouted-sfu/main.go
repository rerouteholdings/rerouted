// Command rerouted-sfu runs the voice SFU for rerouted, in a process of its own
// (internal/sfuipc, deploy/README.md): the UDP from anyone, and WebRTC's parsers, run
// where there are no keys, no database, and no settings file.
//
//	rerouted-sfu [-listen PATH] [-allow-user USER]
//
// It serves on the socket systemd passes, or on -listen PATH. It reads nothing: rerouted
// sends the settings (REROUTED_VOICE_UDP_PORT, REROUTED_VOICE_PUBLIC_IPS, and dev mode's
// loopback) when it connects.
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

	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/sfuipc"
)

func main() {
	listen := flag.String("listen", "", "unix socket to listen on, without systemd's")
	allow := flag.String("allow-user", "", "the only user that may connect (rerouted's)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	restrictUmask()
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
		// rerouted's connection may be open, and holds Serve: end everything now. Its
		// rooms end with the process, as they would with rerouted.
		<-sigs
		log.Info("rerouted-sfu stopping")
		os.Exit(0)
	}()
	log.Info("rerouted-sfu serving", "allow_uid", uid)
	if err := (&sfuipc.Server{UID: uid, Log: log}).Serve(l); err != nil {
		fail("serve: " + err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "rerouted-sfu:", msg)
	os.Exit(1)
}
