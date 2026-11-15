// Command rerouted is the reference Tieroute homeserver (README.md).
//
//	rerouted [-env FILE]                    run the server
//	rerouted [-env FILE] reports [N]        print the N newest reports (default 20)
//	rerouted [-env FILE] remove-media ID --confirm
//	                                        delete a reported file: fetches answer 410 removed
//	rerouted [-env FILE] release-handle HANDLE --confirm
//	                                        free a handle so a new identity can register it
//	rerouted [-env FILE] keep-handle HANDLE keep a handle reserved after its 30-day hold
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rerouteholdings/rerouted/internal/api"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/keyd"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// idleTimeout is how long a keep-alive connection may wait for its next request. Without
// one (and without a ReadTimeout), it waits forever, holding a file descriptor.
const idleTimeout = 2 * time.Minute

func main() {
	envFile := flag.String("env", ".env", "path to the .env file")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	restrictUmask()

	cfg, err := config.Load(*envFile)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	var st *sqlite.Store
	if cfg.Store == "temp" {
		st, err = sqlite.OpenTemp()
	} else {
		db := filepath.Join(cfg.DataDir, "rerouted-v1.db")
		st, err = sqlite.Open(db)
		// A database from before the umask above may be readable by everyone.
		for _, f := range []string{db, db + "-wal", db + "-shm"} {
			if fi, err := os.Stat(f); err == nil && fi.Mode().Perm()&0o077 != 0 {
				os.Chmod(f, fi.Mode().Perm()&0o700)
			}
		}
	}
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	if cfg.Store == "temp" {
		log.Warn("storage is temporary: everything is deleted on shutdown (demos only)")
	}
	defer st.Close()
	if flag.NArg() > 0 {
		os.Exit(admin(st, flag.Args()))
	}
	// The keys come after the operator commands, which don't sign: run from a shell, without
	// the unit's REROUTED_KEYD, they'd otherwise make new keys in the data directory.
	var key serverkey.Key
	if cfg.Keyd != "" {
		key, err = keyd.Load(cfg.Keyd, cfg.Name)
		if _, serr := os.Stat(filepath.Join(cfg.DataDir, serverkey.FileV1)); err == nil && serr == nil {
			log.Warn("the data directory still has server keys, but rerouted-keyd's are used: move them to rerouted-keyd (deploy/README.md)", "dir", cfg.DataDir)
		}
	} else {
		key, err = serverkey.LoadOrCreate(cfg.DataDir)
	}
	if err != nil {
		log.Error("server key", "err", err)
		st.Close()
		os.Exit(1)
	}
	server := api.New(cfg, key, log, st)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// A keep-alive connection with no request in this long is closed. Streams are
		// unaffected: a WebSocket leaves the server's hands, and an event stream is one
		// long response.
		IdleTimeout: idleTimeout,
	}
	srv.RegisterOnShutdown(server.CloseFirehose)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	log.Info("rerouted starting", "name", cfg.Name, "listen", cfg.Listen,
		"client", cfg.ClientBase(), "s2s", cfg.S2SBase(), "kid", key.KID,
		"client_v2", cfg.ClientBaseV2(), "s2s_v2", cfg.S2SBaseV2(), "kid_v2", key.V2.KID)
	go server.RunOutbox(ctx)
	go server.RunMaintenance(ctx)
	go server.RunCommunityVoice(ctx)
	for _, cm := range cfg.Communities {
		log.Info("community server", "name", cm.Name, "base", cfg.CommunityBase(cm))
	}
	// Dev mode: a community name with a host:port of its own gets its own listener.
	for _, l := range server.CommunityListeners() {
		cs := &http.Server{Addr: l.Addr, Handler: l.Handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: idleTimeout}
		go func() {
			<-ctx.Done()
			cs.Close()
		}()
		go func() {
			if err := cs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("community listener", "name", l.Name, "err", err)
			}
		}()
	}
	if cfg.Dev {
		log.Warn("dev mode: S2S to these peers uses plain http", "peers", cfg.Peers)
	}
	if cfg.PauseMoves {
		log.Warn("moves are paused (REROUTED_PAUSE_MOVES=on): device-signed moves to and from this server are refused")
	}
	// With socket activation, systemd made the listening socket, so rerouted needs no
	// network of its own (deploy/rerouted.socket). Otherwise, REROUTED_LISTEN.
	l, passed, err := ipc.Passed()
	if err == nil && !passed {
		l, err = net.Listen("tcp", cfg.Listen)
	}
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	if passed {
		log.Info("listening on the socket systemd passed", "addr", l.Addr().String())
	}
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
