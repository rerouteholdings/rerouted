// Command rerouted is the reference Tieroute homeserver (README.md).
//
//	rerouted [-env FILE]                    run the server
//	rerouted [-env FILE] reports [N]        print the N newest reports (default 20)
//	rerouted [-env FILE] remove-media ID --confirm
//	                                        delete a reported file: fetches answer 410 removed
//	rerouted [-env FILE] release-handle HANDLE --confirm
//	                                        free a handle so a new identity can register it
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rerouteholdings/rerouted/internal/api"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

func main() {
	envFile := flag.String("env", ".env", "path to the .env file")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*envFile)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	key, err := serverkey.LoadOrCreate(cfg.DataDir)
	if err != nil {
		log.Error("server key", "err", err)
		os.Exit(1)
	}

	var st *sqlite.Store
	if cfg.Store == "temp" {
		st, err = sqlite.OpenTemp()
	} else {
		st, err = sqlite.Open(filepath.Join(cfg.DataDir, "rerouted-v1.db"))
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
	server := api.New(cfg, key, log, st)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
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
	if cfg.Dev {
		log.Warn("dev mode: S2S to these peers uses plain http", "peers", cfg.Peers)
	}
	if cfg.PauseMoves {
		log.Warn("moves are paused (REROUTED_PAUSE_MOVES=on): device-signed moves to and from this server are refused")
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
