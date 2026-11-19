package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rerouteholdings/rerouted/internal/api"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// serve runs the server until SIGINT or SIGTERM, and returns the exit code.
func serve(cfg *config.Config, key serverkey.Key, log *slog.Logger, st *sqlite.Store) int {
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
	go server.RunCommunityVoice(ctx)
	for _, cm := range cfg.Communities {
		log.Info("community server", "name", cm.Name, "base", cfg.CommunityBase(cm))
	}
	// Dev mode: a community name with a host:port of its own gets its own listener.
	for _, l := range server.CommunityListeners() {
		cs := &http.Server{Addr: l.Addr, Handler: l.Handler, ReadHeaderTimeout: 10 * time.Second}
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
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		return 1
	}
	return 0
}
