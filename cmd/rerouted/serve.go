package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rerouteholdings/rerouted/internal/api"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/idlerestart"
	"github.com/rerouteholdings/rerouted/internal/metrics"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/sigs"
	"github.com/rerouteholdings/rerouted/internal/status"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/turnrelay"
	"github.com/rerouteholdings/rerouted/internal/updatecheck"
	"github.com/rerouteholdings/rerouted/internal/version"
)

// How often the status file is rewritten, and how often a pending restart checks for
// active voice calls.
const (
	statusEvery       = 30 * time.Second
	restartCheckEvery = 15 * time.Second
)

// serve runs the server until SIGINT or SIGTERM, or until a restart asked for with SIGUSR2
// can go ahead, and returns the exit code: 0, or idlerestart.ExitCode for that restart.
// SIGHUP reloads the settings.
func serve(cfg *config.Config, key serverkey.Key, log *slog.Logger, st *sqlite.Store) int {
	started := time.Now()
	server := api.New(cfg, key, log, st)
	var requests metrics.Requests
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           requests.Wrap(server.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	srv.RegisterOnShutdown(server.CloseFirehose)
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// ctx ends on SIGINT or SIGTERM, or when a restart goes ahead.
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()
	var exitCode atomic.Int32
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	log.Info("rerouted starting", "version", version.Number, "name", cfg.Name, "listen", cfg.Listen,
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

	// The built-in call relay.
	var relay *turnrelay.Relay
	if cfg.TurnListen != "" {
		var err error
		relay, err = turnrelay.Start(turnrelay.Config{
			Listen: cfg.TurnListen, PublicIP: cfg.TurnRelayIP(), MinPort: cfg.TurnRelayMin, MaxPort: cfg.TurnRelayMax,
			Realm: cfg.Name, Secret: func() string { return cfg.Now().TurnSecret }, Log: log,
		})
		if err != nil {
			log.Error("call relay", "listen", cfg.TurnListen, "err", err)
			return 1
		}
		defer relay.Close()
		log.Info("call relay listening", "listen", cfg.TurnListen, "udp_and_tcp", true, "public_ip", cfg.TurnRelayIP().String(),
			"relay_ports", cfg.TurnRelayMin, "relay_ports_to", cfg.TurnRelayMax, "urls", strings.Join(cfg.Now().TurnURLs, ","))
	}

	var state runState
	var restart idlerestart.Controller
	voiceActive := func() int { return server.Stats().VoiceRooms }

	// Metrics, on a listener of their own.
	if cfg.MetricsListen != "" {
		ln, err := net.Listen("tcp", cfg.MetricsListen)
		if err != nil {
			log.Error("metrics", "listen", cfg.MetricsListen, "err", err)
			return 1
		}
		ms := &http.Server{Handler: metrics.Handler(func() []metrics.Metric {
			src := metrics.Sources{Server: server, Store: st, Requests: &requests, Started: started,
				RestartPending: restart.Pending, UpdateAvailable: func() bool { return state.update() != "" }}
			if relay != nil {
				src.TurnAllocations = relay.Allocations
			}
			return metrics.Collect(ctx, src)
		}), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			ms.Close()
		}()
		go ms.Serve(ln)
		log.Info("metrics listening", "listen", cfg.MetricsListen, "path", "/metrics")
	}

	// The status file.
	statusDir := ""
	if fi, err := os.Stat(cfg.DataDir); err == nil && fi.IsDir() {
		statusDir = cfg.DataDir
	}
	changed := make(chan struct{}, 1)
	poke := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	var statusDone sync.WaitGroup
	statusCtx, stopStatus := context.WithCancel(context.Background())
	defer stopStatus()
	if statusDir != "" {
		write := func() {
			s := status.Status{
				Version: version.Number, PID: os.Getpid(), Started: started.Unix(), Updated: time.Now().Unix(),
				Name: cfg.Name, Listen: cfg.Listen, RestartPending: restart.Pending(), UpdateAvailable: state.update(),
				Metrics: cfg.MetricsListen, Turn: cfg.TurnListen,
			}
			stats := server.Stats()
			s.VoiceRooms, s.VoiceParticipants = stats.VoiceRooms, stats.VoiceParticipants
			qctx, cancel := context.WithTimeout(statusCtx, 5*time.Second)
			if db, err := st.Stats(qctx); err == nil {
				s.Outbox = int(db.Outbox)
			}
			cancel()
			if err := status.Write(statusDir, s); err != nil {
				log.Warn("status file", "err", err)
			}
		}
		write()
		statusDone.Add(1)
		go func() {
			defer statusDone.Done()
			t := time.NewTicker(statusEvery)
			defer t.Stop()
			for {
				select {
				case <-statusCtx.Done():
					return
				case <-t.C:
				case <-changed:
				}
				write()
			}
		}()
	}

	// Update checks, if they're on.
	checker := &updatecheck.Checker{
		Current: version.Number, UserAgent: version.UserAgent(), Log: log,
		Enabled: func() bool { return cfg.Now().UpdateCheck },
		OnNewer: func(r updatecheck.Release) {
			state.setUpdate(r.Version)
			poke()
		},
	}
	go checker.Run(ctx)

	// SIGHUP reloads the settings; SIGUSR2 asks for a restart once voice calls end.
	if len(sigs.Reload) > 0 {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, sigs.Reload...)
		defer signal.Stop(hup)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					reload(cfg, log)
					poke()
				}
			}
		}()
	}
	if len(sigs.RestartWhenIdle) > 0 {
		usr2 := make(chan os.Signal, 1)
		signal.Notify(usr2, sigs.RestartWhenIdle...)
		defer signal.Stop(usr2)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-usr2:
				}
				wait := cfg.Now().RestartMaxWait
				ready := func(o idlerestart.Outcome) {
					if o == idlerestart.TimedOut {
						log.Warn("restarting now: voice calls are still active, but the restart has waited long enough", "waited", wait.String())
					} else {
						log.Info("restarting now: no voice calls are active")
					}
					exitCode.Store(idlerestart.ExitCode)
					cancel()
				}
				if restart.Request(ctx, voiceActive, restartCheckEvery, wait, ready) {
					log.Info("restart pending: rerouted restarts once no voice calls are active", "max_wait", wait.String(), "active_voice_channels", voiceActive())
					poke()
				} else {
					log.Info("a restart is already pending")
				}
			}
		}()
	}

	err := srv.ListenAndServe()
	cancel()
	stopStatus()
	statusDone.Wait()
	if statusDir != "" {
		if err := status.Remove(statusDir); err != nil {
			log.Warn("status file", "err", err)
		}
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		return 1
	}
	return int(exitCode.Load())
}

// reload re-reads the settings, logging what happened.
func reload(cfg *config.Config, log *slog.Logger) {
	needRestart, err := cfg.Reload()
	if err != nil {
		log.Error("settings not reloaded: keeping the ones in use", "err", err)
		return
	}
	log.Info("settings reloaded")
	if len(needRestart) > 0 {
		log.Warn("some changed settings take effect only after a restart: keeping their old values for now", "settings", strings.Join(needRestart, ","))
	}
}

// runState is what the server learns while it runs, for the status file and metrics.
type runState struct {
	mu        sync.Mutex
	newerSeen string // the newest release the update check found
}

func (r *runState) setUpdate(v string) {
	r.mu.Lock()
	r.newerSeen = v
	r.mu.Unlock()
}

func (r *runState) update() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.newerSeen
}
