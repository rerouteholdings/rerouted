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
	"flag"
	"log/slog"
	"os"
	"path/filepath"

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
	if flag.NArg() > 0 {
		code := admin(st, flag.Args())
		st.Close()
		os.Exit(code)
	}
	code := serve(cfg, key, log, st)
	st.Close()
	os.Exit(code)
}
