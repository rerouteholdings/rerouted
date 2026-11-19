package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// packagedEnv is where the packages put the settings file.
const packagedEnv = "/etc/rerouted/rerouted.env"

// envSearch is where rerouted looks for the settings file without -env, in order.
var envSearch = []string{".env", packagedEnv}

// defaultEnvFile is the first settings file in envSearch that exists, or .env if none
// does, which config.Load treats as empty: settings then come from the environment only.
func defaultEnvFile() string {
	for _, f := range envSearch {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ".env"
}

// loadConfig loads the settings. A settings file named with -env must exist: a typo in
// its name would otherwise run with no settings at all.
func loadConfig(g *globals) (*config.Config, error) {
	if g.envGiven {
		if _, err := os.Stat(g.env); err != nil {
			return nil, err
		}
	}
	return config.Load(g.env)
}

// dbFile is the database's path.
func dbFile(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "rerouted-v1.db") }

// openStore opens the database for the server and the commands that change it, creating
// and upgrading it as needed.
func openStore(cfg *config.Config) (*sqlite.Store, error) {
	if cfg.Store == "temp" {
		return sqlite.OpenTemp()
	}
	return sqlite.Open(dbFile(cfg))
}

// openReadOnly opens the database for commands that only look. It never creates or
// upgrades it, so it's safe beside a running server of another version.
func openReadOnly(cfg *config.Config) (*sqlite.Store, error) {
	if cfg.Store == "temp" {
		return nil, errors.New("REROUTED_STORE=temp: the database only exists inside the running server")
	}
	st, err := sqlite.OpenReadOnly(dbFile(cfg))
	if errors.Is(err, os.ErrPermission) {
		return nil, fmt.Errorf("can't read %s: the data directory is the rerouted user's; run as it (sudo -u rerouted rerouted ...) or as root", cfg.DataDir)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no database at %s yet: rerouted creates it when it first starts", dbFile(cfg))
	}
	return st, err
}

// dbCommand runs an admin command (admin.go) against the database.
func dbCommand(g *globals, args []string) int {
	cfg, err := loadConfig(g)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	var st *sqlite.Store
	switch args[0] {
	case "accounts", "communities":
		st, err = openReadOnly(cfg)
	default:
		st, err = openStore(cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "database:", err)
		return 1
	}
	defer st.Close()
	return admin(cfg, st, args)
}
