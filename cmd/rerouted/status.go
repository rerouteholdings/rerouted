package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/version"
)

// statusStale is how old status.json can be before the server counts as not running. The
// server rewrites it more often than this.
const statusStale = 90 * time.Second

// serverStatus is {DATA_DIR}/status.json, which the running server keeps up to date.
type serverStatus struct {
	Version           string   `json:"version"`
	PID               int      `json:"pid"`
	Started           flexTime `json:"started"`
	Updated           flexTime `json:"updated"`
	Name              string   `json:"name"`
	Listen            string   `json:"listen"`
	VoiceRooms        int      `json:"voice_rooms"`
	VoiceParticipants int      `json:"voice_participants"`
	Outbox            int      `json:"outbox"`
	RestartPending    bool     `json:"restart_pending"`
	UpdateAvailable   string   `json:"update_available"` // the newer version, if any
	Metrics           string   `json:"metrics"`          // the metrics address, if on
	Turn              string   `json:"turn"`             // the built-in call relay's address, if on
}

// flexTime reads a time written as RFC 3339 text or as Unix seconds.
type flexTime struct{ time.Time }

func (t *flexTime) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		if s == "" {
			return nil
		}
		v, err := time.Parse(time.RFC3339Nano, s)
		t.Time = v
		return err
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	if n > 0 {
		t.Time = time.Unix(int64(n), 0)
	}
	return nil
}

func (t flexTime) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339))
}

// readStatus reads status.json from the data directory.
func readStatus(dataDir string) (*serverStatus, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "status.json"))
	if err != nil {
		return nil, err
	}
	var s serverStatus
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("status.json: %w", err)
	}
	return &s, nil
}

// running reports whether a server is running on dataDir: its status.json is fresh, or
// the process it names is alive. why says how it decided.
func running(dataDir string, now time.Time) (yes bool, s *serverStatus, why string) {
	s, err := readStatus(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, "no status.json"
		}
		if errors.Is(err, os.ErrPermission) {
			return false, nil, "can't read " + filepath.Join(dataDir, "status.json") + ": the data directory is the rerouted user's; run as it (sudo -u rerouted rerouted status) or as root"
		}
		return false, nil, err.Error()
	}
	age := now.Sub(s.Updated.Time)
	if !s.Updated.IsZero() && age < statusStale {
		return true, s, "status.json updated " + age.Round(time.Second).String() + " ago"
	}
	if s.PID > 0 && processAlive(s.PID) {
		return true, s, "status.json is stale, but process " + strconv.Itoa(s.PID) + " is alive"
	}
	return false, s, "status.json last updated " + age.Round(time.Second).String() + " ago"
}

// statusReport is status --json's output.
type statusReport struct {
	Running        bool          `json:"running"`
	Why            string        `json:"why"`
	Binary         string        `json:"binary_version"`
	RestartDue     bool          `json:"restart_due"`
	Uptime         float64       `json:"uptime_seconds,omitempty"`
	Server         *serverStatus `json:"server,omitempty"`
	Database       *dbCounts     `json:"database,omitempty"`
	DatabaseError  string        `json:"database_error,omitempty"`
	DataDir        string        `json:"data_dir"`
	SettingsFile   string        `json:"settings_file"`
	ServerName     string        `json:"name"`
	SchemaOfBinary int           `json:"schema_version"`
}

// dbCounts are what the database holds.
type dbCounts struct {
	Schema      int   `json:"schema_version"`
	Accounts    int   `json:"identities"`
	Devices     int   `json:"devices"`
	Communities int   `json:"communities"`
	Bytes       int64 `json:"bytes"`
}

func countDB(ctx context.Context, path string, st *sqlite.Store, name string) (*dbCounts, error) {
	c := &dbCounts{}
	var err error
	if c.Schema, err = st.SchemaVersion(); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(path + suffix); err == nil {
			c.Bytes += fi.Size()
		}
	}
	if c.Schema < sqlite.SchemaVersion {
		return c, fmt.Errorf("the database has schema %d, older than this binary's %d: the server upgrades it when it restarts", c.Schema, sqlite.SchemaVersion)
	}
	accounts, err := loadAccounts(ctx, st)
	if err != nil {
		return c, err
	}
	for _, a := range accounts {
		if a.here(name) {
			c.Accounts++
			c.Devices += a.Devices
		}
	}
	cs, err := st.CommunityCounts(ctx)
	if err != nil {
		return c, err
	}
	c.Communities = len(cs)
	return c, nil
}

func runStatus(g *globals, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] status [--json]")
		return 2
	}
	cfg, err := loadConfig(g)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	r := statusReport{Binary: version.Number, DataDir: cfg.DataDir, SettingsFile: g.env, ServerName: cfg.Name, SchemaOfBinary: sqlite.SchemaVersion}
	r.Running, r.Server, r.Why = running(cfg.DataDir, time.Now())
	if r.Server != nil && r.Running {
		r.RestartDue = r.Server.Version != "" && r.Server.Version != version.Number
		if !r.Server.Started.IsZero() {
			r.Uptime = time.Since(r.Server.Started.Time).Seconds()
		}
	}
	if st, err := openReadOnly(cfg); err != nil {
		r.DatabaseError = err.Error()
	} else {
		r.Database, err = countDB(context.Background(), dbFile(cfg), st, cfg.Name)
		if err != nil {
			r.DatabaseError = err.Error()
		}
		st.Close()
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(r)
		return 0
	}
	printStatus(os.Stdout, r)
	return 0
}

func printStatus(w io.Writer, r statusReport) {
	s := r.Server
	fmt.Fprintf(w, "%s (settings %s, data %s)\n", r.ServerName, r.SettingsFile, r.DataDir)
	if r.Running {
		fmt.Fprintf(w, "running:          yes (%s)\n", r.Why)
	} else {
		fmt.Fprintf(w, "running:          no (%s)\n", r.Why)
	}
	if s != nil && r.Running {
		if s.PID > 0 {
			fmt.Fprintf(w, "process:          %d\n", s.PID)
		}
		if r.Uptime > 0 {
			fmt.Fprintf(w, "up for:           %s (since %s)\n", humanDuration(time.Duration(r.Uptime)*time.Second), s.Started.UTC().Format("2006-01-02 15:04 MST"))
		}
		fmt.Fprintf(w, "version:          %s", s.Version)
		if r.RestartDue {
			fmt.Fprintf(w, " (this binary is %s: restart rerouted to run it)", r.Binary)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "voice calls:      %d rooms, %d people\n", s.VoiceRooms, s.VoiceParticipants)
		fmt.Fprintf(w, "outbox:           %d requests waiting for other servers\n", s.Outbox)
		if s.RestartPending {
			fmt.Fprintln(w, "restart pending:  yes, once no calls are active")
		}
		if s.UpdateAvailable != "" {
			fmt.Fprintf(w, "update available: %s\n", s.UpdateAvailable)
		}
		if s.Turn != "" {
			fmt.Fprintf(w, "call relay:       %s\n", s.Turn)
		}
		if s.Metrics != "" {
			fmt.Fprintf(w, "metrics:          http://%s/metrics\n", s.Metrics)
		}
	} else {
		fmt.Fprintf(w, "version:          %s (this binary)\n", r.Binary)
	}
	if d := r.Database; d != nil {
		fmt.Fprintf(w, "database:         %s, schema %d\n", humanBytes(d.Bytes), d.Schema)
		if r.DatabaseError == "" {
			fmt.Fprintf(w, "identities:       %d, with %d devices\n", d.Accounts, d.Devices)
			fmt.Fprintf(w, "communities:      %d\n", d.Communities)
		}
	}
	if r.DatabaseError != "" {
		fmt.Fprintf(w, "database:         %s\n", r.DatabaseError)
	}
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return d.Round(time.Second).String()
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
