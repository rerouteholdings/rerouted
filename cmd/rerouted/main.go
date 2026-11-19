// Command rerouted is the reference Tieroute homeserver (README.md).
//
// With no command it runs the server. Commands look after it: rerouted help lists them,
// and docs/administer-a-homeserver.md and docs/rerouted.1 describe them.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

// globals are the options before the command.
type globals struct {
	env      string // the settings file in use
	envGiven bool   // -env was given
}

// command is one thing rerouted does besides serving.
type command struct {
	name, usage, summary string
	// run gets the command line from the command's name on.
	run func(g *globals, args []string) int
}

// commands, in the order help lists them. Only the ones that need the database open it.
// Set in init, since help and completion read the list.
var commands []command

func init() {
	commands = []command{
		{"init", "init [flags]", "set up a new homeserver: settings file, data directory, keys, Caddy, DNS records", runInit},
		{"checkup", "checkup [--peer NAME] [--handle H]", "check the configuration, DNS, certificates, clock, and call relay", runCheckup},
		{"status", "status [--json]", "show whether the server is running, and what it holds", runStatus},
		{"config", "config check", "check the settings file for mistakes", runConfig},
		{"backup", "backup [DEST]", "back up the database, keys, and files to one archive, while the server runs", runBackup},
		{"restore", "restore FILE [--force]", "restore a backup into the data directory, with the server stopped", runRestore},
		{"accounts", "accounts [N]", "list the N newest identities here (default 50)", dbCommand},
		{"communities", "communities", "list the communities this server hosts, with member counts", dbCommand},
		{"reports", "reports [N]", "print the N newest reports (default 20)", dbCommand},
		{"remove-media", "remove-media ID --confirm", "delete a reported file: fetches then answer 410 removed", dbCommand},
		{"release-handle", "release-handle HANDLE --confirm", "free a handle so a new identity can register it", dbCommand},
		{"keep-handle", "keep-handle HANDLE", "keep a handle reserved after its 30-day hold", dbCommand},
		{"auto-updates", "auto-updates on|off|status", "turn daily package updates of rerouted on or off", runAutoUpdates},
		{"version", "version", "print the version, Go version, platform, schema, and wire versions", runVersion},
		{"completion", "completion bash|zsh|fish", "print a shell completion script", runCompletion},
		{"help", "help", "show this help", func(*globals, []string) int { usage(os.Stdout); return 0 }},
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `rerouted is the reference Tieroute homeserver.

Usage:
  rerouted [-env FILE]                 run the server
  rerouted [-env FILE] COMMAND [ARGS]  run a command

Commands:
`)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-34s %s\n", c.usage, c.summary)
	}
	fmt.Fprint(w, `
Options:
  -env FILE  the settings file. Without it: .env in the working directory if it
             exists, else /etc/rerouted/rerouted.env if it exists.

Signals: SIGHUP reloads the settings; SIGUSR2 restarts once no calls are active
(exit status 75, for the service manager to start it again).

More: man rerouted, and docs/administer-a-homeserver.md.
`)
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("rerouted", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("env", "", "the settings file")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage(os.Stdout)
			return 0
		}
		fmt.Fprintln(os.Stderr, "rerouted:", err)
		usage(os.Stderr)
		return 2
	}
	g := &globals{env: *env}
	fs.Visit(func(f *flag.Flag) { g.envGiven = g.envGiven || f.Name == "env" })
	if !g.envGiven {
		g.env = defaultEnvFile()
	}
	if fs.NArg() == 0 {
		return runServer(g)
	}
	name, rest := fs.Arg(0), fs.Args()[1:]
	for _, c := range commands {
		if c.name != name {
			continue
		}
		if len(rest) == 1 && (rest[0] == "-h" || rest[0] == "--help") {
			fmt.Printf("Usage: rerouted [-env FILE] %s\n\n%s.\n", c.usage, capitalize(c.summary))
			if c.name == "init" {
				fmt.Println()
				initFlags(new(initOptions)).PrintDefaults()
			}
			return 0
		}
		return c.run(g, fs.Args())
	}
	fmt.Fprintf(os.Stderr, "rerouted: unknown command %q\n\n", name)
	usage(os.Stderr)
	return 2
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// runServer loads everything and serves until stopped.
func runServer(g *globals) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig(g)
	if err != nil {
		log.Error("config", "err", err)
		return 2
	}
	log = cfg.Logger(os.Stderr) // REROUTED_LOG_LEVEL and REROUTED_LOG_FORMAT; SIGHUP changes the level
	slog.SetDefault(log)        // the store logs through the default logger
	key, err := serverkey.LoadOrCreate(cfg.DataDir)
	if err != nil {
		log.Error("server key", "err", err)
		return 1
	}
	st, err := openStore(cfg)
	if err != nil {
		log.Error("database", "err", err)
		return 1
	}
	if cfg.Store == "temp" {
		log.Warn("storage is temporary: everything is deleted on shutdown (demos only)")
	}
	code := serve(cfg, key, log, st)
	st.Close()
	return code
}
