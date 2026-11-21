package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

// runKeys lists the server's keys, or rotates them at once (SPEC §5.1). The running server
// rotates on its own; `rotate` is for a key that may have leaked, and `--revoke` marks the
// replaced keys revoked from now, so nothing they sign from now on counts.
func runKeys(g *globals, args []string) int {
	rotate, revoke := false, false
	for _, a := range args[1:] {
		switch a {
		case "rotate":
			rotate = true
		case "--revoke":
			revoke = true
		default:
			fmt.Fprintln(os.Stderr, "usage: rerouted [-env FILE] keys [rotate [--revoke]]")
			return 2
		}
	}
	if revoke && !rotate {
		fmt.Fprintln(os.Stderr, "keys: --revoke goes with rotate")
		return 2
	}
	cfg, err := loadConfig(g)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	// Run as root, the files it writes go to the data directory's owner, the server's user.
	owner, _ := os.Stat(cfg.DataDir)
	defer func() {
		for _, pat := range []string{"server-key*.json", "community-key-*.json", "invite-key.json"} {
			files, _ := filepath.Glob(filepath.Join(cfg.DataDir, pat))
			for _, f := range files {
				chownTree(f, owner)
			}
		}
	}()
	keys, err := serverkey.LoadOrCreate(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keys:", err)
		return 1
	}
	slots := []struct {
		name string
		slot *serverkey.Slot
	}{{cfg.Name + " (wire version 1)", keys.V1}, {cfg.Name + " (wire version 2)", keys.V2}}
	for _, cm := range cfg.Communities {
		if cm.Name == cfg.Name {
			continue
		}
		s, err := serverkey.LoadOrCreateComposite(cfg.DataDir, "community-key-"+cm.Name+".json")
		if err != nil {
			fmt.Fprintln(os.Stderr, "keys:", err)
			return 1
		}
		slots = append(slots, struct {
			name string
			slot *serverkey.Slot
		}{cm.Name + " (community server)", s})
	}
	now := time.Now()
	if rotate {
		var revoked int64
		if revoke {
			revoked = now.Unix()
		}
		for _, s := range slots {
			if err := s.slot.Rotate(now, revoked); err != nil {
				fmt.Fprintln(os.Stderr, "keys:", s.name+":", err)
				return 1
			}
		}
		fmt.Println("Rotated. A running rerouted signs with the new keys within 10 minutes.")
		if revoke {
			fmt.Println("The replaced keys are revoked from now: nothing they sign from now on counts.")
		}
		fmt.Println()
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tKID\tVALID FROM\tUNTIL\tSTATE")
	for _, s := range slots {
		pub := s.slot.Published(now)
		for i, p := range pub {
			state := "replaced"
			switch {
			case i == 0:
				state = "signing"
			case p.Revoked != 0:
				state = "revoked " + time.Unix(p.Revoked, 0).UTC().Format("2006-01-02 15:04")
			case p.NBF > pub[0].NBF: // made after the signing key: its successor
				state = "next"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.name, p.KID, day(p.NBF), day(p.EXP), state)
		}
	}
	w.Flush()
	return 0
}

func day(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02") }
