package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// account is one identity whose chain this server stores, as the commands show it.
type account struct {
	ID      string
	Wire    int
	Handle  string
	Devices int
	Created time.Time // the genesis entry's time
	Home    string    // the chain's home: another server once it moved away
	// Migrated: a wire version 1 identity that became a version 2 one (SPEC §6.8).
	Migrated bool
	Err      error // the chain didn't validate
}

// here reports whether the account lives on this server: not moved away or migrated.
func (a account) here(name string) bool { return a.Err == nil && !a.Migrated && a.Home == name }

// loadAccounts reads and validates every chain stored here, newest first.
func loadAccounts(ctx context.Context, st *sqlite.Store) ([]account, error) {
	chains, err := st.LocalChains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]account, 0, len(chains))
	for _, c := range chains {
		a := account{ID: c.ID, Wire: c.Wire}
		signed := make([]wire.Signed, len(c.Entries))
		for i, b := range c.Entries {
			if signed[i], a.Err = wire.DecodeSignedFor(c.Wire, b); a.Err != nil {
				break
			}
		}
		if a.Err == nil {
			var genesis wire.ChainEntry
			if err := signed[0].Open(&genesis); err == nil {
				a.Created = time.Unix(int64(genesis.TS), 0).UTC()
			}
			var s *chain.State
			if s, a.Err = chain.ValidateFor(c.Wire, signed); a.Err == nil {
				a.Handle, a.Devices, a.Home, a.Migrated = s.Handle, len(s.Devices), s.Home, s.Closed()
			}
		}
		out = append(out, a)
	}
	slices.SortStableFunc(out, func(x, y account) int { return y.Created.Compare(x.Created) })
	return out, nil
}

func listAccounts(ctx context.Context, cfg *config.Config, st *sqlite.Store, n int) int {
	accounts, err := loadAccounts(ctx, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "accounts:", err)
		return 1
	}
	if len(accounts) == 0 {
		fmt.Println("no identities")
		return 0
	}
	here := 0
	for _, a := range accounts {
		if a.here(cfg.Name) {
			here++
		}
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CREATED\tHANDLE\tDEVICES\tWIRE\tIDENTITY\tNOTE")
	for _, a := range accounts[:min(n, len(accounts))] {
		note := ""
		switch {
		case a.Err != nil:
			note = "chain doesn't validate: " + a.Err.Error()
		case a.Migrated:
			note = "migrated to wire version 2"
		case a.Home != cfg.Name:
			note = "moved to " + a.Home
		}
		handle := "-"
		if a.Handle != "" {
			handle = "@" + a.Handle
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", a.Created.Format("2006-01-02 15:04"), handle, a.Devices, a.Wire, a.ID, note)
	}
	w.Flush()
	fmt.Printf("\n%d identities live here, %d chains stored in all", here, len(accounts))
	if n < len(accounts) {
		fmt.Printf(" (showing the %d newest)", n)
	}
	fmt.Println()
	return 0
}

func listCommunities(ctx context.Context, cfg *config.Config, st *sqlite.Store) int {
	counts, err := st.CommunityCounts(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "communities:", err)
		return 1
	}
	created := map[string]sqlite.CommunityCount{}
	for _, c := range counts {
		created[c.Name] = c
	}
	if len(cfg.Communities) == 0 && len(counts) == 0 {
		fmt.Println("no communities: REROUTED_COMMUNITIES names none")
		return 0
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMEMBERS\tCREATED\tNOTE")
	listed := map[string]bool{}
	for _, cm := range cfg.Communities {
		listed[cm.Name] = true
		c, ok := created[cm.Name]
		if !ok {
			fmt.Fprintf(w, "%s\t-\t-\tnot created yet\n", cm.Name)
			continue
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t\n", c.Name, c.Members, time.Unix(c.Created, 0).UTC().Format("2006-01-02"))
	}
	for _, c := range counts {
		if !listed[c.Name] {
			fmt.Fprintf(w, "%s\t%d\t%s\tnot in REROUTED_COMMUNITIES: not served\n", c.Name, c.Members, time.Unix(c.Created, 0).UTC().Format("2006-01-02"))
		}
	}
	w.Flush()
	return 0
}

// joinNames lists names for a sentence.
func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
