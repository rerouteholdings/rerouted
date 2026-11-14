package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// admin runs an operator command against the server's storage, and returns the exit code.
// It works while the server runs: SQLite takes the second connection.
func admin(st store.Store, args []string) int {
	ctx := context.Background()
	switch args[0] {
	case "reports":
		n := 20
		if len(args) > 1 {
			var err error
			if n, err = strconv.Atoi(args[1]); err != nil || n < 1 {
				fmt.Fprintln(os.Stderr, "reports N: N is how many to show")
				return 2
			}
		}
		rs, err := st.Reports().List(ctx, n)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(rs) == 0 {
			fmt.Println("no reports")
		}
		for _, r := range rs {
			fmt.Printf("%s  from %s\n  reporter %s\n  reported %s\n  %s\n\n",
				time.Unix(r.Received, 0).UTC().Format(time.RFC3339), r.Origin, r.Reporter, r.Reported, r.Body)
		}
		return 0
	case "remove-media":
		if len(args) < 2 || len(args) > 3 {
			fmt.Fprintln(os.Stderr, "remove-media ID [--confirm]: the file's ID, base64url, as in its media-ref")
			return 2
		}
		if len(args) != 3 || args[2] != "--confirm" {
			fmt.Fprintln(os.Stderr, "This deletes the file's bytes for good. If the report might involve a crime,\n"+
				"preserve them first (docs/operators.md, \"Preserve evidence\"). Then run again with --confirm.")
			return 2
		}
		id, err := base64.RawURLEncoding.DecodeString(args[1])
		if err != nil || len(id) != 16 {
			fmt.Fprintln(os.Stderr, "the ID is 16 bytes of base64url")
			return 2
		}
		if err := st.Media().Remove(ctx, id); err != nil {
			fmt.Fprintln(os.Stderr, "remove-media:", err)
			return 1
		}
		fmt.Println("removed: fetches now answer 410 removed")
		return 0
	case "release-handle":
		if len(args) < 2 || len(args) > 3 {
			fmt.Fprintln(os.Stderr, "release-handle HANDLE [--confirm]: frees a handle so a new identity can register it")
			return 2
		}
		handle := strings.ToLower(strings.TrimPrefix(args[1], "@"))
		id, err := st.Chains().ByHandle(ctx, handle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nobody here holds %s\n", handle)
			return 1
		}
		if len(args) != 3 || args[2] != "--confirm" {
			fmt.Fprintf(os.Stderr, "%s belongs to %s. Releasing it lets a new identity register the name; the old\n"+
				"identity keeps its contacts and chats, but its handle stops resolving, so clients show it as\n"+
				"\"handle no longer valid\" (SPEC §5.3). Run again with --confirm.\n", handle, id)
			return 2
		}
		if _, err := st.Chains().ReleaseHandle(ctx, handle); err != nil {
			fmt.Fprintln(os.Stderr, "release-handle:", err)
			return 1
		}
		fmt.Printf("released %s (was %s)\n", handle, id)
		return 0
	case "keep-handle":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "keep-handle HANDLE: keeps a name reserved instead of freeing it when its 30-day hold ends")
			return 2
		}
		handle := strings.ToLower(strings.TrimPrefix(args[1], "@"))
		id, err := st.Chains().KeepHandle(ctx, handle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nobody here holds %s\n", handle)
			return 1
		}
		fmt.Printf("kept %s for %s: nobody else can register it. release-handle frees it\n", handle, id)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown command %q: use reports, remove-media, release-handle, or keep-handle\n", args[0])
	return 2
}
