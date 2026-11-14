package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- handle changes (SPEC §5.3) ----
//
// A homeserver gives each of its users a name under its handle domain. A chain entry that
// changes the identity's handle (set-handle) or its home (a move away) changes which of
// those names the identity uses, in the same transaction as the entry:
//
//   - A new name under this server's handle domain has to be free: not in use, in its hold,
//     or kept reserved for another identity, and not a reserved name (SPEC §5.4). Otherwise
//     the entry is refused with 409 handle-taken, and nothing is stored. A name elsewhere
//     (the user's own domain) is the user's to publish.
//   - The name it stops using is held for it for 30 days (store.HandleHold). Nobody else can
//     register it or move here with it, and it resolves as no longer valid, because the
//     chain doesn't name it. The identity can take it back.
//   - After the hold, maintenance frees it, unless the operator keeps it reserved
//     (rerouted keep-handle).
//
// A recovery-signed entry is never refused over a name: if its name is taken, it's stored
// without it, and the handle doesn't resolve until the user picks another.

// handleChange is what a chain write that took a local identity from handleBefore and
// homeBefore to `after` does to the names this server gives out: nil if it changes neither
// handle nor home, or, with a status, the refusal.
func (s *Server) handleChange(handleBefore, homeBefore string, after *chain.State, byRecovery bool) (h *store.HandleChange, status int, code, msg string) {
	if after.Handle == handleBefore && after.Home == homeBefore {
		return nil, 0, "", ""
	}
	h = &store.HandleChange{BestEffort: byRecovery}
	if after.Home != s.cfg.Name || s.cfg.Handles == "" || !strings.HasSuffix(after.Handle, "."+s.cfg.Handles) {
		return h, 0, "", "" // a name this server doesn't give out, or none: its own go into their hold
	}
	switch {
	case !validHandleUnder(after.Handle, s.cfg.Handles):
		status, code, msg = http.StatusBadRequest, wire.ErrCodeInvalidChain, "a handle under "+s.cfg.Handles+" is <name>."+s.cfg.Handles
	case reservedHandles[strings.TrimSuffix(after.Handle, "."+s.cfg.Handles)]:
		status, code, msg = http.StatusConflict, wire.ErrCodeHandleTaken, "that name is reserved"
	default:
		h.Handle = after.Handle
		return h, 0, "", ""
	}
	if byRecovery {
		return h, 0, "", ""
	}
	return nil, status, code, msg
}

// appendEntry stores a local identity's next entry, with its handle change if it has one.
func (s *Server) appendEntry(ctx context.Context, id string, prevSeq uint64, entry []byte, h *store.HandleChange) error {
	if h != nil {
		return s.st.Chains().AppendHandle(ctx, id, prevSeq, entry, *h)
	}
	return s.st.Chains().Append(ctx, id, prevSeq, entry)
}
