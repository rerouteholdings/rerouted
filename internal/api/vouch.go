package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Who vouches for chain entries (SPEC §6.5). A device-signed entry counts only if the
// server that was home just before it appended it: that server checked its clock and
// alerted the user's devices. Entries arriving from any other server are confirmed with
// that home. Recovery-signed entries count from anywhere.

const graceWindow = 72 * 3600 // seconds: deliveries from a previous home (SPEC §6.6)

// askHome asks a previous home for its copy of a chain (SPEC §6.5). Tests replace it.
func (s *Server) askHome(ctx context.Context, home, id string) ([][]byte, error) {
	if s.homeAsker != nil {
		return s.homeAsker(ctx, home, id)
	}
	raw, cached, err := s.fetchChain(ctx, home, id)
	if err == nil && cached {
		// It doesn't host the identity, and answered from its cache: that's a pointer to
		// where the identity lives, not the home vouching for anything. Treat it as the
		// 404 it would otherwise have sent.
		return nil, &fed.ErrStatus{Status: http.StatusNotFound, Code: wire.ErrCodeNotFound}
	}
	return raw, err
}

// fetchChainRaw asks a server for its copy of a chain, canonicalized, without following moves.
func (s *Server) fetchChainRaw(ctx context.Context, home, id string) ([][]byte, error) {
	raw, _, err := s.fetchChain(ctx, home, id)
	return raw, err
}

// fetchChain is fetchChainRaw, also saying whether the server answered from its cache
// rather than as the identity's host (`cached`, spec/api/s2s-stage2.md).
func (s *Server) fetchChain(ctx context.Context, home, id string) ([][]byte, bool, error) {
	if home == s.cfg.Name {
		raw, err := s.st.Chains().Entries(ctx, id, -1)
		return raw, false, err
	}
	if s.fed == nil {
		return nil, false, errors.New("no federation")
	}
	body, _ := wire.Marshal(map[string]any{"id": id})
	b, err := s.fed.Call(ctx, home, "identity/fetch", body)
	if err != nil {
		return nil, false, err
	}
	var res struct {
		Entries []wire.Raw `json:"entries"`
		Cached  bool       `json:"cached"`
	}
	if err := wire.Unmarshal(b, &res); err != nil {
		return nil, false, err
	}
	raw := make([][]byte, len(res.Entries))
	for i, e := range res.Entries {
		raw[i] = e
	}
	raw, err = s.canonChain(raw)
	return raw, res.Cached, err
}

// replayFor walks a chain of wire version v and reports, for each entry, the home before it
// and whether the recovery key signed it. It stops at the first entry that doesn't validate.
func replayFor(v int, raw [][]byte) (prevHome []string, byRecovery []bool, n int) {
	if len(raw) == 0 {
		return nil, nil, 0
	}
	sig, err := wire.DecodeSignedFor(v, raw[0])
	if err != nil {
		return nil, nil, 0
	}
	st, _, err := chain.GenesisFor(v, sig)
	if err != nil {
		return nil, nil, 0
	}
	prevHome, byRecovery = []string{""}, []bool{false}
	for i := 1; i < len(raw); i++ {
		sig, err := wire.DecodeSignedFor(v, raw[i])
		if err != nil {
			return prevHome, byRecovery, i
		}
		before := st.Home
		a, err := st.Apply(sig)
		if err != nil {
			return prevHome, byRecovery, i
		}
		prevHome = append(prevHome, before)
		byRecovery = append(byRecovery, a.Signer == chain.SignerRecovery)
	}
	return prevHome, byRecovery, len(raw)
}

// lastRecovery is the index of the last recovery-signed entry in the first n, or 0.
// A recovery-signed entry vouches for everything before it (SPEC §6.5).
func lastRecovery(byRecovery []bool, n int) int {
	for i := n - 1; i > 0; i-- {
		if byRecovery[i] {
			return i
		}
	}
	return 0
}

// vouched returns the longest prefix of candidate whose new entries (index >= start) the
// rule accepts, given that candidate came from server `from`.
func (s *Server) vouched(ctx context.Context, id string, candidate [][]byte, start int, from string) [][]byte {
	prevHome, byRecovery, n := s.replay(candidate)
	if n == 0 {
		return nil
	}
	covered := lastRecovery(byRecovery, n) // everything up to here is vouched for by recovery
	homes := map[string][][]byte{}         // each previous home's own copy, fetched once
	for i := max(start, 1); i < n; i++ {
		if i <= covered || byRecovery[i] || prevHome[i] == from {
			continue
		}
		theirs, ok := homes[prevHome[i]]
		if !ok {
			theirs, _ = s.askHome(ctx, prevHome[i], id)
			homes[prevHome[i]] = theirs
		}
		if !hasPrefix(theirs, candidate[:i+1]) {
			s.log.Warn("chain entry not vouched for by the home before it", "id", id, "seq", i, "from", from, "previous_home", prevHome[i])
			return candidate[:i]
		}
	}
	return candidate[:n]
}

func hasPrefix(chain, prefix [][]byte) bool {
	if len(chain) < len(prefix) {
		return false
	}
	return slices.EqualFunc(chain[:len(prefix)], prefix, bytes.Equal)
}

// errStorage marks an error as a storage failure rather than a problem with what was
// received, so the caller answers 503 and the sender retries.
var errStorage = errors.New("storage failure")

// acceptChain merges a chain received from server `from` into the cache: it must extend
// the cached chain or be a valid recovery fork (SPEC §6.5, §6.4.1), and only the vouched
// part of what's new is kept. With nothing cached, the chain is taken as its current home
// serves it. Returns the resulting state and entries, and whether anything changed.
func (s *Server) acceptChain(ctx context.Context, id string, raw [][]byte, from string) (*chain.State, [][]byte, bool, error) {
	raw, err := s.canonChain(raw)
	if err != nil {
		return nil, nil, false, err
	}
	st, err := s.decodeChain(raw)
	if err != nil {
		return nil, nil, false, err
	}
	if st.ID != id {
		return nil, nil, false, errors.New("chain is for a different identity")
	}
	_, cached, err := s.st.Remote().Get(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, false, fmt.Errorf("%w: %w", errStorage, err)
	}
	if err != nil {
		if st.Home != from {
			return nil, nil, false, fmt.Errorf("a first copy of a chain must come from its home, not %s", from)
		}
		if err := s.checkMoves(ctx, id, raw, from); err != nil {
			return nil, nil, false, err
		}
		if err := s.st.Remote().Put(ctx, id, st.Home, raw); err != nil {
			return nil, nil, false, fmt.Errorf("%w: %w", errStorage, err)
		}
		return st, raw, true, nil
	}
	keep, out, at, err := chain.ResolveFor(s.wv, cached, raw)
	if err != nil {
		return nil, nil, false, fmt.Errorf("conflicts with the cached chain: %w", err)
	}
	start := len(cached)
	switch out {
	case chain.Same:
		return keep, cached, false, nil
	case chain.Fork:
		start = int(at)
		s.log.Warn("recovery fork", "id", id, "from", from, "at", at)
	}
	accepted := s.vouched(ctx, id, raw, start, from)
	if len(accepted) <= start {
		cst, _ := s.decodeChain(cached)
		return cst, cached, false, nil
	}
	ast, err := s.decodeChain(accepted)
	if err != nil {
		return nil, nil, false, err
	}
	if err := s.st.Remote().Put(ctx, id, ast.Home, accepted); err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", errStorage, err)
	}
	return ast, accepted, true, nil
}

// fromHome reports whether `from` may speak for an identity (SPEC §10.2): its current home,
// or, with grace, the home it moved from, within the grace window (SPEC §6.6). Grace is only
// for deliveries the old home had already queued; anything new it asks for in the user's
// name (a key-package claim, a contact request) needs the current home. Wire version 1;
// fromHomeFor takes the version.
func fromHome(raw [][]byte, from string, now int64, grace bool) bool {
	return fromHomeFor(wire.V1, raw, from, now, grace)
}

func fromHomeFor(v int, raw [][]byte, from string, now int64, grace bool) bool {
	var st *chain.State
	for i, b := range raw {
		sig, err := wire.DecodeSignedFor(v, b)
		if err != nil {
			return false
		}
		if i == 0 {
			if st, _, err = chain.GenesisFor(v, sig); err != nil {
				return false
			}
			continue
		}
		prev := st.Home
		a, err := st.Apply(sig)
		if err != nil {
			return false
		}
		if grace && st.Home != prev && prev == from && int64(a.Entry.TS)+graceWindow >= now {
			return true
		}
	}
	return st != nil && st.Home == from
}

// checkMoves is the first-fetch check (SPEC §6.5): every device-signed set-home in a chain
// we have no copy of, and that no later recovery-signed entry vouches for, is confirmed
// with the home before it. A home that answers 404 or 410 is skipped; one that returns the
// chain without the entry fails it, and so, for now, does one that can't be reached: an
// unanswered question isn't a yes. A home that's gone for good means the move
// needs the recovery code (SPEC §6.6).
func (s *Server) checkMoves(ctx context.Context, id string, raw [][]byte, from string) error {
	_, err := s.confirmMoves(ctx, id, raw, from, len(raw))
	return err
}

// confirmMoves is checkMoves for the entries before `upto`: a registration check runs it
// without the newest entry, which the previous home hasn't been given yet (SPEC §6.6). It
// also says whether the newest entry is a move its previous home confirmed it appended.
func (s *Server) confirmMoves(ctx context.Context, id string, raw [][]byte, from string, upto int) (newestConfirmed bool, err error) {
	prevHome, byRecovery, n := s.replay(raw)
	if n != len(raw) {
		return false, errors.New("chain doesn't validate")
	}
	covered := lastRecovery(byRecovery, n)
	for i := covered + 1; i < upto; i++ {
		next := ""
		if i+1 < n {
			next = prevHome[i+1]
		} else if st, err := s.decodeChain(raw); err == nil {
			next = st.Home
		}
		moved := next != prevHome[i]
		if !moved || byRecovery[i] || prevHome[i] == from {
			continue
		}
		theirs, err := s.askHome(ctx, prevHome[i], id)
		var status *fed.ErrStatus
		if err != nil && errors.As(err, &status) && (status.Status == 404 || status.Status == 410) {
			continue // no longer knows the identity: nothing to ask
		}
		if err != nil {
			return false, fmt.Errorf("entry %d moves the account away from %s, which couldn't be asked to confirm it: try again later", i, prevHome[i])
		}
		if !hasPrefix(theirs, raw[:i+1]) {
			s.log.Warn("first fetch: a move its previous home doesn't know", "id", id, "seq", i, "previous_home", prevHome[i])
			return false, fmt.Errorf("entry %d moves the account away from %s, which didn't append it", i, prevHome[i])
		}
		if i == n-1 {
			newestConfirmed = true
		}
	}
	return newestConfirmed, nil
}
