package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- account keys and account data (SPEC §7.4, spec/api/client-stage4.md) ----

const maxAccountData = 256 << 10 // bytes of ciphertext

type wrappedKey struct {
	Via    string     `json:"via"`
	CT     wire.Bytes `json:"ct"`
	Commit wire.Bytes `json:"commit,omitempty"` // which recovery code: SHA-256 of its key 1 (SPEC §6.3)
	Argon2 *struct {
		Salt wire.Bytes `json:"salt"`
		M    uint64     `json:"m"`
		T    uint64     `json:"t"`
		P    uint64     `json:"p"`
	} `json:"argon2,omitempty"`
}

func (s *Server) getAccountKeys(w http.ResponseWriter, r *http.Request, sess session) {
	// Read through UpdateKeys for slot names: retained wraps aren't listed (see below).
	var items []wire.Raw
	err := s.st.Account().UpdateKeys(r.Context(), sess.id, func(_ [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		items = items[:0]
		for _, k := range slots {
			if !strings.HasPrefix(k.Slot, retainedPrefix) {
				items = append(items, k.Wrapped)
			}
		}
		return nil, nil
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	if items == nil {
		items = []wire.Raw{}
	}
	writeBody(w, http.StatusOK, map[string]any{"items": items})
}

// Recovery wraps (SPEC §6.3, §7.4) live in three kinds of slot:
//
//   - "recovery": the current recovery wrap.
//   - "recovery-next/<commit>": a rotation's staged wrap, one per recovery code, named by
//     the commitment to the code's key 1. Older clients kept one, in a slot named
//     "recovery-next"; it's moved to its own slot the first time the identity's wraps are touched.
//   - "recovery-retained/<commit>/<digest>": a recovery wrap that a promotion replaced. It
//     isn't listed, and nothing deletes it on its own. Old codes keep account-key access as
//     long as it's kept, until the user asks to forget it (below).
//
// Every decision is made inside Account().UpdateKeys, which is serialized with chain
// writes, so the chain it reads is still the chain when its changes land:
//
//   - Promotion (set "recovery") is a compare-and-swap on the chain and the current wrap:
//     the code has to be one the chain commits to (some set-recovery's next), and no older
//     there than the current wrap's code. A stale promoter is refused, never replaces the
//     winner. Promoting the code that's already current changes nothing.
//   - Cleanup (remove "recovery-next") never deletes a staged wrap whose code the chain
//     commits to, unless a recovery wrap for that code is stored (it was promoted). One the
//     chain doesn't commit to is kept for stagedGrace after it was staged, since its entry
//     may still be appended; after that it can go.
//   - Staged plus retained wraps are capped per identity. At the cap, staging is refused,
//     and nothing is evicted.
//   - Forgetting (remove "retained") deletes only retained wraps, and only for codes the
//     chain has superseded: ones it doesn't commit to, or commits to earlier than the current
//     wrap's code. It never touches the current wrap or a staged one. And it waits until the
//     entry that made the current code current is forgetAfter old, the fork window (SPEC
//     §6.4.1), so a fork can't bring back a code whose wrap is gone. The wait is measured
//     from that one entry for every retained wrap: the strictest choice, and the simplest.
const (
	maxStaged        = 8         // unpromoted staged wraps at once
	maxRecoveryWraps = 32        // unpromoted staged wraps plus retained ones, per identity
	stagedGrace      = 24 * 3600 // seconds an unreferenced staged wrap is kept
	forgetAfter      = 72 * 3600 // seconds the current code's entry must be old before retained wraps go
	retainedPrefix   = "recovery-retained/"
)

// wrapClock is the clock wrap decisions read. Tests move it to look past the fork window.
var wrapClock = now

var (
	errWrapStale = errors.New("the chain doesn't commit to that recovery code, or a newer one is already current")
	errWrapsFull = errors.New("too many recovery wraps")
)

func stagedSlot(commit []byte) string { return "recovery-next/" + hex.EncodeToString(commit) }

// wrapState is an identity's recovery wraps as one UpdateKeys call sees them, with the
// changes it has decided on.
type wrapState struct {
	now      int64
	pos      map[string]int // hex(commit) -> order of the chain's last set-recovery naming it
	posTS    []int64        // order -> ts of the entry holding that set-recovery
	current  *store.KeySlot
	curKey   wrappedKey
	staged   map[string]store.KeySlot // slot -> wrap
	commits  map[string][]byte        // staged slot -> commit
	retained int
	kept     map[string][]byte // retained slot -> its code's commit, nil for a wrap without one
	promoted map[string]bool   // hex(commit) of every stored recovery wrap, current or retained
	changes  []store.KeyChange
}

// recoveryPositions orders the commitments the chain's set-recovery ops have named.
// Recovery wraps name a code's key 1, so only the entries that start a code (genesis and
// rotations) can match one; advancing within a code adds commitments no wrap names.
func recoveryPositions(chain [][]byte) (map[string]int, []int64) {
	pos := map[string]int{}
	var at []int64
	n := 0
	for _, raw := range chain {
		// The identity's own stored chain, so the body is all that's read. A wire version 2
		// entry's envelope has version 2's shape.
		sig, err := wire.DecodeSigned(raw)
		if err != nil {
			if sig, err = wire.DecodeSignedV2(raw); err != nil {
				continue
			}
		}
		var e wire.ChainEntry
		if sig.Open(&e) != nil {
			continue
		}
		for _, op := range e.Ops {
			if op.Op == wire.OpSetRecovery && len(op.Next) == 32 {
				pos[hex.EncodeToString(op.Next)] = n
				at = append(at, int64(e.TS))
				n++
			}
		}
	}
	return pos, at
}

func loadWraps(chain [][]byte, slots []store.KeySlot, now int64) (*wrapState, error) {
	ws := &wrapState{now: now, staged: map[string]store.KeySlot{}, commits: map[string][]byte{}, kept: map[string][]byte{}, promoted: map[string]bool{}}
	ws.pos, ws.posTS = recoveryPositions(chain)
	var legacy *store.KeySlot
	for i, k := range slots {
		var w wrappedKey
		ok := wire.Unmarshal(k.Wrapped, &w) == nil
		switch {
		case k.Slot == "recovery":
			ws.current = &slots[i]
			if ok {
				ws.curKey = w
				if len(w.Commit) == 32 {
					ws.promoted[hex.EncodeToString(w.Commit)] = true
				}
			}
		case k.Slot == "recovery-next":
			legacy = &slots[i]
		case strings.HasPrefix(k.Slot, "recovery-next/"):
			if !ok || len(w.Commit) != 32 {
				return nil, errors.New("invalid staged wrap")
			}
			ws.staged[k.Slot] = k
			ws.commits[k.Slot] = w.Commit
		case strings.HasPrefix(k.Slot, retainedPrefix):
			ws.retained++
			ws.kept[k.Slot] = nil
			if ok && len(w.Commit) == 32 {
				ws.promoted[hex.EncodeToString(w.Commit)] = true
				ws.kept[k.Slot] = w.Commit
			}
		}
	}
	if legacy != nil { // an older client's single staged slot: moved to its own, in the same transaction
		var w wrappedKey
		if wire.Unmarshal(legacy.Wrapped, &w) != nil || w.Via != "recovery-next" || len(w.Commit) != 32 {
			return nil, errors.New("invalid legacy staged wrap")
		}
		slot := stagedSlot(w.Commit)
		if _, have := ws.staged[slot]; !have {
			moved := store.KeySlot{Slot: slot, Wrapped: legacy.Wrapped, Stored: legacy.Stored}
			ws.staged[slot] = moved
			ws.commits[slot] = w.Commit
			ws.changes = append(ws.changes, store.KeyChange{Slot: slot, Wrapped: moved.Wrapped, Stored: moved.Stored})
		}
		ws.changes = append(ws.changes, store.KeyChange{Slot: "recovery-next", Delete: true})
	}
	return ws, nil
}

// pending counts the staged wraps that haven't been promoted.
func (ws *wrapState) pending() int {
	n := 0
	for slot := range ws.staged {
		if !ws.promoted[hex.EncodeToString(ws.commits[slot])] {
			n++
		}
	}
	return n
}

// stage stores a rotation's staged wrap. Staging a code again, or one already promoted,
// changes nothing: the first copy is kept.
func (ws *wrapState) stage(commit, canon []byte) error {
	slot := stagedSlot(commit)
	if _, have := ws.staged[slot]; have || ws.promoted[hex.EncodeToString(commit)] {
		return nil
	}
	if p := ws.pending(); p >= maxStaged || p+ws.retained >= maxRecoveryWraps {
		return errWrapsFull
	}
	ws.changes = append(ws.changes, store.KeyChange{Slot: slot, Wrapped: canon, Stored: ws.now})
	return nil
}

// promote makes a wrap the current recovery wrap, if the chain allows it (see above).
func (ws *wrapState) promote(commit, canon []byte) error {
	cur := ws.curKey.Commit
	if commit == nil { // a wrap from an older client names no code, so it can't replace one that does
		switch {
		case ws.current == nil:
		case len(cur) == 32:
			return errWrapStale
		case bytes.Equal(ws.current.Wrapped, canon):
			return nil
		}
	} else {
		p, ok := ws.pos[hex.EncodeToString(commit)]
		if !ok {
			return errWrapStale
		}
		if ws.current != nil && len(cur) == 32 {
			if bytes.Equal(cur, commit) {
				return nil
			}
			if pc, ok := ws.pos[hex.EncodeToString(cur)]; ok && p < pc {
				return errWrapStale
			}
		}
	}
	if ws.current != nil {
		// The replaced wrap is retained. A staged copy of the promoted code stops counting,
		// so finishing a staged rotation never runs into the cap.
		growth := 1
		if _, have := ws.staged[stagedSlot(commit)]; have && commit != nil && !ws.promoted[hex.EncodeToString(commit)] {
			growth = 0
		}
		if growth > 0 && ws.pending()+ws.retained >= maxRecoveryWraps {
			return errWrapsFull
		}
		digest := sha256.Sum256(ws.current.Wrapped)
		name := "legacy"
		if len(cur) == 32 {
			name = hex.EncodeToString(cur)
		}
		ws.changes = append(ws.changes, store.KeyChange{Slot: retainedPrefix + name + "/" + hex.EncodeToString(digest[:8]), Wrapped: ws.current.Wrapped, Stored: ws.current.Stored})
	}
	ws.changes = append(ws.changes, store.KeyChange{Slot: "recovery", Wrapped: canon, Stored: ws.now})
	return nil
}

// cleanup removes staged wraps, the one for `commit` or (older clients, which name none) every one, that
// are safe to remove (see above), and keeps the rest.
func (ws *wrapState) cleanup(commit []byte) (kept int) {
	slots := make([]string, 0, len(ws.staged))
	for slot := range ws.staged {
		slots = append(slots, slot)
	}
	slices.Sort(slots)
	for _, slot := range slots {
		c := ws.commits[slot]
		if commit != nil && !bytes.Equal(c, commit) {
			continue
		}
		_, referenced := ws.pos[hex.EncodeToString(c)]
		switch {
		case ws.promoted[hex.EncodeToString(c)]:
		case referenced, ws.now-ws.staged[slot].Stored < stagedGrace:
			kept++
			continue
		}
		ws.changes = append(ws.changes, store.KeyChange{Slot: slot, Delete: true})
	}
	return kept
}

// forget deletes the retained wraps whose codes the chain has superseded, if the entry that
// made the current code current is at least forgetAfter old (see above). It reports how
// many it deleted, how many it kept only because that entry is too new, and how many
// seconds until they can go. Retained wraps it can't place before the current code (the
// current wrap names no code, or the chain doesn't commit to it, or one names a code no
// older than it) are kept, and counted in neither.
func (ws *wrapState) forget() (removed, waiting int, retry int64) {
	cur := ws.curKey.Commit
	if ws.current == nil || len(cur) != 32 {
		return 0, 0, 0
	}
	pc, ok := ws.pos[hex.EncodeToString(cur)]
	if !ok {
		return 0, 0, 0
	}
	age := ws.now - ws.posTS[pc]
	slots := make([]string, 0, len(ws.kept))
	for slot := range ws.kept {
		slots = append(slots, slot)
	}
	slices.Sort(slots)
	for _, slot := range slots {
		if c := ws.kept[slot]; c != nil {
			if bytes.Equal(c, cur) {
				continue
			}
			if p, in := ws.pos[hex.EncodeToString(c)]; in && p >= pc {
				continue
			}
		}
		if age < forgetAfter {
			waiting++
			continue
		}
		ws.changes = append(ws.changes, store.KeyChange{Slot: slot, Delete: true})
		removed++
	}
	ws.retained -= removed
	if waiting > 0 {
		retry = forgetAfter - age
	}
	return removed, waiting, retry
}

// updateWraps runs f on the identity's recovery wraps inside one UpdateKeys call.
func (s *Server) updateWraps(ctx context.Context, id string, f func(ws *wrapState) error) error {
	return s.st.Account().UpdateKeys(ctx, id, func(chain [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		ws, err := loadWraps(chain, slots, wrapClock())
		if err != nil {
			return nil, err
		}
		if err := f(ws); err != nil {
			return nil, err
		}
		return ws.changes, nil
	})
}

func (s *Server) writeWrapError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errWrapStale):
		writeError(w, http.StatusConflict, wire.ErrCodeStaleVersion, "the chain doesn't commit to that recovery code, or a newer one is already current: fetch the chain")
	case errors.Is(err, errWrapsFull):
		writeError(w, http.StatusTooManyRequests, wire.ErrCodeRateLimited, "too many recovery-code rotations in progress: finish or remove one")
	default:
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
	}
}

func (s *Server) postAccountKeys(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Set    wire.Raw   `json:"set,omitempty"`
		Remove string     `json:"remove,omitempty"`
		Commit wire.Bytes `json:"commit,omitempty"` // with remove "recovery-next": which one
	}
	if !readBody(w, r, &req) {
		return
	}
	ctx := r.Context()
	switch {
	case req.Set != nil && req.Remove == "":
		var k wrappedKey
		if wire.Unmarshal(req.Set, &k) != nil || len(k.CT) == 0 || len(k.CT) > 1024 {
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "set must be a wrapped-key")
			return
		}
		switch {
		case k.Via == "recovery" && k.Argon2 == nil && (k.Commit == nil || len(k.Commit) == 32):
		case k.Via == "recovery-next" && k.Argon2 == nil && len(k.Commit) == 32: // staged by a rotation (SPEC §6.3)
		case k.Via == "passphrase" && k.Argon2 != nil && len(k.Argon2.Salt) == 16 && k.Commit == nil:
		default:
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `via is "recovery", "recovery-next" with a 32-byte commit, or "passphrase" with argon2 and a 16-byte salt`)
			return
		}
		canon, _ := wire.Marshal(k)
		var err error
		switch k.Via {
		case "recovery-next":
			err = s.updateWraps(ctx, sess.id, func(ws *wrapState) error { return ws.stage(k.Commit, canon) })
		case "recovery":
			err = s.updateWraps(ctx, sess.id, func(ws *wrapState) error { return ws.promote(k.Commit, canon) })
		default:
			err = s.st.Account().SetKey(ctx, sess.id, k.Via, canon)
		}
		if err != nil {
			if errors.Is(err, errWrapStale) {
				s.log.Info("refused a stale recovery wrap", "id", sess.id)
			}
			s.writeWrapError(w, err)
			return
		}
	case req.Set == nil && req.Remove == "passphrase" && req.Commit == nil:
		// The recovery copy can't be removed: it's how a user who loses every device gets back in.
		if err := s.st.Account().RemoveKey(ctx, sess.id, req.Remove); err != nil {
			writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
			return
		}
	case req.Set == nil && req.Remove == "retained" && req.Commit == nil:
		// Forget older recovery codes (SPEC §7.4): only superseded retained wraps, after the
		// fork window. A signed-in device asks; never a recovery-key signature, which would
		// reveal the next key before it's used (SPEC §6.3).
		var removed, waiting int
		var retry int64
		err := s.updateWraps(ctx, sess.id, func(ws *wrapState) error { removed, waiting, retry = ws.forget(); return nil })
		if err != nil {
			s.writeWrapError(w, err)
			return
		}
		if removed > 0 {
			s.log.Info("forgot retained recovery wraps", "id", sess.id, "removed", removed)
		}
		if removed == 0 && waiting > 0 {
			writeBody(w, http.StatusTooManyRequests, wire.Error{Code: wire.ErrCodeRateLimited, Msg: "the recovery code changed less than 72 hours ago: older codes can be forgotten after that", Retry: uint64(max(retry, 1))})
			return
		}
		writeBody(w, http.StatusOK, map[string]any{"removed": removed, "waiting": waiting})
		return
	case req.Set == nil && req.Remove == "recovery-next" && (req.Commit == nil || len(req.Commit) == 32):
		var kept int
		err := s.updateWraps(ctx, sess.id, func(ws *wrapState) error { kept = ws.cleanup(req.Commit); return nil })
		if err != nil {
			s.writeWrapError(w, err)
			return
		}
		if kept > 0 {
			s.log.Info("kept staged recovery wraps that may still be needed", "id", sess.id, "kept", kept)
		}
	default:
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `give "set", or "remove": "passphrase", "retained", or "recovery-next" with its 32-byte "commit"`)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getAccountData(w http.ResponseWriter, r *http.Request, sess session) {
	v, ct, err := s.st.Account().Data(r.Context(), sess.id)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	res := map[string]any{"version": v}
	if v > 0 {
		res["ct"] = wire.Bytes(ct)
	}
	writeBody(w, http.StatusOK, res)
}

func (s *Server) postAccountData(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		CT       wire.Bytes `json:"ct"`
		Replaces int64      `json:"replaces"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if len(req.CT) < 28 || req.Replaces < 0 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "ct is a nonce and AES-GCM output")
		return
	}
	if len(req.CT) > maxAccountData {
		writeError(w, http.StatusRequestEntityTooLarge, wire.ErrCodeTooLarge, "account data is at most 256 KiB")
		return
	}
	v, err := s.st.Account().PutData(r.Context(), sess.id, req.Replaces, req.CT)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, wire.ErrCodeStaleVersion, "another device wrote first: fetch, merge, and try again")
		return
	} else if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"version": v})
}
