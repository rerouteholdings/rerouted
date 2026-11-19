package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// optAuthed is like authed, but lets requests without a token through with an empty session.
// Handlers then serve only public, local data (chains and handles are public, SPEC §6.5).
func (s *Server) optAuthed(h func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			h(w, r, session{})
			return
		}
		s.authed(h)(w, r)
	}
}

// ---- GET servers/{name}: another server's document, for checking hub receipts ----

func (s *Server) serverInfo(w http.ResponseWriter, r *http.Request, _ session) {
	name := r.PathValue("name")
	if name == s.cfg.Name {
		s.serverDoc(w, r)
		return
	}
	d, err := s.fed.ServerDoc(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, err.Error())
		return
	}
	writeBody(w, http.StatusOK, d)
}

// ---- POST recover (spec/api/client-stage3.md) ----

// recoverAccount appends a recovery-signed entry for an identity that has no
// usable device (SPEC §6.1, §6.3). No session: the recovery key is the proof.
func (s *Server) recoverAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entry wire.Raw `json:"entry"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := s.decodeSignedField(w, req.Entry)
	if !ok {
		return
	}
	var e wire.ChainEntry
	if err := sig.OpenClosed(&e); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	for _, op := range e.Ops {
		if op.Op == wire.OpMigrate && s.wv == wire.V1 {
			// It registers a version 2 identity, which only chain/append does (SPEC §6.8).
			writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `migrate goes through chain/append, with the version 2 genesis in "genesis"`)
			return
		}
	}
	st, raw, err := s.identity(r.Context(), e.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	if chain.CheckClock(e.TS, uint64(now()), true) != nil {
		s.writeClockSkew(w, int64(e.TS), chain.MaxSkew)
		return
	}
	enc, _ := sig.Encode()
	devicesBefore := st.Devices
	homeBefore, handleBefore := st.Home, st.Handle
	var removed [][]byte
	switch {
	case e.Seq == st.Seq+1 && bytes.Equal(e.Prev, st.Head):
		// On top of the head.
		before := st.Seq
		applied, err := st.Apply(sig)
		if err != nil {
			writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, err.Error())
			return
		}
		if applied.Signer != chain.SignerRecovery {
			writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "recover takes only recovery-signed entries; devices use chain/append")
			return
		}
		if removed, err = s.revokeRemoved(r.Context(), e.ID, devicesBefore, st.Devices); err != nil {
			s.unavailableRead(w, "revoking a removed device's sessions", err)
			return
		}
		names, _, _, _ := s.handleChange(handleBefore, homeBefore, st, true) // never refused over a name (SPEC §5.3)
		if err := s.appendEntry(r.Context(), e.ID, before, enc, names); err != nil {
			writeChainWriteError(w, s, err)
			return
		}
	case e.Seq >= 1 && e.Seq <= st.Seq:
		// A fork that undoes recent device changes (SPEC §6.4.1).
		candidate := append(append([][]byte(nil), raw[:e.Seq]...), enc)
		next, out, at, err := chain.ResolveFor(s.wv, raw, candidate)
		if err != nil || out != chain.Fork {
			msg := "not a valid recovery fork"
			if err != nil {
				msg = err.Error()
			}
			writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, msg)
			return
		}
		if removed, err = s.revokeRemoved(r.Context(), e.ID, devicesBefore, next.Devices); err != nil {
			s.unavailableRead(w, "revoking a removed device's sessions", err)
			return
		}
		if names, _, _, _ := s.handleChange(handleBefore, homeBefore, next, true); names != nil {
			err = s.st.Chains().ForkHandle(r.Context(), e.ID, at, st.Seq, [][]byte{enc}, *names)
		} else {
			err = s.st.Chains().Fork(r.Context(), e.ID, at, st.Seq, [][]byte{enc})
		}
		if err != nil {
			writeChainWriteError(w, s, err)
			return
		}
		s.log.Warn("recovery fork", "id", e.ID, "replaced_from", at, "replaced_to", st.Seq)
		st = next
	default:
		writeError(w, http.StatusConflict, wire.ErrCodeStaleHead, "")
		return
	}
	for _, dev := range removed {
		s.closeDevice(e.ID, dev)
	}
	if st.Home != s.cfg.Name {
		s.dropPush(r.Context(), e.ID) // a recovery-signed move away
	}
	s.log.Info("account recovered", "id", e.ID, "seq", st.Seq)
	// Every remaining device hears about it: someone used the recovery code (SPEC §6.4.1).
	s.logged("sending a recovery alert", s.notify(r.Context(), e.ID, map[string]any{"t": "chain-alert", "level": "alarm", "entry": wire.Raw(enc)}))
	s.pushChain(r.Context(), e.ID)
	writeBody(w, http.StatusOK, map[string]any{"seq": st.Seq, "head": st.Head})
}

// ---- identity push (SPEC §6.5) ----

// pushChain tells everyone who has `id` as a contact that its chain changed: local
// users get a notice, other servers get the chain (S2S identity/push). It runs after the
// change is stored, so failures are only logged: contacts also fetch the chain when they
// next need it.
func (s *Server) pushChain(ctx context.Context, id string) {
	raw, err := s.st.Chains().Entries(ctx, id, -1)
	if err != nil {
		s.logged("reading a chain to push", err)
		return
	}
	cs, _, err := s.st.Contacts().List(ctx, id, "", 10000)
	if err != nil {
		s.logged("listing contacts to push a chain to", err)
		return
	}
	homes := map[string]bool{}
	for _, c := range cs {
		if c.State == store.StateBlocked {
			continue
		}
		if s.isLocal(ctx, c.ID) {
			s.logged("telling a contact about a chain update", s.notify(ctx, c.ID, map[string]any{"t": "chain-update", "id": id}))
			continue
		}
		if st, _, err := s.lookup(ctx, c.ID, ""); err == nil {
			homes[st.Home] = true
		} else if s.wv == wire.V2 {
			// A version 1 contact the migration carried over, who hasn't migrated yet (SPEC
			// §6.8): its version 2 identity will start on its version 1 home, which keeps our
			// chain current until then, for the contact carrying over on its side.
			if st, _, err := s.legacy().lookup(ctx, c.ID, ""); err == nil && st.Home != s.cfg.Name {
				homes[st.Home] = true
			}
		}
	}
	if s.fed == nil {
		return
	}
	entries := make([]wire.Raw, len(raw))
	for i, e := range raw {
		entries[i] = e
	}
	for home := range homes {
		s.logged("queueing a chain push", s.enqueue(ctx, home, "identity/push", map[string]any{"id": id, "entries": entries}))
	}
}

// s2sIdentityPush accepts an updated chain from the identity's homeserver, and tells
// local users who have it as a contact.
func (s *Server) s2sIdentityPush(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		ID      string     `json:"id"`
		Entries []wire.Raw `json:"entries"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	raw := make([][]byte, len(req.Entries))
	for i, e := range req.Entries {
		raw[i] = e
	}
	// It must extend our cache or be a valid recovery fork, and device-signed entries
	// count only if the home before them vouches for them (SPEC §6.5, §6.4.1).
	_, _, changed, err := s.acceptChain(r.Context(), req.ID, raw, from)
	if errors.Is(err, errStorage) {
		s.unavailableRead(w, "caching a pushed chain", err) // the pusher retries
		return
	}
	if err != nil {
		writeError(w, http.StatusConflict, wire.ErrCodeInvalidChain, err.Error())
		return
	}
	if changed {
		owners, err := s.st.Contacts().Owners(r.Context(), req.ID)
		s.logged("listing who to tell about a chain update", err)
		for _, o := range owners {
			s.logged("telling a contact about a chain update", s.notify(r.Context(), o, map[string]any{"t": "chain-update", "id": req.ID}))
		}
	}
	writeBody(w, http.StatusAccepted, map[string]any{})
}

// ---- S2S commit: sequencing for groups whose hub is here (SPEC §11.6) ----

func (s *Server) s2sCommit(w http.ResponseWriter, r *http.Request, _ string, body wire.Raw) {
	var req struct {
		Commit wire.Raw   `json:"commit"`
		Data   wire.Bytes `json:"data"`
	}
	if wire.Unmarshal(body, &req) != nil || req.Commit == nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	// The commit-request names the group and epoch; the epoch key signature is the authorization.
	sig, err := s.decodeSigned(req.Commit)
	var cr struct {
		Group wire.Bytes `json:"group"`
		Epoch uint64     `json:"epoch"`
	}
	if err != nil || sig.Open(&cr) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	receipt, code := s.sequence(r.Context(), req.Commit, req.Data, cr.Group, cr.Epoch)
	if code != "" {
		status := map[string]int{wire.ErrCodeStaleEpoch: 409, wire.ErrCodeAwaitingKey: 409, wire.ErrCodeNotFound: 404, wire.ErrCodeBadSignature: 400, wire.ErrCodeBadRequest: 400}[code]
		if status == 0 {
			status = 503
		}
		writeError(w, status, code, "")
		return
	}
	enc, _ := receipt.Encode()
	writeBody(w, http.StatusOK, map[string]any{"receipt": wire.Raw(enc)})
}
