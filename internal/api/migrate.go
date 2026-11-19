package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rerouteholdings/rerouted/internal/chain"
	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Migrating from wire version 1 to version 2 (SPEC §6.8).
//
// A version 1 identity becomes a version 2 one in two signed steps: the device makes the
// version 2 genesis, whose `migrated-from` names the version 1 identifier, then a current
// version 1 device appends `migrate`, naming the genesis's hash, to the version 1 chain.
//
// Ordering. The server does both at once: the version 1 `POST chain/append` that carries
// `migrate` also carries the version 2 genesis (`genesis`), and one transaction appends the
// entry, registers the version 2 identity, hands it the handle, and carries the allowlists
// over (store.Migration). So neither step can be left without the other:
//
//   - Registering the version 2 identity first, on its own, would leave it holding nothing
//     a stranger couldn't claim: anyone can sign a genesis that names someone's version 1
//     identifier, and the handle still belongs to the version 1 identity.
//   - Appending `migrate` first, on its own, would close the version 1 chain, and a version
//     2 registration that then failed (a taken handle, a storage failure) would strand the
//     user with neither.
//
// The version 2 `POST register` with a genesis that names a version 1 identity only
// confirms a migration that happened (200, the same as a retry); before the `migrate` it
// answers 403 not-allowed and says to append it. A lost reply is safe either way: the
// append is idempotent, and the version 1 chain says whether it happened.
//
// The migration happens on the version 1 identity's homeserver, and the version 2 identity
// starts there; moving it is a separate step (SPEC §6.6).
//
// After it, the version 1 chain is closed. Everything sent to the version 1 identity is
// refused out loud with 410 `migrated`: version 1 deliveries (to the sender's devices as
// a delivery-failed event, when they went to another server), key-package claims, and
// contact requests from its own server. Its handle no longer resolves on the version 1
// API, and resolves to the version 2 identity on the version 2 API. Its devices keep their
// version 1 sessions, to read what's left in the version 1 inbox, but can't send.
//
// Contacts carry over once both sides have migrated: the version 2 identity's contact list
// starts as the version 1 one's, and an entry for a version 1 identity becomes its version
// 2 identity when both links check out (chain.Linked): at the migration, when another
// server pushes a version 1 chain that ends in `migrate` (or it's fetched), and when a
// version 2 client lists its contacts.

const (
	migratedMsg     = "this identity moved to Tieroute wire version 2: update the app to reach it"
	migratedSelfMsg = "this identity moved to Tieroute wire version 2: sign in with the version 2 identity"
)

var errNotMigrated = errors.New("not a migrated version 1 identity")

// legacy is the version 1 Server, from either version's.
func (s *Server) legacy() *Server {
	if s.wv == wire.V1 {
		return s
	}
	return s.v1
}

// modern is the version 2 Server, from either version's.
func (s *Server) modern() *Server {
	if s.wv == wire.V2 {
		return s
	}
	return s.v2
}

// closedLocal reports whether id is a local version 1 identity whose chain ended in migrate.
func (s *Server) closedLocal(ctx context.Context, id string) bool {
	if s.wv != wire.V1 {
		return false
	}
	st, _, err := s.identity(ctx, id)
	return err == nil && st.Closed()
}

// closedKnown is closedLocal, or a remote version 1 identity whose chain, as we have it, ended
// in migrate. It doesn't ask other servers.
func (s *Server) closedKnown(ctx context.Context, id string) bool {
	if s.wv != wire.V1 {
		return false
	}
	raw, err := s.lookupCached(ctx, id)
	if err != nil {
		return false
	}
	st, err := s.decodeChain(raw)
	return err == nil && st.Closed()
}

// followMigration finds the version 2 identity a version 1 identity migrated to, and checks
// both links (SPEC §6.8). The version 1 chain comes from here or our cache, or from
// homeHint if it's given; the version 2 one from here, our cache, or the home the version 1
// chain names, which is where the version 2 identity starts. Call it on the version 2 Server.
func (s *Server) followMigration(ctx context.Context, id1, homeHint string) (*chain.State, error) {
	old := s.legacy()
	st1, _, err := old.lookup(ctx, id1, homeHint)
	if err != nil {
		return nil, err
	}
	if !st1.Closed() {
		return nil, errNotMigrated
	}
	st2, _, err := s.modern().lookup(ctx, st1.MigratedID(), st1.Home)
	if err != nil {
		return nil, err
	}
	if !chain.Linked(st1, st2) {
		return nil, errors.New("the version 2 identity and the version 1 migrate don't name each other")
	}
	return st2, nil
}

// migratedContacts maps the contacts of a local version 1 identity that have migrated to
// their version 2 identities, as far as we know without asking about the version 1 chains
// again. Those we don't know about yet are kept as they are, and rewritten when we learn of
// it (onMigrated, reconcile).
func (s *Server) migratedContacts(ctx context.Context, owner string) (map[string]string, error) {
	out := map[string]string{}
	after := ""
	for {
		cs, next, err := s.st.Contacts().List(ctx, owner, after, maxPage)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if c.State == store.StatePendingIn || c.State == store.StatePendingOut || !s.closedKnown(ctx, c.ID) {
				continue
			}
			if st2, err := s.modern().followMigration(ctx, c.ID, ""); err == nil {
				out[c.ID] = st2.ID
			}
		}
		if next == "" {
			return out, nil
		}
		after = next
	}
}

// appendMigrate finishes a version 1 chain/append whose entry carries migrate (SPEC §6.8):
// st is the chain with the entry applied, before the head it followed. genesisRaw is the
// version 2 genesis the entry names, registered in the same transaction.
func (s *Server) appendMigrate(w http.ResponseWriter, r *http.Request, sess session, st *chain.State, before uint64, applied *chain.Applied, enc []byte, genesisRaw wire.Raw) {
	ctx := r.Context()
	for _, op := range applied.Entry.Ops {
		if op.Op != wire.OpMigrate && (op.Op != wire.OpSetRecovery || applied.Signer != chain.SignerRecovery) {
			writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "an entry with migrate carries nothing else, except the recovery key's set-recovery")
			return
		}
	}
	if genesisRaw == nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, `migrate needs the version 2 genesis it names, in "genesis": it's registered with the migration`)
		return
	}
	v2 := s.modern()
	sig2, err := v2.decodeSigned(genesisRaw)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "genesis: "+err.Error())
		return
	}
	st2, a2, err := v2.genesis(sig2)
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "version 2 genesis: "+err.Error())
		return
	}
	if !chain.Linked(st, st2) {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "the version 2 genesis and migrate have to name each other: migrate the hash of the genesis, and the genesis this identity in migrated-from")
		return
	}
	if chain.CheckClock(a2.Entry.TS, uint64(now()), true) != nil {
		s.writeClockSkew(w, int64(a2.Entry.TS), chain.MaxSkew)
		return
	}
	if st2.Home != s.cfg.Name {
		writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "the version 2 identity starts on this server: move it once it's registered")
		return
	}
	// The version 1 identity's handle comes along, wherever it's from. A new one has to be
	// one this server would register.
	if st2.Handle != st.Handle {
		if s.cfg.Handles == "" || !validHandleUnder(st2.Handle, s.cfg.Handles) {
			writeError(w, http.StatusBadRequest, wire.ErrCodeInvalidChain, "the handle must be the version 1 identity's, or <name>."+s.cfg.Handles)
			return
		}
		if reservedHandles[strings.TrimSuffix(st2.Handle, "."+s.cfg.Handles)] {
			writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "that name is reserved")
			return
		}
	}
	contacts, err := s.migratedContacts(ctx, sess.id)
	if err != nil {
		s.unavailableRead(w, "reading the contacts of a migrating identity", err)
		return
	}
	genc, _ := sig2.Encode()
	err = s.st.Chains().Migrate(ctx, store.Migration{From: sess.id, To: st2.ID, PrevSeq: before, Entry: enc, Genesis: genc, Handle: st2.Handle, Contacts: contacts})
	switch {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, wire.ErrCodeStaleHead, "")
		return
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "that version 2 identity is already registered")
		return
	case errors.Is(err, store.ErrHandleTaken):
		writeError(w, http.StatusConflict, wire.ErrCodeHandleTaken, "")
		return
	case err != nil:
		s.unavailableRead(w, "migrating an identity", err) // nothing was stored: the client retries
		return
	}
	s.log.Info("migrated to wire version 2", "id", sess.id, "to", st2.ID, "handle", st2.Handle)
	s.dropPush(ctx, sess.id) // the app registers its token again for the version 2 identity
	// A device-signed migrate hands the identity over: an alarm, like a move (SPEC §6.4.1).
	if lvl := chain.Alert(applied); lvl != chain.AlertNone {
		s.logged("sending a chain alert", s.notify(ctx, sess.id, map[string]any{"t": "chain-alert", "level": "alarm", "entry": wire.Raw(enc)}))
	}
	s.pushChain(ctx, sess.id) // contacts' servers learn the chain is closed
	s.tellMigrated(ctx, st2.ID)
	writeBody(w, http.StatusOK, map[string]any{"seq": st.Seq, "head": st.Head, "id": st2.ID})
}

// tellMigrated tells the local version 2 identities that list id2 as a contact that its
// chain changed: it took the place of the version 1 identity it migrated from.
func (s *Server) tellMigrated(ctx context.Context, id2 string) {
	v2 := s.modern()
	owners, err := v2.st.Contacts().Owners(ctx, id2)
	s.logged("listing who to tell about a migration", err)
	for _, o := range owners {
		v2.logged("telling a contact about a migration", v2.notify(ctx, o, map[string]any{"t": "chain-update", "id": id2}))
	}
}

// onMigrated runs on the version 1 Server when it learns that a remote version 1 identity's
// chain ended in migrate: local version 2 identities that list it list its version 2
// identity instead, once both links check out. Failures are only logged: listing contacts
// tries again (reconcile).
func (s *Server) onMigrated(ctx context.Context, st1 *chain.State) {
	st2, err := s.modern().followMigration(ctx, st1.ID, st1.Home)
	if err != nil {
		s.log.Info("a contact migrated, but its version 2 identity couldn't be checked yet", "id", st1.ID, "err", err)
		return
	}
	s.rewriteMigrated(ctx, st1.ID, st2.ID)
}

func (s *Server) rewriteMigrated(ctx context.Context, id1, id2 string) {
	owners, err := s.st.Contacts().RewriteMigrated(ctx, id1, id2)
	if err != nil {
		s.logged("rewriting contacts after a migration", err)
		return
	}
	v2 := s.modern()
	for _, o := range owners {
		v2.logged("telling a contact about a migration", v2.notify(ctx, o, map[string]any{"t": "chain-update", "id": id2}))
	}
}

// reconcile rewrites the entries of a version 2 identity's contact list that name version
// 1 identities we know have migrated, as far as we know without asking about the version 1
// chains again. It's what catches a migration whose version 2 identity couldn't be checked
// when we learned of it. Call it on the version 2 Server.
func (s *Server) reconcile(ctx context.Context, owner string, cs []store.Contact) bool {
	changed := false
	for _, c := range cs {
		if c.State == store.StatePendingIn || c.State == store.StatePendingOut || !s.legacy().closedKnown(ctx, c.ID) {
			continue
		}
		st2, err := s.followMigration(ctx, c.ID, "")
		if err != nil {
			continue
		}
		s.legacy().rewriteMigrated(ctx, c.ID, st2.ID)
		changed = true
	}
	return changed
}

// registerMigrated answers a version 2 registration whose genesis names a version 1
// identity (SPEC §6.8). The registration happens with the version 1 migrate (above), so
// this only confirms one that did: it never registers anything itself.
func (s *Server) registerMigrated(w http.ResponseWriter, r *http.Request, st2 *chain.State, genc []byte) {
	ctx := r.Context()
	st1, _, err := s.legacy().identity(ctx, st2.MigratedFrom)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the version 1 identity isn't registered on this server: migrate on its own homeserver")
		return
	case err != nil:
		s.unavailableRead(w, "reading a migrating identity's version 1 chain", err)
		return
	case st1.Home != s.cfg.Name:
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the version 1 identity moved away from this server: migrate on its own homeserver")
		return
	case chain.Linked(st1, st2):
		have, err := s.st.Chains().Entries(ctx, st2.ID, -1)
		if err != nil || len(have) == 0 || !bytes.Equal(have[0], genc) {
			s.unavailableRead(w, "reading a migrated identity's chain", errors.Join(err, errors.New("migrated without its genesis")))
			return
		}
		writeBody(w, http.StatusOK, map[string]any{"id": st2.ID})
	case st1.Closed():
		writeError(w, http.StatusConflict, wire.ErrCodeAlreadyExists, "the version 1 identity migrated to another version 2 identity")
	default:
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, `append migrate to the version 1 chain first, with this genesis in "genesis" (chain/append on the version 1 API): the version 2 identity is registered with it`)
	}
}

// allMigrated reports whether every recipient of a delivery but its sender is a version 1
// identity we know migrated (SPEC §6.8).
func (s *Server) allMigrated(ctx context.Context, from string, to []string) bool {
	if s.wv != wire.V1 {
		return false
	}
	n := 0
	for _, id := range to {
		if id == from {
			continue
		}
		if !s.closedKnown(ctx, id) {
			return false
		}
		n++
	}
	return n > 0
}

// whoMigrated narrows the recipients of a delivery that home refused with `migrated` to
// those whose chains, fetched again from there, end in migrate. Fetching them also
// updates our copies, so the next delivery is refused here. If none can be fetched, it
// keeps them all.
func (s *Server) whoMigrated(ctx context.Context, to []string, home string) []string {
	var out []string
	for _, id := range to {
		if st, _, err := s.fetchRemote(ctx, id, home, false); err == nil && st.Closed() {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return to
	}
	return out
}
