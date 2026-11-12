package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- public profiles (SPEC §13.1) ----

// profileTTL is how long a fetched remote profile is reused.
const profileTTL = time.Hour

type profileBody struct {
	ID     string   `json:"id"`
	V      int64    `json:"v"`
	TS     int64    `json:"ts"`
	Name   string   `json:"name,omitempty"`
	Bio    string   `json:"bio,omitempty"`
	Links  []string `json:"links,omitempty"`
	Avatar *struct {
		Server string     `json:"server"`
		ID     wire.Bytes `json:"id"`
		SHA256 wire.Bytes `json:"sha256"`
		Size   int64      `json:"size"`
		Mime   string     `json:"mime"`
	} `json:"avatar,omitempty"`
	Invite string `json:"invite,omitempty"`
}

// remoteProfiles caches profiles fetched from other servers.
type remoteProfiles struct {
	mu sync.Mutex
	m  map[string]cachedProfile
}

type cachedProfile struct {
	signed  []byte
	fetched time.Time
}

func (s *Server) postProfile(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		Profile wire.Raw `json:"profile"`
	}
	if !readBody(w, r, &req) {
		return
	}
	sig, ok := decodeSignedField(w, req.Profile)
	if !ok {
		return
	}
	key, err := sig.VerifySelf("profile")
	if err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadSignature, "")
		return
	}
	var p profileBody
	if err := sig.Open(&p); err != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	if p.ID != sess.id {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "a profile is published by its own identity")
		return
	}
	if me, _, err := s.identity(ctx, sess.id); err != nil || !me.HasDevice(key) {
		writeError(w, http.StatusForbidden, wire.ErrCodeNotAllowed, "the signer isn't a current device")
		return
	}
	if msg := s.checkProfile(ctx, p); msg != "" {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, msg)
		return
	}
	enc, _ := sig.Encode()
	if err := s.st.Profiles().Put(ctx, sess.id, p.V, enc); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, wire.ErrCodeStaleVersion, "v must be higher than the published profile's")
		return
	} else if err != nil {
		writeError(w, http.StatusServiceUnavailable, wire.ErrCodeUnavailable, "")
		return
	}
	// Contacts learn the new version (pv) from presence (SPEC §13.1).
	if _, ok := s.presence.get(sess.id); ok {
		s.broadcastPresence(ctx, sess.id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// checkProfile applies the limits of SPEC §13.1. It returns what's wrong, or "".
func (s *Server) checkProfile(ctx context.Context, p profileBody) string {
	switch {
	case p.V < 1:
		return "v starts at 1"
	case utf8.RuneCountInString(p.Name) > 64:
		return "name is at most 64 characters"
	case utf8.RuneCountInString(p.Bio) > 500:
		return "bio is at most 500 characters"
	case len(p.Links) > 5:
		return "at most 5 links"
	}
	for _, l := range p.Links {
		if !strings.HasPrefix(l, "https://") || len(l) > 2048 {
			return "links are https URLs"
		}
	}
	if a := p.Avatar; a != nil {
		m, err := s.st.Media().Get(ctx, a.ID)
		if a.Server != s.cfg.Name || err != nil || !m.Public || m.Owner != p.ID || m.Removed ||
			!bytes.Equal(m.SHA256, a.SHA256) || m.Size != a.Size || m.Mime != a.Mime {
			return "avatar must be a picture this identity uploaded here with media/upload-public"
		}
	}
	if p.Invite != "" {
		invs, _ := s.st.Invites().List(ctx, p.ID, now()) // an error finds nothing: the profile is refused
		h := s.inviteHash(p.Invite)
		found := false
		for _, inv := range invs {
			found = found || (inv.Public && bytes.Equal(inv.Hash, h))
		}
		if !found {
			return "invite must be one of this identity's live public invite codes"
		}
	}
	return ""
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	ctx := r.Context()
	if s.isLocal(ctx, id) {
		b, err := s.st.Profiles().Get(ctx, id)
		if err != nil {
			writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
			return
		}
		writeBody(w, http.StatusOK, map[string]any{"profile": wire.Raw(b)})
		return
	}
	s.profiles.mu.Lock()
	c, ok := s.profiles.m[id]
	s.profiles.mu.Unlock()
	if ok && time.Since(c.fetched) < profileTTL {
		writeBody(w, http.StatusOK, map[string]any{"profile": wire.Raw(c.signed)})
		return
	}
	them, _, err := s.lookup(ctx, id, r.URL.Query().Get("home"))
	if err != nil || s.fed == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	body, _ := wire.Marshal(map[string]any{"id": id})
	b, err := s.fed.Call(ctx, them.Home, "profile/fetch", body)
	var res struct {
		Profile wire.Raw `json:"profile"`
	}
	if err != nil || wire.Unmarshal(b, &res) != nil || res.Profile == nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	// The client verifies it against the chain (SPEC §13.1); the server doesn't vouch for it.
	s.profiles.mu.Lock()
	s.profiles.m[id] = cachedProfile{signed: res.Profile, fetched: time.Now()}
	s.profiles.mu.Unlock()
	writeBody(w, http.StatusOK, map[string]any{"profile": res.Profile})
}

func (s *Server) s2sProfileFetch(w http.ResponseWriter, r *http.Request, _ string, body wire.Raw) {
	var req struct {
		ID string `json:"id"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	b, err := s.st.Profiles().Get(r.Context(), req.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, wire.ErrCodeNotFound, "")
		return
	}
	writeBody(w, http.StatusOK, map[string]any{"profile": wire.Raw(b)})
}
