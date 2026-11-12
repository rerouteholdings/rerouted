package api

import (
	"context"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- presence (SPEC §13.2, spec/api/client-stage5.md) ----

// presenceOfflineAfter is how long after an identity's last stream closes the server marks
// it offline on its behalf.
const presenceOfflineAfter = 5 * time.Minute

var presenceStates = map[string]bool{"available": true, "online": true, "away": true, "busy": true, "offline": true}

type presence struct {
	State  string
	Status string
	PV     int64
	TS     int64
	auto   bool // set by the server (connect or disconnect), not by the user
}

// presenceBook holds presence in memory: it's only worth knowing while it's current.
type presenceBook struct {
	mu     sync.Mutex
	local  map[string]presence // this server's users
	remote map[string]presence // contacts on other servers, as their servers last told us
	timers map[string]*time.Timer
}

func (p *presenceBook) get(id string) (presence, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.local[id]; ok {
		return v, true
	}
	v, ok := p.remote[id]
	return v, ok
}

// POST presence.
func (s *Server) setPresence(w http.ResponseWriter, r *http.Request, sess session) {
	var req struct {
		State  string `json:"state"`
		Status string `json:"status,omitempty"`
	}
	if !readBody(w, r, &req) {
		return
	}
	if !presenceStates[req.State] || utf8.RuneCountInString(req.Status) > 128 {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "state must be available, online, away, busy, or offline; status at most 128 characters")
		return
	}
	s.updatePresence(r.Context(), sess.id, presence{State: req.State, Status: req.Status})
	w.WriteHeader(http.StatusNoContent)
}

// updatePresence records a local user's presence and sends it to their mutual contacts.
func (s *Server) updatePresence(ctx context.Context, id string, p presence) {
	p.TS = now()
	if p.State == "offline" {
		p.Status = "" // appearing offline shares nothing more (SPEC §13.2)
	}
	s.presence.mu.Lock()
	s.presence.local[id] = p
	s.presence.mu.Unlock()
	s.broadcastPresence(ctx, id)
}

// presenceConnected is called when one of id's devices opens a stream.
func (s *Server) presenceConnected(ctx context.Context, id string) {
	s.presence.mu.Lock()
	if t := s.presence.timers[id]; t != nil {
		t.Stop()
		delete(s.presence.timers, id)
	}
	cur, ok := s.presence.local[id]
	s.presence.mu.Unlock()
	// Coming online, unless the user chose a state themselves (including appearing offline).
	if !ok || (cur.auto && cur.State == "offline") {
		s.updatePresence(ctx, id, presence{State: "online", auto: true})
	}
}

// presenceDisconnected is called when id's last stream closes.
func (s *Server) presenceDisconnected(id string) {
	s.presence.mu.Lock()
	defer s.presence.mu.Unlock()
	if t := s.presence.timers[id]; t != nil {
		t.Stop()
	}
	s.presence.timers[id] = time.AfterFunc(presenceOfflineAfter, func() {
		s.presence.mu.Lock()
		delete(s.presence.timers, id)
		cur := s.presence.local[id]
		s.presence.mu.Unlock()
		if s.streams.connected(id) || cur.State == "offline" {
			return
		}
		s.updatePresence(context.Background(), id, presence{State: "offline", auto: true})
	})
}

// dropStaleProfile forgets a cached remote profile older than version pv, so the next
// GET profile fetches the new one: contacts' clients fetch when presence says pv went up
// (spec/api/client-stage5.md).
func (s *Server) dropStaleProfile(id string, pv int64) {
	s.profiles.mu.Lock()
	defer s.profiles.mu.Unlock()
	c, ok := s.profiles.m[id]
	if !ok {
		return
	}
	if sig, err := wire.DecodeSigned(c.signed); err == nil {
		var body struct {
			V int64 `json:"v"`
		}
		if sig.Open(&body) == nil && body.V >= pv {
			return
		}
	}
	delete(s.profiles.m, id)
}

func (s *Server) profileVersion(ctx context.Context, id string) int64 {
	b, err := s.st.Profiles().Get(ctx, id)
	if err != nil {
		return 0
	}
	sig, err := wire.DecodeSigned(b)
	if err != nil {
		return 0
	}
	var body struct {
		V int64 `json:"v"`
	}
	sig.Open(&body)
	return body.V
}

func presenceFrame(id string, p presence) map[string]any {
	f := map[string]any{"t": "presence", "id": id, "state": p.State, "pv": p.PV, "ts": p.TS}
	if p.Status != "" {
		f["status"] = p.Status
	}
	return f
}

// mutual reports whether local user a has b as a full contact, and (if b is local) b has a.
func (s *Server) mutual(ctx context.Context, a, b string) bool {
	if c, err := s.st.Contacts().Get(ctx, a, b); err != nil || c.State != store.StateContact {
		return false
	}
	if s.isLocal(ctx, b) {
		c, err := s.st.Contacts().Get(ctx, b, a)
		return err == nil && c.State == store.StateContact
	}
	return true // b's own server checks the other direction
}

// contactsOf lists id's full contacts.
func (s *Server) contactsOf(ctx context.Context, id string) []string {
	var out []string
	after := ""
	for {
		cs, next, err := s.st.Contacts().List(ctx, id, after, 500)
		if err != nil {
			return out
		}
		for _, c := range cs {
			if c.State == store.StateContact {
				out = append(out, c.ID)
			}
		}
		if next == "" {
			return out
		}
		after = next
	}
}

// broadcastPresence sends id's presence to its mutual contacts: on the stream for local
// ones, and with one S2S presence call per other server, right away (SPEC §13.2 allows
// that for a small server).
func (s *Server) broadcastPresence(ctx context.Context, id string) {
	p, ok := s.presence.get(id)
	if !ok {
		return
	}
	p.PV = s.profileVersion(ctx, id)
	frame := presenceFrame(id, p)
	byHome := map[string][]string{}
	for _, c := range s.contactsOf(ctx, id) {
		if !s.mutual(ctx, id, c) {
			continue
		}
		if s.isLocal(ctx, c) {
			s.push(c, frame, -1)
		} else if st, _, err := s.lookup(ctx, c, ""); err == nil {
			byHome[st.Home] = append(byHome[st.Home], c)
		}
	}
	if s.fed == nil {
		return
	}
	for home, to := range byHome {
		u := map[string]any{"id": id, "state": p.State, "pv": p.PV, "ts": p.TS, "to": to}
		if p.Status != "" {
			u["status"] = p.Status
		}
		body, err := wire.Marshal(map[string]any{"updates": []any{u}})
		if err != nil {
			continue
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s.fed.Call(ctx, home, "presence", body) // presence is never retried
		}()
	}
}

// S2S presence.
func (s *Server) s2sPresence(w http.ResponseWriter, r *http.Request, from string, body wire.Raw) {
	var req struct {
		Updates []struct {
			ID     string   `json:"id"`
			State  string   `json:"state"`
			Status string   `json:"status,omitempty"`
			PV     int64    `json:"pv"`
			TS     int64    `json:"ts"`
			To     []string `json:"to"`
		} `json:"updates"`
	}
	if wire.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, wire.ErrCodeBadRequest, "")
		return
	}
	ctx := r.Context()
	for _, u := range req.Updates {
		if !presenceStates[u.State] || utf8.RuneCountInString(u.Status) > 128 || !s.remoteUser(ctx, u.ID, from) {
			continue
		}
		p := presence{State: u.State, Status: u.Status, PV: u.PV, TS: u.TS}
		s.presence.mu.Lock()
		s.presence.remote[u.ID] = p
		s.presence.mu.Unlock()
		s.dropStaleProfile(u.ID, u.PV)
		frame := presenceFrame(u.ID, p)
		for _, to := range u.To {
			if s.isLocal(ctx, to) && s.mutual(ctx, to, u.ID) {
				s.push(to, frame, -1)
			}
		}
	}
	writeBody(w, http.StatusAccepted, map[string]any{}) // drops are silent (SPEC §10.3)
}

// presenceSnapshot sends a new stream the presence of every mutual contact it knows.
func (s *Server) presenceSnapshot(ctx context.Context, st *stream) {
	for _, c := range s.contactsOf(ctx, st.id) {
		if !s.mutual(ctx, st.id, c) {
			continue
		}
		p, ok := s.presence.get(c)
		if !ok {
			continue
		}
		if s.isLocal(ctx, c) {
			p.PV = s.profileVersion(ctx, c)
		}
		s.sendFrame(st, presenceFrame(c, p))
	}
}
