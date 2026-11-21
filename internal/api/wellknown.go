package api

import (
	"net/http"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// The server document (SPEC §5.1). It's the only fixed path in the protocol:
// clients and servers find both APIs from its "apis" list (SPEC §8.1).
//
// rerouted lists wire versions 1 and 2, each with its own bases, while its users migrate
// (SPEC §5.1, §6.8). keys holds both versions' server keys: the version 1 Ed25519 key and
// the version 2 composite key, under different key IDs. A reader picks the key a signature
// names by kid, and each version's verifier takes only its own kind of key (32 or 1,984
// bytes), so a version 1 reader that looks keys up by kid isn't confused by the other.
//
// Each version's list holds its current key, the key that signs next once one has been made,
// and the keys rotation replaced, until each one's exp (serverkey).
type serverKeyDoc = serverkey.Published

type apiBase struct {
	V         int    `json:"v"`
	Client    string `json:"client,omitempty"`
	S2S       string `json:"s2s"`
	Community string `json:"community,omitempty"` // with role "community" (SPEC §16.1)
}

type serverDoc struct {
	Name         string         `json:"name"`
	Roles        []string       `json:"roles"`
	APIs         []apiBase      `json:"apis"`
	Keys         []serverKeyDoc `json:"keys"`
	Handles      string         `json:"handles,omitempty"`
	Registration string         `json:"registration,omitempty"`
	Invite       string         `json:"invite,omitempty"`
}

func (s *Server) serverDoc(w http.ResponseWriter, r *http.Request) {
	doc := serverDoc{
		Name:  s.cfg.Name,
		Roles: []string{"home"},
		APIs: []apiBase{
			{V: wire.V1, Client: s.cfg.ClientBase(), S2S: s.cfg.S2SBase()},
			{V: wire.V2, Client: s.cfg.ClientBaseV2(), S2S: s.cfg.S2SBaseV2()},
		},
		Keys:         append(s.keys.V1.Published(time.Now()), s.keys.V2.Published(time.Now())...),
		Handles:      s.cfg.Handles,
		Registration: s.cfg.Now().Registration,
	}
	// This name can also be a community server (SPEC §16.1), with the same keys.
	if c := s.comm.byName[s.cfg.Name]; c != nil {
		doc.Roles = append(doc.Roles, "community")
		doc.APIs[1].Community = s.cfg.CommunityBase(c.conf)
	}
	if reg := s.cfg.Now(); reg.Registration == "invite" && reg.RegistrationPublic {
		doc.Invite = reg.RegistrationCode // open signups are a public invite (SPEC §8.2)
	}
	w.Header().Set("Cache-Control", "max-age=3600")
	writeBody(w, http.StatusOK, doc)
}
