package api

import (
	"net/http"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// The server document (SPEC §5.1). It's the only fixed path in the protocol:
// clients and servers find both APIs from its "apis" list (SPEC §8.1).
type serverKeyDoc struct {
	KID string     `json:"kid"`
	Pub wire.Bytes `json:"pub"`
	NBF int64      `json:"nbf"`
	EXP int64      `json:"exp"`
}

type apiBase struct {
	V      uint   `json:"v"`
	Client string `json:"client,omitempty"`
	S2S    string `json:"s2s"`
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
		APIs:  []apiBase{{V: 1, Client: s.cfg.ClientBase(), S2S: s.cfg.S2SBase()}},
		Keys: []serverKeyDoc{{
			KID: s.key.KID,
			Pub: wire.Bytes(s.key.Public()),
			NBF: s.key.Created.Unix(),
			EXP: s.key.Created.Add(serverkey.Lifetime).Unix(),
		}},
		Handles:      s.cfg.Handles,
		Registration: s.cfg.Registration,
	}
	if s.cfg.Registration == "invite" && s.cfg.RegistrationPublic {
		doc.Invite = s.cfg.RegistrationCode // open signups are a public invite (SPEC §8.2)
	}
	w.Header().Set("Cache-Control", "max-age=3600")
	writeBody(w, http.StatusOK, doc)
}
