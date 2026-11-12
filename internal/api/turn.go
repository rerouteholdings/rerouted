package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ---- call relays (SPEC §15.1) ----

// turnTTL is how long relay credentials last.
const turnTTL = 24 * 3600

func (s *Server) getTurn(w http.ResponseWriter, r *http.Request, sess session) {
	if len(s.cfg.TurnURLs) == 0 {
		writeError(w, http.StatusNotImplemented, wire.ErrCodeNotImplemented, "this homeserver runs no call relay")
		return
	}
	// The TURN REST API format: username "expiry:user", credential HMAC-SHA1 under the shared secret.
	user := fmt.Sprintf("%d:%s", now()+turnTTL, sess.id)
	m := hmac.New(sha1.New, []byte(s.cfg.TurnSecret))
	m.Write([]byte(user))
	writeBody(w, http.StatusOK, map[string]any{
		"urls": s.cfg.TurnURLs, "username": user, "credential": base64.StdEncoding.EncodeToString(m.Sum(nil)), "ttl": turnTTL,
	})
}
