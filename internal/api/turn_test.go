package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
)

// SPEC §15.1: relay credentials in the TURN REST format, or 501 without a relay.
func TestTurn(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	if c := call(t, ts, "GET", "turn", kat.token, nil, nil); c != 501 {
		t.Fatalf("no relay: %d, want 501", c)
	}
	secret := "a shared secret for coturn"
	ts = testServerCfg(t, newStore(t), func(c *config.Config) {
		c.TurnURLs, c.TurnSecret = []string{"turn:turn.chat.test:3478"}, secret
	})
	kat = newUser(t, ts, "kat")
	var res struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	}
	if c := call(t, ts, "GET", "turn", kat.token, nil, &res); c != 200 || len(res.URLs) != 1 {
		t.Fatalf("turn: %d %+v", c, res)
	}
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(res.Username))
	if res.Credential != base64.StdEncoding.EncodeToString(m.Sum(nil)) || !strings.HasSuffix(res.Username, ":"+kat.id) {
		t.Fatalf("credentials don't verify: %+v", res)
	}
}
