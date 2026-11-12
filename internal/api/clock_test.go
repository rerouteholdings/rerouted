package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// SPEC §8.4: the homeserver is the clock. auth/challenge gives its time, and a request
// dated too far off is refused with clock-skew, saying by how much, with the server's time.
func TestClockSkewSaysHowFar(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	pub := []byte(kat.dev.Public().(ed25519.PublicKey))

	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
		Now   int64      `json:"now"`
	}
	if c := call(t, ts, "POST", "auth/challenge", "", map[string]any{"id": kat.id, "key": pub}, &ch); c != 200 {
		t.Fatalf("challenge: %d", c)
	}
	if d := ch.Now - time.Now().Unix(); d < -2 || d > 2 {
		t.Fatalf("challenge now is %d s off", d)
	}

	// Signed by a device whose clock is 20 minutes slow.
	auth := signed(t, "auth", map[string]any{"id": kat.id, "nonce": ch.Nonce, "server": "chat.test", "ts": time.Now().Unix() - 1200}, kat.dev)
	var e wire.Error
	if c := call(t, ts, "POST", "auth/session", "", map[string]any{"auth": auth}, &e); c != 400 || e.Code != wire.ErrCodeClockSkew {
		t.Fatalf("a slow clock: %d %q", c, e.Code)
	}
	if d := e.Now - time.Now().Unix(); d < -2 || d > 2 {
		t.Fatalf("the refusal's now is %d s off", d)
	}
	if !strings.Contains(e.Msg, "20m0s behind") {
		t.Fatalf("the refusal doesn't say how far: %q", e.Msg)
	}

	// A chain entry from a clock that's 15 minutes fast.
	entries := kat.chainOf(ts)
	prev := sha256.Sum256(entries[len(entries)-1])
	entry := signed(t, "chain-entry", map[string]any{
		"id": kat.id, "seq": len(entries), "prev": prev[:], "ts": time.Now().Unix() + 900,
		"ops": []any{map[string]any{"op": "set-handle", "handle": "kat2.chat.test"}},
	}, kat.dev)
	e = wire.Error{}
	if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": entry}, &e); c != 400 || e.Code != wire.ErrCodeClockSkew || !strings.Contains(e.Msg, "15m0s ahead of") || e.Now == 0 {
		t.Fatalf("a fast clock: %d %+v", c, e)
	}
}
