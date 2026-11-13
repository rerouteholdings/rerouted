package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Remembered chains: a caller applying entries to the state it got doesn't change what
// the next caller gets, and a chain that changed is validated again.
func TestValidChainCache(t *testing.T) {
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub)
	sign := func(body any) []byte {
		s, err := wire.Sign("chain-entry", body, dev)
		if err != nil {
			t.Fatal(err)
		}
		enc, _ := s.Encode()
		return enc
	}
	g := sign(map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey)), "name": "laptop"},
		map[string]any{"op": "set-home", "home": "chat.test"},
		map[string]any{"op": "set-handle", "handle": "kat.chat.test"},
		map[string]any{"op": "set-recovery", "next": commit[:]},
	}})
	st, err := decodeChain([][]byte{g})
	if err != nil {
		t.Fatal(err)
	}
	prev := sha256.Sum256(g)
	k, _, _ := ed25519.GenerateKey(rand.Reader)
	next := sign(map[string]any{"id": st.ID, "seq": 1, "prev": prev[:], "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(k), "name": "phone"},
	}})
	sig, _ := wire.DecodeSigned(next)
	if _, err := st.Apply(sig); err != nil {
		t.Fatal(err)
	}
	again, err := decodeChain([][]byte{g})
	if err != nil || again.Seq != 0 || len(again.Devices) != 1 {
		t.Fatalf("the cached state changed under its caller: %+v %v", again, err)
	}
	two, err := decodeChain([][]byte{g, next})
	if err != nil || two.Seq != 1 || len(two.Devices) != 2 {
		t.Fatalf("an extended chain: %+v %v", two, err)
	}
	bad := append([]byte(nil), next...)
	bad[len(bad)-3] ^= 1
	if _, err := decodeChain([][]byte{g, bad}); err == nil {
		t.Fatal("a tampered entry after a cached prefix validated")
	}
}
