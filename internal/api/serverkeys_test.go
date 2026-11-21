package api

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// After a rotation, the server document lists the new key and the one it replaced, and
// the server signs with the new one, which other servers accept (SPEC §5.1).
func TestServerKeyRotation(t *testing.T) {
	a, b, sa, _ := twoServers(t)
	old := sa.key().V2.KID
	if err := sa.keys.V2.Rotate(time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	if sa.key().V2.KID == old || sa.v2.key().V2.KID != sa.key().V2.KID {
		t.Fatal("not signing with the new key")
	}
	resp, err := http.Get(a.URL + "/.well-known/tieroute/server")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var doc serverDoc
	if err := wire.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, k := range doc.Keys {
		listed[k.KID] = true
	}
	if len(doc.Keys) != 3 || !listed[old] || !listed[sa.key().V2.KID] || !listed[sa.key().KID] {
		t.Fatalf("published keys: %+v", doc.Keys)
	}
	// S2S requests signed with the new key work.
	kat, ravi := newV2User(t, a, "kat", "a.test"), newV2User(t, b, "ravi", "b.test")
	contacts2(t, kat, ravi)
}
