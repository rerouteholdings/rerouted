package api

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/egress"
)

// withEgress makes the servers tests start connect out through an rerouted-egress, on a
// unix socket (TestThroughEgress).
var withEgress bool

// testEgress gives cfg an rerouted-egress whose policy allows loopback for dev mode's
// peers, and exactly REROUTED_TLS_ASK_ALSO's instances.
func testEgress(t testing.TB, cfg *config.Config) {
	t.Helper()
	if !withEgress {
		return
	}
	p := egress.Policy{Local: egress.LocalFrom(cfg.TLSAskAlso)}
	if cfg.Dev {
		p.Allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	}
	dir, err := os.MkdirTemp("", "eg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&egress.Server{Policy: p, UID: -1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Serve(l)
	cfg.Egress = sock
}

// Federation, and the TLS ask of other local instances, with every connection out made by
// rerouted-egress.
func TestThroughEgress(t *testing.T) {
	withEgress = true
	t.Cleanup(func() { withEgress = false })
	for name, f := range map[string]func(*testing.T){
		"FederatedFlow":         TestFederatedFlow,
		"MoveReservationIssued": TestMoveReservationIssued,
		"V2HubFederated":        TestV2HubFederated,
		"TLSAskAlso":            TestTLSAskAlso,
	} {
		t.Run(name, f)
	}
}
