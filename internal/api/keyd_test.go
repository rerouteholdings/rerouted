package api

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/keyd"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
)

// withKeyd makes the servers tests start sign through rerouted-keyd instead of holding
// their keys (TestKeyd).
var withKeyd bool

// testKey is a server's keys, in dir: held by this process, or, with withKeyd, by an
// rerouted-keyd serving them on a unix socket.
func testKey(t testing.TB, dir string, cfg *config.Config) serverkey.Key {
	t.Helper()
	if !withKeyd {
		key, err := serverkey.LoadOrCreate(dir)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	var cms []string
	for _, c := range cfg.Communities {
		cms = append(cms, c.Name)
	}
	ks, err := keyd.LoadDir(dir, cfg.Name, cms)
	if err != nil {
		t.Fatal(err)
	}
	// A short path: a unix socket's is limited to about 100 bytes.
	sockDir, err := os.MkdirTemp("", "kd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&keyd.Server{Keys: ks, UID: -1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Serve(l)
	key, err := keyd.Load(sock, cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if key.Priv != nil || key.V2.Priv != nil {
		t.Fatal("the keys are in this process")
	}
	return key
}

// The flows that sign with a server key, with the keys in rerouted-keyd: S2S requests,
// commit receipts as a hub (both wire versions), move reservations, and a community's.
// Each signature goes through rerouted-keyd's checks, and verifies.
func TestKeyd(t *testing.T) {
	withKeyd = true
	t.Cleanup(func() { withKeyd = false })
	for name, f := range map[string]func(*testing.T){
		"FederatedFlow":         TestFederatedFlow,
		"MoveReservationIssued": TestMoveReservationIssued,
		"V2HubLocal":            TestV2HubLocal,
		"V2HubFederated":        TestV2HubFederated,
		"CommunityServerDocs":   TestCommunityServerDocs,
		"CommunityMove":         TestCommunityMove,
		"CommunityOnlyName":     TestCommunityOnlyName,
	} {
		t.Run(name, f)
	}
}
