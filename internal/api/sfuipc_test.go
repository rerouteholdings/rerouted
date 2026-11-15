package api

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/sfuipc"
)

// withSFU makes the community servers tests start use an rerouted-sfu, on a unix socket,
// instead of an SFU of their own (TestVoiceInSFUProcess).
var withSFU bool

func testSFU(t testing.TB, cfg *config.Config) {
	t.Helper()
	if !withSFU {
		return
	}
	dir, err := os.MkdirTemp("", "sfu")
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
	go (&sfuipc.Server{UID: -1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Serve(l)
	cfg.SFU = sock
}

// The voice tests, with the SFU in rerouted-sfu: joins, offers both ways, ICE, casts,
// voice-state, and leaving, over its socket.
func TestVoiceInSFUProcess(t *testing.T) {
	withSFU = true
	t.Cleanup(func() { withSFU = false })
	for name, f := range map[string]func(*testing.T){
		"CommunityVoice": TestCommunityVoice,
	} {
		t.Run(name, f)
	}
}
