package sfu_test

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/sfu"
	"github.com/rerouteholdings/rerouted/internal/sfuipc"
)

// The SFU's tests again, with the SFU in an rerouted-sfu on a unix socket: media both ways,
// offers from the SFU and the devices, ICE, casts, glare, visits, a vanished device, one
// UDP port, and public addresses, each through internal/sfuipc.
func TestThroughSFUProcess(t *testing.T) {
	sfu.NewVoice = func(t *testing.T, cfg sfu.Config) sfu.Voice {
		// REROUTED_SFU_TEST_SOCKET: a running rerouted-sfu's socket, to test it as
		// installed, run as the user it lets in.
		sock := os.Getenv("REROUTED_SFU_TEST_SOCKET")
		if sock != "" {
			c, err := sfuipc.Dial(sock, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			return c
		}
		dir, err := os.MkdirTemp("", "sfu")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		sock = filepath.Join(dir, "s")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		log := cfg.Log
		if log == nil {
			log = slog.New(slog.NewTextHandler(io.Discard, nil))
		}
		go (&sfuipc.Server{UID: -1, Log: log, Filter: cfg.IPFilter}).Serve(l)
		c, err := sfuipc.Dial(sock, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	t.Cleanup(func() { sfu.NewVoice = nil })
	for name, f := range map[string]func(*testing.T){
		"ForwardBothWays":         sfu.TestForwardBothWays,
		"VoiceGated":              sfu.TestVoiceGated,
		"CastLimitAndGating":      sfu.TestCastLimitAndGating,
		"VisitsAndMax":            sfu.TestVisitsAndMax,
		"LeaveFreesSections":      sfu.TestLeaveFreesSections,
		"KeyframeRequestsForward": sfu.TestKeyframeRequestsForwarded,
		"Glare":                   sfu.TestGlare,
		"OneUDPPort":              sfu.TestOneUDPPort,
		"GoneAndClose":            sfu.TestGoneAndClose,
		"PublicIPs":               sfu.TestPublicIPs,
	} {
		t.Run(name, f)
	}
}
