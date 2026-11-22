package sfu

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/pion/ice/v4"
)

// Link-local addresses are always left out, whatever filter the caller sets: binding the
// voice port on a container's fe80:: address can fail and stop the SFU.
func TestNoLinkLocal(t *testing.T) {
	all := noLinkLocal(nil)
	v4only := noLinkLocal(func(ip net.IP) bool { return ip.To4() != nil })
	for s, want := range map[string][2]bool{
		"203.0.113.7":  {true, true},
		"2001:db8::1":  {true, false},
		"fe80::1":      {false, false},
		"169.254.10.1": {false, false},
		"ff02::1":      {false, false},
		"127.0.0.1":    {true, true},
	} {
		ip := net.ParseIP(s)
		if all(ip) != want[0] || v4only(ip) != want[1] {
			t.Errorf("%s: %v %v, want %v", s, all(ip), v4only(ip), want)
		}
	}
}

// Binding the voice port while an address is still tentative fails with EADDRNOTAVAIL;
// that's retried, and anything else isn't.
func TestListenMuxRetriesTentativeAddress(t *testing.T) {
	defer func(f func(int, ...ice.UDPMuxFromPortOption) (*ice.MultiUDPMuxDefault, error), w time.Duration) {
		newMux, muxWait = f, w
	}(newMux, muxWait)
	muxWait = time.Millisecond
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	notReady := fmt.Errorf("listen udp [2001:db8::1]:50000: bind: %w", &net.OpError{Op: "listen", Err: syscall.EADDRNOTAVAIL})

	calls := 0
	newMux = func(int, ...ice.UDPMuxFromPortOption) (*ice.MultiUDPMuxDefault, error) {
		if calls++; calls < 3 {
			return nil, notReady
		}
		return &ice.MultiUDPMuxDefault{}, nil
	}
	if _, err := listenMux(50000, nil, log); err != nil || calls != 3 {
		t.Fatalf("after two tentative failures: %v, %d tries", err, calls)
	}

	calls = 0
	newMux = func(int, ...ice.UDPMuxFromPortOption) (*ice.MultiUDPMuxDefault, error) { calls++; return nil, notReady }
	if _, err := listenMux(50000, nil, log); err == nil || calls != muxTries {
		t.Fatalf("an address that never comes up: %v, %d tries", err, calls)
	}

	calls = 0
	inUse := errors.New("bind: address already in use")
	newMux = func(int, ...ice.UDPMuxFromPortOption) (*ice.MultiUDPMuxDefault, error) { calls++; return nil, inUse }
	if _, err := listenMux(50000, nil, log); !errors.Is(err, inUse) || calls != 1 {
		t.Fatalf("another error: %v, %d tries", err, calls)
	}
}
