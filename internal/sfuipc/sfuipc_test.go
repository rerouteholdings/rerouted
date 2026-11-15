package sfuipc

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/sfu"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// listen makes a unix socket with a short path: a socket's is limited to about 100 bytes.
func listen(t *testing.T) (string, net.Listener) {
	t.Helper()
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
	return sock, l
}

func serve(t *testing.T, uid int) string {
	sock, l := listen(t)
	go (&Server{UID: uid, Log: discard()}).Serve(l)
	return sock
}

// Every error a room returns comes back as itself.
func TestErrorsCross(t *testing.T) {
	for _, e := range []error{sfu.ErrVisitInUse, sfu.ErrFull, sfu.ErrBadSDP, sfu.ErrNotIn, sfu.ErrCastLimit, sfu.ErrGlare, sfu.ErrNotAllowed} {
		if got := codeErr(errCode(e)); got != e {
			t.Errorf("%v came back as %v", e, got)
		}
	}
	if got := codeErr(errCode(errors.New("boom"))); got == nil || got.Error() != "rerouted-sfu: boom" {
		t.Errorf("another error: %v", got)
	}
	c, err := Dial(serve(t, -1), sfu.Config{Loopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := c.Room("c|1")
	if _, err := r.Join(sfu.Member{Key: "k", Visit: 1}, `{"type":"offer","sdp":"nonsense"}`, 5, true, nil); !errors.Is(err, sfu.ErrBadSDP) {
		t.Fatalf("a bad offer: %v", err)
	}
	if err := r.NewVisit("nobody", 2); !errors.Is(err, sfu.ErrNotIn) {
		t.Fatalf("not in the room: %v", err)
	}
	if r.Len() != 0 || r.Has("k") || r.State() == nil {
		t.Fatal("an empty room")
	}
}

// When rerouted-sfu goes away, so does everyone in its rooms: OnGone hears of each. The
// next request connects again, to a new one.
func TestSFUProcessGone(t *testing.T) {
	sock, l := listen(t)
	srv := &Server{UID: -1, Log: discard()}
	go srv.Serve(l)
	var mu sync.Mutex
	var gone []string
	c, err := Dial(sock, sfu.Config{Loopback: true, OnGone: func(room, key string) {
		mu.Lock()
		gone = append(gone, room+" "+key)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Two participants, as a join records them.
	c.mu.Lock()
	conn := c.conn
	c.signals[[2]string{"c|1", "kat"}] = signalOn{func(map[string]any) {}, conn}
	c.signals[[2]string{"c|2", "ravi"}] = signalOn{func(map[string]any) {}, conn}
	c.mu.Unlock()
	l.Close()
	conn.Close() // as if rerouted-sfu died
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(gone)
		mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gone: %v", gone)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := c.Room("c|1"); r.Len() != 0 || r.Has("kat") {
		t.Fatal("answered with rerouted-sfu down")
	}
	// A new rerouted-sfu on the same socket.
	os.Remove(sock)
	l2, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	go srv.Serve(l2)
	if err := c.Room("c|1").NewVisit("kat", 1); !errors.Is(err, sfu.ErrNotIn) {
		t.Fatalf("after reconnecting: %v", err)
	}
}

// rerouted-sfu says hello once per connection, and nothing before it.
func TestHello(t *testing.T) {
	conn, err := net.Dial("unix", serve(t, -1))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ask := func(r request) message {
		if err := ipc.Write(conn, r, maxMessage); err != nil {
			t.Fatal(err)
		}
		var m message
		if err := ipc.Read(conn, &m, maxMessage); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := ask(request{ID: 1, Op: "len", Room: "c|1"}); m.Err == "" {
		t.Fatal("answered before hello")
	}
	if m := ask(request{ID: 2, Op: "hello", Loopback: true}); m.Err != "" || m.ID != 2 {
		t.Fatalf("hello: %+v", m)
	}
	if m := ask(request{ID: 3, Op: "hello"}); m.Err == "" {
		t.Fatal("a second hello")
	}
	if m := ask(request{ID: 4, Op: "nope"}); m.Err == "" {
		t.Fatal("an unknown op")
	}
}

// Only the allowed user may connect.
func TestPeerUID(t *testing.T) {
	if !ipc.PeerCheckSupported {
		t.Skip("no SO_PEERCRED here")
	}
	if _, err := Dial(serve(t, os.Getuid()+1), sfu.Config{}); err == nil {
		t.Fatal("another user's connection was served")
	}
	c, err := Dial(serve(t, os.Getuid()), sfu.Config{})
	if err != nil {
		t.Fatalf("the allowed user: %v", err)
	}
	c.Close()
}
