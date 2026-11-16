package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
	"github.com/rerouteholdings/rerouted/internal/ws"
)

// The address a rate limit counts is the one the local proxy saw connect, never one the
// caller wrote into X-Forwarded-For itself.
func TestClientIP(t *testing.T) {
	for _, c := range []struct {
		remote string
		xff    []string
		want   string
	}{
		{"127.0.0.1:5000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"127.0.0.1:5000", []string{"10.0.0.1, 203.0.113.9"}, "203.0.113.9"},                 // the caller's own entry first
		{"127.0.0.1:5000", []string{"10.0.0.1", "198.51.100.2, 203.0.113.9"}, "203.0.113.9"}, // or its own header line
		{"[::1]:5000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"127.0.0.1:5000", []string{"203.0.113.9, not-an-address"}, "127.0.0.1"},
		{"127.0.0.1:5000", nil, "127.0.0.1"},
		{"198.51.100.7:5000", []string{"203.0.113.9"}, "198.51.100.7"}, // no local proxy: the header is anyone's
	} {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("%s, %q: %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

// The registration code can't be guessed at any rate: wrong codes are counted per address.
func TestWrongRegistrationCodesLimited(t *testing.T) {
	ts := testServer(t)
	register := func(addr, code string) int {
		b, _ := wire.Marshal(map[string]any{"invite": code})
		req, _ := http.NewRequest("POST", ts.URL+"/.well-known/tieroute/v1/client/register", bytes.NewReader(b))
		req.Header.Set("Content-Type", wire.MediaType)
		req.Header.Set("X-Forwarded-For", addr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < wrongCodesPerAddress; i++ {
		if c := register("203.0.113.9", fmt.Sprintf("guess-%d", i)); c != 403 {
			t.Fatalf("wrong code %d: %d", i, c)
		}
	}
	if c := register("203.0.113.9", "one-more-guess"); c != 429 {
		t.Fatalf("a wrong code past the limit: %d", c)
	}
	if c := register("203.0.113.9", testRegCode); c != 429 {
		t.Fatalf("the right code from an address past the limit: %d, and a guesser would learn it", c)
	}
	// Another address isn't affected, and the right code gets past the code check: 400 for
	// the genesis this request doesn't have.
	if c := register("203.0.113.10", testRegCode); c != 400 {
		t.Fatalf("the right code from another address: %d", c)
	}
}

// An identity has only so many streams open: one more is closed with 4429.
func TestStreamCap(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	for i := 0; i < maxStreams; i++ {
		openStream(t, ts, kat, "")
	}
	c := dialStream(t, ts)
	b, _ := wire.Marshal(map[string]any{"t": "auth", "token": kat.token})
	c.SendText(b)
	_, err := c.Next(5 * time.Second)
	var ce *ws.CloseError
	if !errors.As(err, &ce) || ce.Code != closeRateLimited {
		t.Fatalf("stream %d: %v, want close %d", maxStreams+1, err, closeRateLimited)
	}
	// Another identity's aren't counted with them.
	openStream(t, ts, newUser(t, ts, "ravi"), "")
}

func TestHardenedHeaders(t *testing.T) {
	ts := testServer(t)
	resp, err := http.Get(ts.URL + "/.well-known/tieroute/server")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("headers: %v", resp.Header)
	}
}

// A body that doesn't arrive doesn't hold its connection: the server gives up on it.
func TestSlowBody(t *testing.T) {
	defer func(old time.Duration) { bodyTime = old }(bodyTime)
	bodyTime = 300 * time.Millisecond
	ts := testServer(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /.well-known/tieroute/v1/client/auth/challenge HTTP/1.1\r\nHost: chat.test\r\nContent-Type: %s\r\nContent-Length: 1000\r\n\r\n{\"id\":", wire.MediaType)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	io.Copy(io.Discard, conn) // until the server answers and closes, or the 5 seconds pass
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the server held a stalled body for %v", d)
	}
	// A body that arrives in time is unaffected, and a handler may take longer than the
	// body's deadline after reading it: the deadline is lifted.
	kat := newUser(t, ts, "kat")
	time.Sleep(400 * time.Millisecond)
	if kat.token == "" {
		t.Fatal("no session")
	}
}

// IPv6 callers are counted by /64, and a limit's key is forgotten once its window has
// passed, not 30 days later.
func TestLimiterKeysAndSweep(t *testing.T) {
	for addr, want := range map[string]string{
		"203.0.113.9": "203.0.113.9", "2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64", "2001:db8:1:2::1": "2001:db8:1:2::/64",
		"::ffff:203.0.113.9": "::ffff:203.0.113.9", "junk": "junk",
	} {
		if got := addrKey(addr); got != want {
			t.Errorf("%s counted as %s, want %s", addr, got, want)
		}
	}
	l := &limiter{m: map[string][]int64{"old|restart": {1000}}}
	l.allow("hourly|a", 5, 3600, 1000, true)
	l.allow("monthly|b", 5, 30*24*3600, 1000, true)
	l.sweep(1000 + 3601)
	if _, ok := l.m["hourly|a"]; ok || len(l.win) != 1 {
		t.Fatalf("an hourly key an hour later: %v %v", l.m, l.win)
	}
	if len(l.m["monthly|b"]) != 1 || len(l.m["old|restart"]) != 1 {
		t.Fatalf("keys still in their windows: %v", l.m)
	}
	l.sweep(1000 + 30*24*3600 + 1)
	if len(l.m) != 0 || len(l.win) != 0 {
		t.Fatalf("after 30 days: %v %v", l.m, l.win)
	}
}
