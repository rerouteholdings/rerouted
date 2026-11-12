package ws

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func echo(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r, "tieroute.v1")
		if err != nil {
			return
		}
		for {
			_, msg, err := c.Read()
			if err != nil {
				return
			}
			c.WriteText(append([]byte("echo: "), msg...))
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestEchoAndFragments(t *testing.T) {
	ts := echo(t)
	c, _, err := Dial(ts.URL, "tieroute.v1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SendText([]byte("hi"))
	if m, err := c.Next(time.Second); err != nil || string(m) != "echo: hi" {
		t.Fatalf("%q %v", m, err)
	}
	// A fragmented message, with a ping in the middle (RFC 6455 §5.4).
	big := strings.Repeat("x", 70000)
	c.c.Write(frame(false, OpText, []byte("ab")))
	c.Send(opPing, []byte("p"))
	c.c.Write(frame(true, opContinuation, []byte(big)))
	if m, err := c.Next(time.Second); err != nil || string(m) != "echo: ab"+big {
		t.Fatalf("fragments: %d bytes, %v", len(m), err)
	}
}

func TestWrongProtocolRefused(t *testing.T) {
	ts := echo(t)
	if _, resp, err := Dial(ts.URL, "chat"); err == nil || resp.StatusCode != 400 {
		t.Fatalf("another subprotocol: %v", err)
	}
	if _, _, err := Dial(ts.URL, ""); err == nil {
		t.Fatal("no subprotocol was accepted")
	}
}

func TestUnmaskedFrameClosesConnection(t *testing.T) {
	ts := echo(t)
	c, _, err := Dial(ts.URL, "tieroute.v1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.c.Write([]byte{0x81, 0x02, 'h', 'i'}) // no mask bit
	var ce *CloseError
	if _, err := c.Next(time.Second); !errors.As(err, &ce) || ce.Code != CloseProtocol {
		t.Fatalf("an unmasked frame: %v, want close 1002", err)
	}
}

// frame builds a masked frame with an explicit FIN bit.
func frame(fin bool, op int, p []byte) []byte {
	var b []byte
	first := byte(op)
	if fin {
		first |= 0x80
	}
	b = append(b, first)
	switch n := len(p); {
	case n < 126:
		b = append(b, 0x80|byte(n))
	case n <= 0xFFFF:
		b = append(b, 0x80|126, byte(n>>8), byte(n))
	default:
		b = append(b, 0x80|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	mask := []byte{1, 2, 3, 4}
	b = append(b, mask...)
	for i := range p {
		b = append(b, p[i]^mask[i%4])
	}
	return b
}
