package ws

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

// pipeConn is a net.Conn whose writes are kept: what the server sent back.
type pipeConn struct {
	net.Conn
	out bytes.Buffer
}

func (p *pipeConn) Write(b []byte) (int, error)      { return p.out.Write(b) }
func (p *pipeConn) Close() error                     { return nil }
func (p *pipeConn) SetWriteDeadline(time.Time) error { return nil }

// outcome is what a client's bytes lead to: the messages read, the pongs and close frame
// written back, and how reading ended.
type outcome struct {
	Msgs  []string
	Pongs []string
	Close int    // the close code the server sent, 0 if none
	End   string // "eof", "peer CODE REASON", or "closed"
}

// reference reads a client's bytes as RFC 6455 and this package's limits say: masked frames,
// no extensions, control frames of up to 125 bytes and never fragmented, frames and messages
// of up to max bytes. It's written separately from Conn.Read, for FuzzRead to compare.
func reference(data []byte, max int64) outcome {
	var o outcome
	closeWith := func(code int) outcome {
		if o.Close == 0 {
			o.Close = code
		}
		o.End = "closed"
		return o
	}
	var msg []byte
	op := -1
	for {
		if len(data) < 2 {
			o.End = "eof"
			return o
		}
		b0, b1 := data[0], data[1]
		data = data[2:]
		fin, opcode := b0&0x80 != 0, int(b0&0x0F)
		if b0&0x70 != 0 || b1&0x80 == 0 {
			return closeWith(CloseProtocol)
		}
		n := uint64(b1 & 0x7F)
		if n == 126 || n == 127 {
			size := 2
			if n == 127 {
				size = 8
			}
			if len(data) < size {
				o.End = "eof"
				return o
			}
			n = 0
			for _, c := range data[:size] {
				n = n<<8 | uint64(c)
			}
			data = data[size:]
			if n>>63 != 0 { // the most significant bit must be 0 (RFC 6455 §5.2)
				return closeWith(CloseProtocol)
			}
		}
		if opcode >= 8 && (n > 125 || !fin) {
			return closeWith(CloseProtocol)
		}
		if n > uint64(max) {
			return closeWith(CloseTooBig)
		}
		if uint64(len(data)) < 4+n {
			o.End = "eof"
			return o
		}
		mask := data[:4]
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = data[4+i] ^ mask[i%4]
		}
		data = data[4+n:]
		switch opcode {
		case 0x9:
			o.Pongs = append(o.Pongs, string(payload))
			continue
		case 0xA:
			continue
		case 0x8:
			code, reason := 1005, ""
			if len(payload) >= 2 {
				code, reason = int(binary.BigEndian.Uint16(payload)), string(payload[2:])
			}
			o.Close = CloseNormal
			o.End = fmt.Sprintf("peer %d %q", code, reason)
			return o
		case 0x1, 0x2:
			if op != -1 {
				return closeWith(CloseProtocol)
			}
			op = opcode
		case 0x0:
			if op == -1 {
				return closeWith(CloseProtocol)
			}
		default:
			return closeWith(CloseProtocol)
		}
		if int64(len(msg))+int64(n) > max {
			return closeWith(CloseTooBig)
		}
		msg = append(msg, payload...)
		if fin {
			o.Msgs = append(o.Msgs, fmt.Sprintf("%d:%s", op, msg))
			msg, op = nil, -1
		}
	}
}

// replies reads the frames the server wrote: pongs, then perhaps a close.
func replies(t *testing.T, out []byte, o *outcome) {
	for len(out) > 0 {
		if len(out) < 2 {
			t.Fatalf("a partial frame written: %x", out)
		}
		op, n := out[0]&0x0F, int(out[1]&0x7F)
		if out[0]&0x80 == 0 || out[1]&0x80 != 0 || n > 125 || len(out) < 2+n {
			t.Fatalf("a bad control frame written: %x", out)
		}
		p := out[2 : 2+n]
		out = out[2+n:]
		switch op {
		case 0xA:
			o.Pongs = append(o.Pongs, string(p))
		case 0x8:
			if len(p) < 2 || len(out) > 0 {
				t.Fatalf("a bad close frame written: %x", p)
			}
			o.Close = int(binary.BigEndian.Uint16(p))
		default:
			t.Fatalf("opcode %x written", op)
		}
	}
}

// Conn.Read reads any client bytes as the reference does: the same messages, pongs, close
// code, and ending, without panicking or holding more than its limit.
func FuzzRead(f *testing.F) {
	f.Add(frame(true, OpText, []byte("hi")))
	f.Add(append(append(frame(false, OpText, []byte("ab")), frame(true, opPing, []byte("p"))...), frame(true, opContinuation, []byte("cd"))...))
	f.Add(append(frame(true, OpBinary, bytes.Repeat([]byte{7}, 300)), frame(true, opClose, []byte{3, 232, 'b', 'y', 'e'})...))
	f.Add(frame(true, OpText, bytes.Repeat([]byte("x"), 70000)))
	f.Add(frame(false, opPing, nil))
	f.Add(frame(true, opContinuation, []byte("orphan")))
	f.Add([]byte{0x81, 0x02, 'h', 'i'}) // unmasked
	f.Add([]byte{0x81, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4})
	const max = 1 << 16
	f.Fuzz(func(t *testing.T, data []byte) {
		want := reference(data, max)
		pc := &pipeConn{}
		c := &Conn{c: pc, r: bufio.NewReader(bytes.NewReader(data)), MaxSize: max}
		var got outcome
		for {
			op, msg, err := c.Read()
			if err == nil {
				if op != OpText && op != OpBinary || len(msg) > max {
					t.Fatalf("Read gave opcode %d, %d bytes", op, len(msg))
				}
				got.Msgs = append(got.Msgs, fmt.Sprintf("%d:%s", op, msg))
				continue
			}
			var ce *CloseError
			switch {
			case errors.As(err, &ce):
				got.End = fmt.Sprintf("peer %d %q", ce.Code, ce.Reason)
			case errors.Is(err, ErrClosed):
				got.End = "closed"
			default:
				got.End = "eof"
			}
			break
		}
		replies(t, pc.out.Bytes(), &got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Read: %+v\nreference: %+v", got, want)
		}
	})
}
