// Package ws is the small part of WebSocket (RFC 6455) that the Tieroute stream needs: a
// server that upgrades a request, reads text messages from a client, and writes text
// messages back. It answers pings, handles fragmented messages and the closing handshake,
// and nothing else: no extensions, no compression. Written here so rerouted keeps to the
// standard library.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Opcodes (RFC 6455 §5.2).
const (
	opContinuation = 0x0
	OpText         = 0x1
	OpBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// Close codes this package sends itself.
const (
	CloseNormal      = 1000
	CloseProtocol    = 1002
	CloseTooBig      = 1009
	closeNoStatus    = 1005
	acceptGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxControlLength = 125
)

// ErrClosed is returned once the connection is closed, by either side.
var ErrClosed = errors.New("ws: closed")

// CloseError is the peer's close frame.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("ws: closed by peer: %d %s", e.Code, e.Reason)
}

// Conn is a server-side WebSocket connection.
type Conn struct {
	c       net.Conn
	r       *bufio.Reader
	wmu     sync.Mutex
	closed  bool
	MaxSize int64 // largest message accepted; larger ones close with 1009
}

// Upgrade answers a WebSocket handshake that offers protocol in Sec-WebSocket-Protocol.
// If the request isn't a valid handshake, or doesn't offer protocol, it writes an HTTP
// error and returns an error.
func Upgrade(w http.ResponseWriter, r *http.Request, protocol string) (*Conn, error) {
	fail := func(status int, msg string) (*Conn, error) {
		http.Error(w, msg, status)
		return nil, errors.New("ws: " + msg)
	}
	if r.Method != http.MethodGet {
		return fail(http.StatusMethodNotAllowed, "a WebSocket handshake is a GET")
	}
	if !headerHas(r.Header, "Connection", "upgrade") || !headerHas(r.Header, "Upgrade", "websocket") {
		return fail(http.StatusBadRequest, "not a WebSocket handshake")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		return fail(http.StatusUpgradeRequired, "WebSocket version 13 only")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 16 {
		return fail(http.StatusBadRequest, "bad Sec-WebSocket-Key")
	}
	if !headerHas(r.Header, "Sec-WebSocket-Protocol", protocol) {
		return fail(http.StatusBadRequest, "the subprotocol must be "+protocol)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return fail(http.StatusInternalServerError, "can't take over the connection")
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + acceptGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n" +
		"Sec-WebSocket-Protocol: " + protocol + "\r\n\r\n"
	if _, err := c.Write([]byte(resp)); err != nil {
		c.Close()
		return nil, err
	}
	return &Conn{c: c, r: rw.Reader, MaxSize: 1 << 20}, nil
}

// headerHas reports whether a comma-separated header lists token, ignoring case.
func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// SetReadDeadline bounds how long the next Read may wait.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

// Read returns the next data message and its opcode (OpText or OpBinary). It answers pings
// and close frames itself. After the peer closes, it returns a *CloseError.
func (c *Conn) Read() (int, []byte, error) {
	var msg []byte
	op := -1
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch opcode {
		case opPing:
			c.writeFrame(opPong, payload)
			continue
		case opPong:
			continue
		case opClose:
			code, reason := closeNoStatus, ""
			if len(payload) >= 2 {
				code, reason = int(binary.BigEndian.Uint16(payload)), string(payload[2:])
			}
			c.closeWith(CloseNormal, "")
			return 0, nil, &CloseError{code, reason}
		case OpText, OpBinary:
			if op != -1 {
				c.closeWith(CloseProtocol, "expected a continuation")
				return 0, nil, ErrClosed
			}
			op = opcode
		case opContinuation:
			if op == -1 {
				c.closeWith(CloseProtocol, "continuation without a message")
				return 0, nil, ErrClosed
			}
		default:
			c.closeWith(CloseProtocol, "unknown opcode")
			return 0, nil, ErrClosed
		}
		if int64(len(msg)+len(payload)) > c.MaxSize {
			c.closeWith(CloseTooBig, "message too large")
			return 0, nil, ErrClosed
		}
		msg = append(msg, payload...)
		if fin {
			return op, msg, nil
		}
	}
}

func (c *Conn) readFrame() (fin bool, opcode int, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(c.r, h[:]); err != nil {
		return
	}
	fin, opcode = h[0]&0x80 != 0, int(h[0]&0x0F)
	if h[0]&0x70 != 0 {
		c.closeWith(CloseProtocol, "no extensions were negotiated")
		return false, 0, nil, ErrClosed
	}
	if h[1]&0x80 == 0 {
		c.closeWith(CloseProtocol, "client frames must be masked")
		return false, 0, nil, ErrClosed
	}
	n := int64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(c.r, b[:]); err != nil {
			return
		}
		n = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(c.r, b[:]); err != nil {
			return
		}
		n = int64(binary.BigEndian.Uint64(b[:]))
	}
	if opcode >= opClose && (n > maxControlLength || !fin) {
		c.closeWith(CloseProtocol, "bad control frame")
		return false, 0, nil, ErrClosed
	}
	if n > c.MaxSize || n < 0 {
		c.closeWith(CloseTooBig, "frame too large")
		return false, 0, nil, ErrClosed
	}
	var mask [4]byte
	if _, err = io.ReadFull(c.r, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.r, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return
}

// WriteText sends one text message.
func (c *Conn) WriteText(b []byte) error { return c.writeFrame(OpText, b) }

// Ping sends a ping, which the client answers with a pong.
func (c *Conn) Ping() error { return c.writeFrame(opPing, nil) }

func (c *Conn) writeFrame(opcode int, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return ErrClosed
	}
	h := []byte{0x80 | byte(opcode), 0}
	switch n := len(payload); {
	case n < 126:
		h[1] = byte(n)
	case n <= 0xFFFF:
		h[1] = 126
		h = binary.BigEndian.AppendUint16(h, uint16(n))
	default:
		h[1] = 127
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.c.Write(append(h, payload...)); err != nil {
		c.closed = true
		c.c.Close()
		return err
	}
	return nil
}

// Close sends a close frame with code and reason, and closes the connection.
func (c *Conn) Close(code int, reason string) { c.closeWith(code, reason) }

func (c *Conn) closeWith(code int, reason string) {
	if len(reason) > maxControlLength-2 {
		reason = reason[:maxControlLength-2]
	}
	payload := binary.BigEndian.AppendUint16(nil, uint16(code))
	c.writeFrame(opClose, append(payload, reason...))
	c.wmu.Lock()
	c.closed = true
	c.wmu.Unlock()
	c.c.Close()
}
