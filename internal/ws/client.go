package ws

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client is the client side of a connection, for tests and tools: it masks what it sends.
type Client struct {
	c net.Conn
	r *bufio.Reader
}

// Dial opens a WebSocket to an http:// URL with one subprotocol.
func Dial(rawURL, protocol string) (*Client, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	c, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	k := make([]byte, 16)
	rand.Read(k)
	key := base64.StdEncoding.EncodeToString(k)
	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	if protocol != "" {
		req.Header.Set("Sec-WebSocket-Protocol", protocol)
	}
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, nil, err
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	sum := sha1.Sum([]byte(key + acceptGUID))
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		c.Close()
		return nil, resp, errors.New("ws: handshake refused: " + resp.Status)
	}
	return &Client{c: c, r: r}, resp, nil
}

// Send writes one masked frame.
func (cl *Client) Send(opcode int, payload []byte) error {
	h := []byte{0x80 | byte(opcode), 0x80}
	switch n := len(payload); {
	case n < 126:
		h[1] |= byte(n)
	case n <= 0xFFFF:
		h[1] |= 126
		h = binary.BigEndian.AppendUint16(h, uint16(n))
	default:
		h[1] |= 127
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	mask := make([]byte, 4)
	rand.Read(mask)
	h = append(h, mask...)
	m := make([]byte, len(payload))
	for i := range payload {
		m[i] = payload[i] ^ mask[i%4]
	}
	_, err := cl.c.Write(append(h, m...))
	return err
}

// SendText sends a text message.
func (cl *Client) SendText(b []byte) error { return cl.Send(OpText, b) }

// Next returns the next text message. A close frame returns a *CloseError with its code.
func (cl *Client) Next(timeout time.Duration) ([]byte, error) {
	cl.c.SetReadDeadline(time.Now().Add(timeout))
	for {
		var h [2]byte
		if _, err := io.ReadFull(cl.r, h[:]); err != nil {
			return nil, err
		}
		n := int64(h[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			io.ReadFull(cl.r, b[:])
			n = int64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			io.ReadFull(cl.r, b[:])
			n = int64(binary.BigEndian.Uint64(b[:]))
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(cl.r, p); err != nil {
			return nil, err
		}
		switch int(h[0] & 0x0F) {
		case OpText:
			return p, nil
		case opClose:
			code := closeNoStatus
			if len(p) >= 2 {
				code = int(binary.BigEndian.Uint16(p))
			}
			return nil, &CloseError{Code: code, Reason: string(p[min(2, len(p)):])}
		case opPing:
			cl.Send(opPong, p)
		}
	}
}

// Close closes the connection without a closing handshake.
func (cl *Client) Close() { cl.c.Close() }
