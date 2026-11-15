package keyd

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// timeout bounds one request, connecting included. The first may wait for rerouted-keyd
// to start: with socket activation, the connection is accepted once it has.
const timeout = 30 * time.Second

// Client asks rerouted-keyd to sign. It's safe for concurrent use: a request takes an idle
// connection, or makes one, and gives it back after.
type Client struct {
	path string
	idle chan net.Conn
}

// Load connects to rerouted-keyd at the unix socket path, and answers the keys it holds
// for the server name: each signs through it.
func Load(path, name string) (serverkey.Key, error) {
	c := &Client{path: path, idle: make(chan net.Conn, 16)}
	resp, err := c.do(request{Op: "keys"})
	if err != nil {
		return serverkey.Key{}, err
	}
	k := serverkey.Key{InviteKey: resp.Invite, Communities: map[string]serverkey.CompositeKey{}}
	for _, p := range resp.Keys {
		switch {
		case p.Name == name && p.V == wire.V1:
			if len(p.Pub) != ed25519.PublicKeySize {
				return serverkey.Key{}, errors.New("rerouted-keyd: bad version 1 public key")
			}
			k.Pub, k.KID, k.Created, k.Remote = ed25519.PublicKey(p.Pub), p.KID, time.Unix(p.Created, 0), c
		case p.V == wire.V2:
			pub, err := wire.ParseCompositePublicKey(p.Pub)
			if err != nil {
				return serverkey.Key{}, fmt.Errorf("rerouted-keyd: %s's public key: %w", p.Name, err)
			}
			ck := serverkey.CompositeKey{Pub: pub, KID: p.KID, Created: time.Unix(p.Created, 0), Remote: c}
			if p.Name == name {
				k.V2 = ck
			} else {
				k.Communities[p.Name] = ck
			}
		}
	}
	if k.Remote == nil || k.V2.Remote == nil {
		return serverkey.Key{}, fmt.Errorf("rerouted-keyd holds no keys for %s: is it reading the same settings?", name)
	}
	if len(k.InviteKey) == 0 {
		return serverkey.Key{}, errors.New("rerouted-keyd sent no invite code key")
	}
	return k, nil
}

// Sign implements serverkey.Signer.
func (c *Client) Sign(kid, t, b string) ([]byte, error) {
	resp, err := c.do(request{Op: "sign", KID: kid, T: t, B: b})
	if err != nil {
		return nil, err
	}
	return resp.S, nil
}

func (c *Client) do(req request) (response, error) {
	for {
		conn, reused := c.conn()
		if conn == nil {
			d := net.Dialer{Timeout: timeout}
			var err error
			if conn, err = d.Dial("unix", c.path); err != nil {
				return response{}, fmt.Errorf("rerouted-keyd: %w", err)
			}
		}
		conn.SetDeadline(time.Now().Add(timeout))
		var resp response
		err := writeMsg(conn, req)
		if err == nil {
			err = readMsg(conn, &resp)
		}
		if err != nil {
			conn.Close()
			// An idle connection may be to an rerouted-keyd that has since restarted:
			// try a new one. Signing again is harmless.
			if reused {
				continue
			}
			return response{}, fmt.Errorf("rerouted-keyd: %w", err)
		}
		c.put(conn)
		if resp.Err != "" {
			return response{}, errors.New("rerouted-keyd: " + resp.Err)
		}
		return resp, nil
	}
}

func (c *Client) conn() (net.Conn, bool) {
	select {
	case conn := <-c.idle:
		return conn, true
	default:
		return nil, false
	}
}

func (c *Client) put(conn net.Conn) {
	select {
	case c.idle <- conn:
	default:
		conn.Close()
	}
}
