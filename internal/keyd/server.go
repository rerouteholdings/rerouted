package keyd

import (
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Server answers rerouted's requests on a listener.
type Server struct {
	Keys *Keys
	// UID, unless -1, is the only user that may connect, checked with the socket's peer
	// credentials on top of its file permissions.
	UID int
	Log *slog.Logger
	// Now is the clock S2S request times and reservations are checked against. Nil is the
	// system clock.
	Now func() int64
}

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			// Out of file descriptors, say: wait rather than spin.
			s.Log.Warn("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	if s.UID != -1 {
		uid, err := ipc.PeerUID(c)
		if err != nil || uid != s.UID {
			s.Log.Warn("refused a connection from another user", "uid", uid, "err", err)
			return
		}
	}
	for {
		var req request
		if err := readMsg(c, &req); err != nil {
			if !errors.Is(err, io.EOF) {
				s.Log.Warn("unreadable request", "err", err)
			}
			return
		}
		if err := writeMsg(c, s.handle(req)); err != nil {
			return
		}
	}
}

func (s *Server) now() int64 {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().Unix()
}

func (s *Server) handle(req request) response {
	switch req.Op {
	case "keys":
		return response{Keys: s.Keys.pubs, Invite: s.Keys.invite}
	case "sign":
		h, ok := s.Keys.byKID[req.KID]
		if !ok {
			return response{Err: "no key " + req.KID}
		}
		if err := check(h, req.T, req.B, s.now()); err != nil {
			// rerouted never asks for these: it has a bug, or someone else is in it.
			s.Log.Warn("refused to sign", "t", req.T, "kid", req.KID, "name", h.name, "err", err)
			return response{Err: "refused: " + err.Error()}
		}
		sig, err := sign(h, req.T, req.B)
		if err != nil {
			return response{Err: err.Error()}
		}
		return response{S: sig}
	}
	return response{Err: "no such op"}
}

func sign(h held, t, b string) ([]byte, error) {
	if h.v2 != nil {
		in, err := wire.SigInputV2(t, b)
		if err != nil {
			return nil, err
		}
		return h.v2.Sign(in)
	}
	in, err := wire.SigInput(t, b)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(h.v1, in), nil
}
