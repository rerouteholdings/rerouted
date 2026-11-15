package sfuipc

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/sfu"
)

// Server is rerouted-sfu: it makes an SFU when rerouted says hello, and answers for it.
type Server struct {
	// UID, unless -1, is the only user that may connect (SO_PEERCRED), on top of the
	// socket's file permissions.
	UID int
	Log *slog.Logger
	// Filter, if set, keeps only the local addresses it returns true for: tests use it.
	Filter func(net.IP) bool
}

// Serve answers one connection at a time until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			s.Log.Warn("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.serve(c)
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
	var wmu sync.Mutex
	send := func(m message) {
		wmu.Lock()
		defer wmu.Unlock()
		if err := ipc.Write(c, m, maxMessage); err != nil {
			c.Close() // the read loop ends, and so does every room
		}
	}
	var v *sfu.SFU
	var wg sync.WaitGroup
	defer func() {
		if v != nil {
			v.Close()
		}
		wg.Wait()
	}()
	for {
		var req request
		if err := ipc.Read(c, &req, maxMessage); err != nil {
			if !errors.Is(err, io.EOF) {
				s.Log.Warn("unreadable request", "err", err)
			}
			return
		}
		if req.Op == "hello" {
			if v != nil {
				send(message{ID: req.ID, Err: "error: hello twice"})
				continue
			}
			var err error
			v, err = sfu.New(sfu.Config{
				UDPPort: req.UDPPort, PublicIPs: req.PublicIPs, Loopback: req.Loopback, IPFilter: s.Filter,
				OnGone: func(room, key string) { send(message{Ev: "gone", Room: room, Key: key}) },
				Log:    s.Log,
			})
			if err != nil {
				v = nil
				send(message{ID: req.ID, Err: errCode(err)})
				return
			}
			s.Log.Info("SFU started", "udp_port", req.UDPPort, "public_ips", req.PublicIPs)
			send(message{ID: req.ID})
			continue
		}
		if v == nil {
			send(message{ID: req.ID, Err: "error: no hello"})
			continue
		}
		// A join waits for ICE gathering: others go on meanwhile. rerouted sends a device's
		// next request after the answer to its last one, so each device's stay in order.
		wg.Add(1)
		go func() {
			defer wg.Done()
			send(handle(v, req, send))
		}()
	}
}

func handle(v *sfu.SFU, req request, send func(message)) message {
	r := v.Room(req.Room)
	out := message{ID: req.ID}
	var err error
	switch req.Op {
	case "join":
		room, key := req.Room, req.Key
		signal := func(f map[string]any) {
			t, _ := f["t"].(string)
			ch, _ := f["channel"].(uint64)
			data, _ := f["data"].(string)
			send(message{Ev: "signal", Room: room, Key: key, T: t, Channel: ch, Data: data})
		}
		m := sfu.Member{Key: req.Key, ID: req.Who, Dev: req.Dev, Visit: req.Visit, Channel: req.Channel}
		out.Data, err = r.Join(m, req.Data, req.Max, req.May, signal)
	case "visit":
		err = r.NewVisit(req.Key, req.Visit)
	case "leave":
		out.OK = r.Leave(req.Key)
	case "remote":
		out.Data, err = r.Remote(req.Key, req.Data)
	case "ice":
		err = r.ICE(req.Key, req.Data)
	case "voice":
		r.SetVoice(req.Key, req.May)
	case "cast":
		err = r.SetCast(req.Key, req.Kinds, req.Limit)
	case "state":
		for _, p := range r.State() {
			out.State = append(out.State, participant{ID: p.ID, Dev: p.Dev, Visit: p.Visit, Cast: p.Cast})
		}
	case "has":
		out.OK = r.Has(req.Key)
	case "len":
		out.N = r.Len()
	default:
		err = errors.New("no such op " + req.Op)
	}
	out.Err = errCode(err)
	return out
}
