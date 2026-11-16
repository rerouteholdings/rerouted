package sfuipc

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/sfu"
)

// timeout bounds a request: a join waits up to 3 seconds for ICE gathering, and the first
// request may wait for rerouted-sfu to start.
const timeout = 30 * time.Second

var errDown = errors.New("rerouted-sfu: connection lost")

// Client is rerouted's side: an sfu.Voice whose rooms are in rerouted-sfu. If the
// connection drops, every participant is gone (cfg.OnGone hears of each), and the next
// request connects again.
type Client struct {
	path string
	cfg  sfu.Config

	cmu     sync.Mutex // held while connecting
	mu      sync.Mutex
	conn    net.Conn // once it said hello
	closed  bool
	next    uint64
	waiting map[uint64]chan message
	signals map[[2]string]signalOn // by room and key

	wmu    sync.Mutex
	events *queue
}

// signalOn is a participant's Signal, and the connection it joined on.
type signalOn struct {
	signal sfu.Signal
	conn   net.Conn
}

// Dial connects to rerouted-sfu at the unix socket path, and has it start an SFU with
// cfg's UDP port, public addresses, and loopback setting. cfg.OnGone hears of participants
// gone; cfg.IPFilter can't cross, and is ignored.
func Dial(path string, cfg sfu.Config) (*Client, error) {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	c := &Client{path: path, cfg: cfg, waiting: map[uint64]chan message{}, signals: map[[2]string]signalOn{}, events: newQueue()}
	go c.dispatch()
	if _, err := c.connect(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// connect answers the connection, making one and saying hello if there's none.
func (c *Client) connect() (net.Conn, error) {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	c.mu.Lock()
	conn, closed := c.conn, c.closed
	c.mu.Unlock()
	if closed {
		return nil, sfu.ErrNotIn // as a closed SFU's rooms answer
	}
	if conn != nil {
		return conn, nil
	}
	conn, err := net.DialTimeout("unix", c.path, timeout)
	if err != nil {
		return nil, err
	}
	go c.read(conn)
	c.mu.Lock()
	p := c.register()
	c.mu.Unlock()
	err = c.write(conn, request{ID: p.id, Op: "hello", UDPPort: c.cfg.UDPPort, PublicIPs: c.cfg.PublicIPs, Loopback: c.cfg.Loopback})
	if err == nil {
		err = p.wait()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	return conn, nil
}

type pending struct {
	id uint64
	ch chan message
	c  *Client
	m  message
}

// register makes an ID to wait on. c.mu is held.
func (c *Client) register() *pending {
	c.next++
	p := &pending{id: c.next, ch: make(chan message, 1), c: c}
	c.waiting[p.id] = p.ch
	return p
}

func (p *pending) wait() error {
	select {
	case m, ok := <-p.ch:
		if !ok {
			return errDown
		}
		p.m = m
		return codeErr(m.Err)
	case <-time.After(timeout):
		p.c.mu.Lock()
		delete(p.c.waiting, p.id)
		p.c.mu.Unlock()
		return errors.New("rerouted-sfu: no answer")
	}
}

func (c *Client) write(conn net.Conn, req request) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(timeout))
	return ipc.Write(conn, req, maxMessage)
}

// call sends a request and waits for its answer. on, if set, runs with c.mu held once the
// connection is known, before the request goes.
func (c *Client) call(req request, on func(net.Conn)) (message, error) {
	conn, err := c.connect()
	if err != nil {
		return message{}, err
	}
	c.mu.Lock()
	p := c.register()
	if on != nil {
		on(conn)
	}
	c.mu.Unlock()
	req.ID = p.id
	if err := c.write(conn, req); err != nil {
		conn.Close()
		return message{}, err
	}
	err = p.wait()
	return p.m, err
}

func (c *Client) read(conn net.Conn) {
	for {
		var m message
		if err := ipc.Read(conn, &m, maxMessage); err != nil {
			break
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.waiting[m.ID]
			delete(c.waiting, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		c.events.push(m)
	}
	conn.Close()
	// Everyone in a room was in that rerouted-sfu: they're gone with the connection.
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	for id, ch := range c.waiting {
		close(ch)
		delete(c.waiting, id)
	}
	var gone [][2]string
	for k, s := range c.signals {
		if s.conn == conn {
			gone = append(gone, k)
			delete(c.signals, k)
		}
	}
	c.mu.Unlock()
	for _, k := range gone {
		c.events.push(message{Ev: "gone", Room: k[0], Key: k[1], OK: true})
	}
}

// dispatch hands events over in the order they came, apart from the reader, so a handler
// that asks rerouted-sfu something isn't waiting on itself.
func (c *Client) dispatch() {
	for {
		m, ok := c.events.pop()
		if !ok {
			return
		}
		k := [2]string{m.Room, m.Key}
		switch m.Ev {
		case "signal":
			c.mu.Lock()
			s := c.signals[k]
			c.mu.Unlock()
			if s.signal != nil {
				s.signal(map[string]any{"t": m.T, "channel": m.Channel, "data": m.Data})
			}
		case "gone":
			if !m.OK { // OK: already removed when the connection dropped
				// rerouted-sfu drops a connection before it says so. A device that joined
				// again in between is in the room: the news is of its old connection.
				if c.Room(m.Room).Has(m.Key) {
					continue
				}
				c.mu.Lock()
				delete(c.signals, k)
				c.mu.Unlock()
			}
			if c.cfg.OnGone != nil {
				c.cfg.OnGone(m.Room, m.Key)
			}
		}
	}
}

// Room implements sfu.Voice.
func (c *Client) Room(key string) sfu.VoiceRoom { return room{c, key} }

// Close implements sfu.Voice: rerouted-sfu ends every room when the connection does.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	c.events.close()
	return nil
}

type room struct {
	c   *Client
	key string
}

func (r room) Join(m sfu.Member, offer string, max int, mayVoice bool, signal sfu.Signal) (string, error) {
	k := [2]string{r.key, m.Key}
	var on net.Conn
	resp, err := r.c.call(request{Op: "join", Room: r.key, Key: m.Key, Who: m.ID, Dev: m.Dev, Visit: m.Visit, Channel: m.Channel, Data: offer, Max: max, May: mayVoice},
		func(conn net.Conn) { on, r.c.signals[k] = conn, signalOn{signal, conn} })
	if err != nil {
		r.c.mu.Lock()
		if r.c.signals[k].conn == on {
			delete(r.c.signals, k)
		}
		r.c.mu.Unlock()
		return "", err
	}
	return resp.Data, nil
}

func (r room) NewVisit(key string, visit uint32) error {
	_, err := r.c.call(request{Op: "visit", Room: r.key, Key: key, Visit: visit}, nil)
	return err
}

func (r room) Leave(key string) bool {
	resp, _ := r.c.call(request{Op: "leave", Room: r.key, Key: key}, nil)
	r.c.mu.Lock()
	delete(r.c.signals, [2]string{r.key, key})
	r.c.mu.Unlock()
	return resp.OK
}

func (r room) Remote(key, data string) (string, error) {
	resp, err := r.c.call(request{Op: "remote", Room: r.key, Key: key, Data: data}, nil)
	return resp.Data, err
}

func (r room) ICE(key, data string) error {
	_, err := r.c.call(request{Op: "ice", Room: r.key, Key: key, Data: data}, nil)
	return err
}

func (r room) SetVoice(key string, may bool) {
	r.c.call(request{Op: "voice", Room: r.key, Key: key, May: may}, nil)
}

func (r room) SetCast(key string, kinds []string, limit int) error {
	_, err := r.c.call(request{Op: "cast", Room: r.key, Key: key, Kinds: kinds, Limit: limit}, nil)
	return err
}

func (r room) State() []sfu.Participant {
	resp, err := r.c.call(request{Op: "state", Room: r.key}, nil)
	if err != nil {
		return nil
	}
	out := make([]sfu.Participant, 0, len(resp.State))
	for _, p := range resp.State {
		out = append(out, sfu.Participant{ID: p.ID, Dev: p.Dev, Visit: p.Visit, Cast: p.Cast})
	}
	return out
}

func (r room) Has(key string) bool {
	resp, _ := r.c.call(request{Op: "has", Room: r.key, Key: key}, nil)
	return resp.OK
}

func (r room) Len() int {
	resp, _ := r.c.call(request{Op: "len", Room: r.key}, nil)
	return resp.N
}

// queue is an unbounded FIFO of events: the reader never waits for the dispatcher.
type queue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []message
	closed bool
}

func newQueue() *queue {
	q := &queue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) push(m message) {
	q.mu.Lock()
	q.items = append(q.items, m)
	q.mu.Unlock()
	q.cond.Signal()
}

func (q *queue) pop() (message, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return message{}, false
	}
	m := q.items[0]
	q.items = q.items[1:]
	return m, true
}

func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}
