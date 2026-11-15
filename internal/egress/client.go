package egress

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/rerouteholdings/rerouted/internal/ipc"
)

// Client is rerouted's side: a dialer and a TXT lookup through rerouted-egress at Path.
type Client struct {
	Path string
}

func (c Client) ask(ctx context.Context, req request) (net.Conn, response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, response{}, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)
	var resp response
	if err = ipc.Write(conn, req, maxMessage); err == nil {
		err = ipc.Read(conn, &resp, maxMessage)
	}
	if err == nil && resp.Err != "" {
		err = errors.New("rerouted-egress: " + resp.Err)
	}
	if err != nil {
		conn.Close()
		return nil, response{}, err
	}
	conn.SetDeadline(time.Time{})
	return conn, resp, nil
}

// DialContext connects to addr (host:port, TCP) through rerouted-egress: an
// http.Transport's DialContext.
func (c Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("egress: only TCP")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	conn, _, err := c.ask(ctx, request{Op: "connect", Host: host, Port: p})
	return conn, err
}

// LookupTXT reads name's DNS TXT records through rerouted-egress: fed.Fed's LookupTXT.
func (c Client) LookupTXT(ctx context.Context, name string) ([]string, error) {
	conn, resp, err := c.ask(ctx, request{Op: "txt", Name: name})
	if err != nil {
		return nil, err
	}
	conn.Close()
	return resp.TXT, nil
}
