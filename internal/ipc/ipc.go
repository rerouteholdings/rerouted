// Package ipc is what rerouted's processes share to talk over unix sockets: messages as a
// 4-byte big-endian length and that much JSON, the user at the other end, and the socket
// systemd passes.
package ipc

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// ErrTooLarge is a message over the size the caller allows.
var ErrTooLarge = errors.New("ipc: message too large")

// Write sends v as one message of at most max bytes of JSON.
func Write(w io.Writer, v any, max int) error {
	b, err := wire.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > max {
		return ErrTooLarge
	}
	msg := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(msg, uint32(len(b)))
	copy(msg[4:], b)
	_, err = w.Write(msg)
	return err
}

// Read reads one message of at most max bytes into v.
func Read(r io.Reader, v any, max int) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if uint64(size) > uint64(max) {
		return ErrTooLarge
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return wire.Unmarshal(b, v)
}

// Listen answers the one socket systemd passes (socket activation), or listens on a new
// unix socket at path, which the owner's group may connect to.
func Listen(path string) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") == "1" {
		f := os.NewFile(3, "systemd socket")
		defer f.Close()
		return net.FileListener(f)
	}
	if path == "" {
		return nil, errors.New("no socket from systemd, and no -listen")
	}
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return l, os.Chmod(path, 0o660)
}
