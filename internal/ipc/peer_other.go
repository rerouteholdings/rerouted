//go:build !linux

package ipc

import (
	"errors"
	"net"
)

func PeerUID(net.Conn) (int, error) {
	return -1, errors.New("checking a unix socket's peer isn't supported on this system")
}

// PeerCheckSupported reports whether the peer's user can be checked here.
const PeerCheckSupported = false
