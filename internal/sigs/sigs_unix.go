//go:build unix

// Package sigs names the signals an operator sends a running rerouted, on the systems that
// have them.
package sigs

import (
	"os"
	"syscall"
)

// Reload asks the server to read its settings again (SIGHUP).
var Reload = []os.Signal{syscall.SIGHUP}

// RestartWhenIdle asks the server to restart once no voice calls are active (SIGUSR2).
var RestartWhenIdle = []os.Signal{syscall.SIGUSR2}
