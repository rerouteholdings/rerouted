//go:build !unix

// Package sigs names the signals an operator sends a running rerouted, on the systems that
// have them.
package sigs

import "os"

// Reload and RestartWhenIdle are empty where there's no SIGHUP or SIGUSR2.
var Reload, RestartWhenIdle []os.Signal
