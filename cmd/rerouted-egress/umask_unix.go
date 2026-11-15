//go:build unix

package main

import "syscall"

// restrictUmask makes the socket, with -listen, its user's only.
func restrictUmask() { syscall.Umask(0o077) }
