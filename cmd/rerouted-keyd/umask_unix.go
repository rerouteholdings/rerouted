//go:build unix

package main

import "syscall"

// restrictUmask makes the key files and the socket readable by this user only.
func restrictUmask() { syscall.Umask(0o077) }
