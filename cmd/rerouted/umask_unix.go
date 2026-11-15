//go:build unix

package main

import "syscall"

// restrictUmask makes everything rerouted creates readable by its own user only: the
// database, its -wal and -shm files, and files. Operator commands run from a shell with
// its umask, often 022, and the first of them on a new server creates the database.
func restrictUmask() { syscall.Umask(0o077) }
