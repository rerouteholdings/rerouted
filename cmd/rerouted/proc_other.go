//go:build !unix

package main

import (
	"errors"
	"os"
)

// processAlive can't tell on this platform, so it says no: status.json's age decides.
func processAlive(int) bool { return false }

func isRoot() bool { return false }

func chownTree(string, os.FileInfo) {}

func diskSpace(string) (uint64, uint64, error) {
	return 0, 0, errors.New("not supported on this platform")
}

func chownTreeTo(string, int, int) {}
