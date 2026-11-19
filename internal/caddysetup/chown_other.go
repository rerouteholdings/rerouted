//go:build !unix

package caddysetup

import "os"

func chownLike(string, os.FileInfo) error { return nil }
