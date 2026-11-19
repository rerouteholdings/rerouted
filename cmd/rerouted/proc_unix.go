//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// processAlive reports whether a process with this ID exists. EPERM means it does, run by
// another user.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// isRoot reports whether rerouted runs as root.
func isRoot() bool { return syscall.Geteuid() == 0 }

// chownTree gives everything under path like's owner and group, when running as root:
// files root restores or creates for the server must stay readable by its user.
func chownTree(path string, like os.FileInfo) {
	if !isRoot() || like == nil {
		return
	}
	st, ok := like.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			os.Lchown(p, int(st.Uid), int(st.Gid))
		}
		return nil
	})
}

// diskSpace returns the bytes free to this user, and the total, on dir's file system.
func diskSpace(dir string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), uint64(st.Blocks) * uint64(st.Bsize), nil
}

// chownTreeTo gives everything under path to uid and gid.
func chownTreeTo(path string, uid, gid int) {
	filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
}
