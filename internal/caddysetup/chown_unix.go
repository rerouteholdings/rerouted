//go:build unix

package caddysetup

import (
	"os"
	"syscall"
)

// chownLike gives path fi's owner and group. Changing them needs root, so when the owner
// is already right this is a no-op that works for anyone.
func chownLike(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	cur, err := os.Stat(path)
	if err != nil {
		return err
	}
	if c, ok := cur.Sys().(*syscall.Stat_t); ok && c.Uid == st.Uid && c.Gid == st.Gid {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}
