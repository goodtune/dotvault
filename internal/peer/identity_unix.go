//go:build !windows

package peer

import (
	"os"
	"syscall"
)

// statIdentity reads the device and inode behind fi. It is what tells a
// recreated socket — a forward that reconnected — from the same one still
// sitting there, which is the readmission signal on any platform without
// inotify. Dev is int32 on darwin and uint64 on linux; the conversion covers
// both.
func statIdentity(fi os.FileInfo) identity {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return identity{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	}
	return identity{}
}
