//go:build unix

package auth

import (
	"os"
	"syscall"
)

// fileIdentity is the device and inode from the stat already taken.
func fileIdentity(_ string, fi os.FileInfo) fileID {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{vol: uint64(st.Dev), idx: uint64(st.Ino)} //nolint:unconvert // Dev and Ino widths differ by platform
}
