//go:build !windows

// TODO(pre-1.0, #172): delete this file with peermigrate.go.

package main

import (
	"os"
	"syscall"
)

// socketIdentity reads the device and inode behind the socket at path, the key
// the migration's once-per-socket bookkeeping uses. It mirrors
// peer.statIdentity: Dev is int32 on darwin and uint64 on linux, so both
// fields are widened.
func socketIdentity(path string) (peerIdentity, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return peerIdentity{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return peerIdentity{}, false
	}
	return peerIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}
