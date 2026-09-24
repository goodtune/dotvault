//go:build windows

// TODO(pre-1.0, #172): delete this file with peermigrate.go.

package main

// socketIdentity has no device/inode to report on Windows (syscall.Stat_t does
// not exist there), so it always fails and the migration is inert. That costs
// nothing: the peer sockets are Unix-domain, so a Windows daemon never borrows
// through one and has no old-default forward to rename.
func socketIdentity(string) (peerIdentity, bool) {
	return peerIdentity{}, false
}
