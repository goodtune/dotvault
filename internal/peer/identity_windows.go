//go:build windows

package peer

import "os"

// statIdentity has no device/inode to report on Windows (syscall.Stat_t does
// not exist there), so every member carries the zero identity and the
// "recreated" test never fires. That costs nothing: the daemon's peer sockets
// are Unix-domain, so a Windows build resolves no members at all, and a member
// that somehow existed would still be readmitted by EvictProbeInterval.
func statIdentity(fi os.FileInfo) identity {
	return identity{}
}
