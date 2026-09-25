//go:build windows

package peer

import "os"

// statIdentity has no device/inode to report on Windows (syscall.Stat_t does
// not exist there), so every member carries the zero identity and the
// "recreated" test never fires.
//
// What that costs is bounded rather than nil. Windows does resolve AF_UNIX
// socket nodes — Go reports os.ModeSocket for the reparse point — so a pool
// there can hold members. With every identity equal, evict's stale-failure
// guard is inert (a failure always matches) and a reconnect behind the same
// name is not recognised as a new socket. Neither is load-bearing: the guard
// only ever suppressed a redundant eviction, and EvictProbeInterval still
// readmits.
func statIdentity(fi os.FileInfo) identity {
	return identity{}
}
