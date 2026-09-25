//go:build windows

// TODO(pre-1.0, #172): delete this file with peermigrate.go.

package main

// socketIdentity has no device/inode to report on Windows (syscall.Stat_t does
// not exist there), so it always fails and the migration is inert there.
//
// The migration is the workstation-facing half of a headless host's borrow, and
// the borrowing side of the fleet is Linux/macOS: a Windows box is the
// workstation that *serves* the forward, not the one that renames it. So
// declining outright is the right answer rather than a gap — and a Windows host
// that did borrow simply keeps using the old default socket, which continues to
// work until #172 removes it.
func socketIdentity(string) (peerIdentity, bool) {
	return peerIdentity{}, false
}
