//go:build darwin || freebsd

package vaultfs

import "golang.org/x/sys/unix"

// unmountStale forces the unmount of a mount whose server is gone. The BSDs
// have no lazy-unmount equivalent of Linux's MNT_DETACH; MNT_FORCE is the
// nearest thing, and a mount with no server behind it has nothing left to
// lose by being torn down under its remaining references.
func unmountStale(dir string) error {
	return unix.Unmount(dir, unix.MNT_FORCE)
}
