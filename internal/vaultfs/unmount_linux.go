//go:build linux

package vaultfs

import "golang.org/x/sys/unix"

// unmountStale detaches a mount whose server is gone. MNT_DETACH is Linux's
// lazy unmount: the mountpoint becomes usable immediately and the kernel
// tears the old mount down once nothing references it any more. That matters
// here because the processes still holding the dead mount can never be served
// again, so waiting for them would mean waiting forever.
func unmountStale(dir string) error {
	return unix.Unmount(dir, unix.MNT_DETACH)
}
