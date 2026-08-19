//go:build linux

package vaultfs

import "golang.org/x/sys/unix"

// fuseSuperMagic identifies a FUSE filesystem in statfs(2)'s f_type. Defined
// here rather than taken from x/sys/unix so the constant does not depend on
// which release of that module is vendored.
const fuseSuperMagic = 0x65735546

// IsMounted reports whether dir is currently a FUSE mount.
//
// It exists for `dotvault status`, which runs as a separate process and so
// cannot ask the daemon's Service for its state. Checking the filesystem type
// is the honest answer to "is something mounted here": it does not confirm
// that the mount is *this* daemon's, but there is no other FUSE mount a user
// would plausibly have on dotvault's own mountpoint, and the alternative —
// asking the daemon over its API — would report nothing at all when the
// daemon is down, which is exactly when the question is being asked.
func IsMounted(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		// ENOTCONN is a mount whose server died: something is mounted, and
		// saying so is what lets status explain a mountpoint that reports
		// "Transport endpoint is not connected".
		if err == unix.ENOTCONN {
			return true, nil
		}
		return false, err
	}
	return st.Type == fuseSuperMagic, nil
}
