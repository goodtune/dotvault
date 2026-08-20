//go:build darwin || freebsd

package vaultfs

import (
	"bytes"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// IsMounted reports whether dir is currently a FUSE mount. See the Linux
// build for why the check is by filesystem type rather than by asking the
// daemon.
//
// The BSDs report a filesystem type name rather than a magic number, and the
// name varies by implementation: macFUSE mounts as "macfuse" (and, on older
// releases, "osxfuse"), while FreeBSD's in-kernel FUSE reports "fusefs".
func IsMounted(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		if errors.Is(err, unix.ENOTCONN) {
			return true, nil
		}
		return false, err
	}
	name := fsTypeName(st.Fstypename[:])
	return strings.Contains(name, "fuse"), nil
}

// fsTypeName turns the NUL-padded character array statfs returns into a
// string.
func fsTypeName(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(string(raw))
}
