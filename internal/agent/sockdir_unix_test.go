//go:build !windows

package agent

import (
	"os"
	"testing"
)

// sockTempDir returns a directory short enough to hold a Unix socket path.
//
// t.TempDir() is unusable for sockets on macOS. A Unix socket address is capped
// by sun_path — 104 bytes on Darwin, 108 on Linux — and macOS puts TMPDIR under
// /var/folders/<2>/<30-odd chars>/T/, so t.TempDir() plus the test name and a
// filename lands around 107 bytes and bind(2) fails with "invalid argument".
// The result is a suite that passes on Linux CI and fails on every developer
// Mac, which is exactly what had been happening here.
//
// Binding under /tmp keeps the whole path near 30 bytes. This file is
// !windows, so /tmp is always present; on macOS it is a symlink to /private/tmp
// which bind resolves.
func sockTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dv")
	if err != nil {
		t.Fatalf("create short temp dir for socket: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
