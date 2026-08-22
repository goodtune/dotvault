// Package sockettest supplies a temporary directory short enough to hold a Unix
// socket path.
//
// t.TempDir() is unusable for sockets on macOS. A Unix socket address is capped
// by sun_path — 104 bytes on Darwin, 108 on Linux — and macOS puts TMPDIR under
// /var/folders/<2>/<30-odd chars>/T/, so t.TempDir() plus the test's own name
// and a filename lands around 106-112 bytes and bind(2) fails with "invalid
// argument".
//
// The failure is a function of how long the *test name* is, which makes it
// worse than a plain platform gap: renaming a passing test can break it, and
// the suite stays green on Linux CI the whole time. Four packages hit this
// independently (agent, auth, uds, web) and two had grown their own private
// helper, which is why this one is importable rather than copied a fifth time.
//
// Binding under /tmp keeps the whole path near 30 bytes. Windows has no
// sun_path limit and its named pipes are not filesystem paths at all, so there
// Dir is just t.TempDir(); the package is deliberately not build-tagged, so
// that tests which compile everywhere and skip at runtime can use it too.
package sockettest

import (
	"os"
	"runtime"
	"testing"
)

// Dir returns a directory short enough to bind a Unix socket in, registering
// its removal with t.Cleanup.
func Dir(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp("/tmp", "dv")
	if err != nil {
		t.Fatalf("create short temp dir for socket: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
