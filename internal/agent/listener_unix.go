//go:build !windows

package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// umaskMu serialises the umask swap around bind so a concurrent file write
// elsewhere in the daemon can't observe (or be created under) the temporary
// 0177 mask. The window is a single Listen call.
var umaskMu sync.Mutex

// platformListen creates the Unix domain socket with 0600 permissions and a
// 0700 parent directory. A stale socket left by an unclean shutdown is removed
// first — but only after confirming no live instance answers on it, so a
// second daemon cannot clobber a running one's socket.
func (l *Listener) platformListen() (net.Listener, error) {
	path := l.addr

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create agent socket dir %s: %w", dir, err)
	}
	// Tighten the directory in case it pre-existed with looser bits.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod agent socket dir %s: %w", dir, err)
	}

	if _, err := os.Stat(path); err == nil {
		// Something is at the path. If a connect succeeds a live instance
		// owns it — refuse to clobber. Otherwise it's a stale socket from an
		// unclean shutdown; remove it.
		if c, derr := net.DialTimeout("unix", path, 200*time.Millisecond); derr == nil {
			c.Close()
			return nil, fmt.Errorf("dotvault agent already running at %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale agent socket %s: %w", path, err)
		}
	}

	// Bind under a 0177 umask so the socket is created 0600 with no window at
	// looser permissions, then chmod as belt-and-braces (some platforms apply
	// the umask differently to AF_UNIX nodes).
	umaskMu.Lock()
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod agent socket %s: %w", path, err)
	}
	return ln, nil
}

// platformCleanup removes the socket file. net.UnixListener.Close already
// unlinks it in the common case; this is a best-effort backstop for paths it
// doesn't (e.g. a bind that failed after creating the node).
func (l *Listener) platformCleanup() {
	_ = os.Remove(l.addr)
}
