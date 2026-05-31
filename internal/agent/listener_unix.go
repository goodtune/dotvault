//go:build !windows

package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// dialEndpoint connects to an existing agent endpoint as a client. It never
// creates the socket — `dotvault status` must observe the running daemon, not
// stand up a competing listener.
func dialEndpoint(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

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

	// Bind, then immediately tighten the socket to 0600. We deliberately do not
	// touch the process-global umask (syscall.Umask): it would apply to every
	// file any other daemon goroutine creates during the bind window — the sync
	// engine writing a managed file, the state store saving — giving them
	// unexpectedly tight modes. The brief moment the socket itself sits at the
	// default-umask mode before the chmod is closed by the 0700 parent dir
	// created above: no other user can traverse into it to reach the socket,
	// whatever the socket's own bits are.
	ln, err := net.Listen("unix", path)
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
