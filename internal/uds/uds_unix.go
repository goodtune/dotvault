//go:build !windows

package uds

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// liveProbeTimeout bounds the "is someone already serving here?" dial. The
// peer is a local socket, so a healthy listener accepts effectively
// instantly; the timeout only caps the pathological case where the socket
// node exists but the owning process is wedged.
const liveProbeTimeout = 200 * time.Millisecond

// Listen creates a Unix domain socket at path with 0600 permissions inside a
// 0700 parent directory, creating the directory if needed.
//
// A socket left behind by an unclean shutdown is removed first — but only
// after confirming no live instance answers on it, so a second daemon can
// never clobber a running one's socket. When one does answer, Listen returns
// an error wrapping ErrAlreadyListening so callers can report it in their own
// vocabulary.
//
// Permissions are a hard invariant, not a nicety: whoever can connect can
// borrow the Vault token (API socket) or have the agent sign for them. The
// bind is followed immediately by an explicit chmod rather than a
// process-global umask swap (syscall.Umask), which would apply to every file
// any other daemon goroutine creates during the bind window — the sync engine
// writing a managed file, the state store saving — giving them unexpectedly
// tight modes. The brief moment the socket sits at the default-umask mode
// before the chmod lands is closed by the 0700 parent: no other user can
// traverse into it to reach the socket, whatever the socket's own bits are.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
	}
	// Tighten the directory in case it pre-existed with looser bits.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod socket dir %s: %w", dir, err)
	}

	if _, err := os.Stat(path); err == nil {
		// Something is at the path. If a connect succeeds a live instance
		// owns it — refuse to clobber. Otherwise it's a stale socket from an
		// unclean shutdown; remove it.
		if c, derr := net.DialTimeout("unix", path, liveProbeTimeout); derr == nil {
			c.Close()
			return nil, fmt.Errorf("%w: %s", ErrAlreadyListening, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return ln, nil
}

// Cleanup removes the socket file. net.UnixListener.Close already unlinks it
// in the common case; this is a best-effort backstop for the paths it doesn't
// cover (e.g. a bind that failed after creating the node).
func Cleanup(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
}
