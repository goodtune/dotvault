//go:build !windows

package uds

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
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
	// AF_UNIX addresses are a fixed-size sun_path field — 104 bytes on the
	// BSDs/macOS, 108 on Linux — and the kernel reports an over-long path as
	// a bare EINVAL, which surfaces as "listen unix …: invalid argument" and
	// tells the operator nothing about what to change. Check it here so a
	// long custom api.unix.path names its own problem. Use the smaller limit
	// everywhere: a path that fails on macOS is worth rejecting on Linux too
	// rather than having one config work on some of a fleet.
	const maxSocketPath = 104
	if len(path) >= maxSocketPath {
		return nil, fmt.Errorf("socket path %s is %d bytes; the operating system limit for a unix socket is %d", path, len(path), maxSocketPath-1)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
	}
	// Tighten the directory in case it pre-existed with looser bits.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod socket dir %s: %w", dir, err)
	}

	// The probe-remove-bind-chmod sequence below must be atomic with respect
	// to other dotvault processes — see withBindLock.
	return withBindLock(path, func() (net.Listener, error) {
		if _, err := os.Stat(path); err == nil {
			// Something is at the path. If a connect succeeds a live instance
			// owns it — refuse to clobber. Otherwise it's a stale socket from
			// an unclean shutdown; remove it.
			if c, derr := net.DialTimeout("unix", path, liveProbeTimeout); derr == nil {
				c.Close()
				return nil, fmt.Errorf("%w: %s", ErrAlreadyListening, path)
			}
			if err := removeStale(path); err != nil {
				return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
			}
		}

		ln, err := net.Listen("unix", path)
		if err != nil {
			// Can't happen while we hold the bind lock, but a foreign process
			// binding the path would land here: report it in the vocabulary
			// callers already handle rather than as a raw bind error, which
			// reads like a bug in dotvault rather than a second instance.
			if errors.Is(err, syscall.EADDRINUSE) {
				return nil, fmt.Errorf("%w: %s", ErrAlreadyListening, path)
			}
			return nil, fmt.Errorf("listen unix %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			ln.Close()
			return nil, fmt.Errorf("chmod socket %s: %w", path, err)
		}
		return ln, nil
	})
}

// bindLockSuffix names the advisory lock file that serialises binding, kept
// beside the socket inside the same 0700 directory.
const bindLockSuffix = ".lock"

// withBindLock runs fn holding an exclusive advisory lock on a file beside the
// socket, so only one process at a time may run the probe-remove-bind
// sequence.
//
// Without it, two processes starting concurrently against the same stale path
// can both get past the liveness probe, and then the loser unlinks the
// *winner's* freshly-bound socket and binds its own on top. Both believe they
// succeeded; the winner serves an inode no client can reach. That is the same
// silent failure the already-running check exists to prevent, arriving by a
// different route — and it is reproducible, not theoretical (see
// TestConcurrentListenYieldsOneWinner, which fails without this lock).
//
// The lock is held only across the bind, not for the listener's lifetime: once
// the socket is bound it is itself the evidence a live instance owns the path,
// which is what the liveness probe reads. The lock file is deliberately never
// unlinked — removing a file other processes hold flocked is the classic way
// to end up with two "holders" of the same lock — so it persists as an empty
// 0600 file beside the socket. flock is released by the kernel if the holder
// dies, so a crashed daemon cannot wedge the next start.
func withBindLock(path string, fn func() (net.Listener, error)) (net.Listener, error) {
	lockFile := path + bindLockSuffix
	lf, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open bind lock %s: %w", lockFile, err)
	}
	defer lf.Close()

	// Blocking: the critical section is our own bounded work (a probe capped
	// at liveProbeTimeout, plus a bind), and the kernel releases the lock if
	// the holder dies, so waiting cannot hang on a dead process.
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("acquire bind lock %s: %w", lockFile, err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	return fn()
}

// removeStale unlinks a socket node that no live instance answered on,
// treating "already gone" as success.
//
// Two processes starting concurrently against the same stale path can both
// get past the liveness probe, and only one of them gets to do the removal;
// the loser would otherwise fail startup with a confusing ENOENT about a node
// it was trying to delete anyway. The goal is that the path is clear, not
// that we personally cleared it.
func removeStale(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
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
