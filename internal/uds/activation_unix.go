//go:build !windows

package uds

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// adoptActivated turns a retained master file into a usable Unix listener,
// enforcing the invariants dotvault normally establishes at bind time. The
// master is never closed — it lives for the process so the same name can be
// claimed again after a listener restart; net.FileListener dups it, and the
// returned listener owns only the dup.
//
// This is the "verify what we are handed" half of delegating the bind to
// systemd, and it checks the objects that actually gate access:
//
//   - The socket *node's* mode — what SocketMode= sets and what the kernel
//     consults on connect(); fstat on the fd itself reports 0777 for every
//     socket and proves nothing. SocketMode defaults to 0666, so a
//     hand-written unit that omits it would silently hand the token
//     endpoint (or the signing agent) to every uid on the box.
//   - The *parent directory's* mode and ownership — the half of the
//     0600-in-0700 invariant a node check alone misses. A socket in a
//     directory another user can write to can be unlinked and replaced with
//     an impostor socket that passes every node check, feeding borrowers a
//     hostile "token"; self-bind closes this by creating the parent 0700,
//     and activation must refuse what self-bind would never produce.
//   - Ownership of both by our own uid, for the same substitution reason.
//
// Stat-ing paths the fd reported is unavoidably a fresh lookup rather than
// an fstat, but the property being verified — nobody else may write the
// parent — is exactly the property that makes the path stable between
// systemd's bind and our check.
//
// A refusal closes only the dup'd listener; FileListener-derived
// UnixListeners have unlink-on-close disabled, so systemd's node survives
// our rejection of it.
func adoptActivated(name string, master *os.File) (net.Listener, string, error) {
	// FileListener also rejects non-socket fds, covering the plain-file
	// misconfiguration case.
	ln, err := net.FileListener(master)
	if err != nil {
		return nil, "", fmt.Errorf("adopt activated fd %q: %w", name, err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		ln.Close()
		return nil, "", fmt.Errorf("activated socket %q is %s, not a unix stream socket — dotvault sockets must be ListenStream= on a filesystem path (a port would silently turn an owner-only socket into a network service)", name, ln.Addr().Network())
	}
	path := ul.Addr().String()

	// Abstract-namespace sockets (ListenStream=@name) have no filesystem
	// node and therefore no file permissions at all — on Linux any process
	// in the namespace may connect. That can never satisfy the owner-only
	// invariant, so refuse it by design rather than by the stat below
	// happening to fail.
	if strings.HasPrefix(path, "@") {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q is in the abstract namespace (%s); abstract sockets have no file permissions and cannot be owner-only — use a filesystem path", name, path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		ul.Close()
		return nil, "", fmt.Errorf("stat activated socket %q at %s: %w", name, path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q: %s is not a socket node", name, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q at %s has mode %04o; refusing anything wider than 0600 — set SocketMode=0600 in the socket unit", name, path, perm)
	}
	if !ownedByCurrentUser(fi) {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q at %s is not owned by uid %d", name, path, os.Getuid())
	}

	dir := filepath.Dir(path)
	dfi, err := os.Stat(dir)
	if err != nil {
		ul.Close()
		return nil, "", fmt.Errorf("stat activated socket %q parent %s: %w", name, dir, err)
	}
	if !dfi.IsDir() {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q parent %s is not a directory", name, dir)
	}
	if perm := dfi.Mode().Perm(); perm&0o077 != 0 {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q parent %s has mode %04o; refusing anything wider than 0700 — set DirectoryMode=0700 in the socket unit", name, dir, perm)
	}
	if !ownedByCurrentUser(dfi) {
		ul.Close()
		return nil, "", fmt.Errorf("activated socket %q parent %s is not owned by uid %d", name, dir, os.Getuid())
	}

	return ul, path, nil
}

// ownedByCurrentUser reports whether fi's underlying inode belongs to our
// uid. A false on an unexpected Sys() type is deliberate — when ownership
// cannot be established the refusal side of the invariant wins.
func ownedByCurrentUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Getuid()
}

// drainListener accepts and immediately closes connections until the
// listener dies. It backs the unclaimed-fd housekeeping: systemd retains
// its own copy of the listening fd, so merely closing *our* dup does not
// refuse anyone — clients would still connect into a backlog nobody
// accepts and hang there. Draining is the honest refusal available to us:
// each client connects, is closed at once, and fails fast with EOF.
func drainListener(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}
