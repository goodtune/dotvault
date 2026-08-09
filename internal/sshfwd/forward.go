package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ErrBind marks a failure to bind the remote Unix socket. The usual causes are
// AllowStreamLocalForwarding being off on the remote sshd, an unwritable
// parent directory, or a stale socket left by a crashed session.
var ErrBind = errors.New("bind remote socket failed")

// Dialer opens a connection to the local API surface the forward targets.
type Dialer func(ctx context.Context) (net.Conn, error)

// ServeForward binds socket on the remote and relays every accepted connection
// to target, returning when ctx is cancelled or the transport dies.
//
// A bind failure alone does not prove the path is stale. sshd's default
// StreamLocalBindUnlink=no makes bind() fail EADDRINUSE for *any* existing
// path entry — a stale socket left by a crashed session and a live socket a
// real `ssh -R` session is using right now are indistinguishable from the
// filesystem alone. So a bind failure triggers liveListenerAt, which answers
// the actual question by dialing through the connection: only a path sshd
// proves nothing is listening on (ConnectionFailed) is treated as stale, and
// only then is it unlinked — at most once, with one retry.
func ServeForward(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(delta int)) error {
	ln, err := cl.ListenUnix(socket)
	if err != nil {
		bindErr := err
		slog.Debug("remote socket bind failed; checking whether a live listener already owns it", "socket", socket, "error", bindErr)

		live, probeErr := liveListenerAt(cl, socket)
		if probeErr != nil {
			return fmt.Errorf("%w: %s: %w (stale-socket probe was inconclusive: %v)", ErrBind, socket, bindErr, probeErr)
		}
		if live {
			// A successful direct-streamlocal dial proves something is
			// actively listening at this path right now. Unlinking here would
			// silently hijack that session — exactly the outcome this probe
			// exists to prevent.
			return fmt.Errorf("%w: %s: %w (a live listener already owns this path)", ErrBind, socket, bindErr)
		}

		if rmErr := removeRemoteFile(ctx, cl, socket); rmErr != nil {
			return fmt.Errorf("%w: %s: %w (stale-socket cleanup also failed: %v)", ErrBind, socket, bindErr, rmErr)
		}
		ln, err = cl.ListenUnix(socket)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrBind, socket, err)
		}
		slog.Info("reclaimed stale remote socket", "socket", socket)
	}
	defer ln.Close()

	return serveListener(ctx, ln, target, onConn)
}

// liveListenerAt reports whether something is actively listening at socket on
// the remote, by attempting a direct-streamlocal dial through the same SSH
// connection. Two outcomes are conclusive:
//
//   - The dial succeeds: something answered the connection. That alone is
//     proof of a live listener (the probe connection is closed immediately —
//     this only asks the question, it never uses the answer).
//   - sshd rejects the channel open with ssh.ConnectionFailed: sshd itself
//     tried to connect() to the path on our behalf and got refused, meaning
//     nothing is listening. The path is safe to treat as stale.
//
// Any other outcome — a different rejection reason (e.g. Prohibited, which is
// what an sshd with AllowStreamLocalForwarding disallowing client-initiated
// direct-streamlocal returns) or a transport error — is inconclusive and must
// not be read as "safe to unlink": ConnectionFailed is the only reason that
// specifically means "I tried to connect and there was nobody there".
func liveListenerAt(cl *ssh.Client, socket string) (live bool, err error) {
	conn, dialErr := cl.Dial("unix", socket)
	if dialErr == nil {
		conn.Close()
		return true, nil
	}
	var openErr *ssh.OpenChannelError
	if errors.As(dialErr, &openErr) && openErr.Reason == ssh.ConnectionFailed {
		return false, nil
	}
	return false, dialErr
}

// serveListener is the transport-agnostic accept loop, split out so it is
// testable without an SSH server.
func serveListener(ctx context.Context, ln net.Listener, target Dialer, onConn func(delta int)) error {
	if onConn == nil {
		onConn = func(int) {}
	}

	tracker := newConnTracker()

	// The watcher's own done channel — closed when serveListener returns for
	// any reason, not only ctx cancellation — releases the goroutine on every
	// path. Without it, a return caused by Accept failing on its own (a dead
	// transport, sshd restarting) leaves the watcher parked on <-ctx.Done()
	// forever: one leaked goroutine per reconnect, on a daemon that
	// reconnects across every sleep/wake for months.
	watcherDone := make(chan struct{})
	defer close(watcherDone)
	go func() {
		select {
		case <-ctx.Done():
			// Cancellation must not leave in-flight relays open indefinitely:
			// Pump only returns once both directions have EOF'd, so one
			// idle-but-open peer would otherwise hold this function — and the
			// caller's shutdown — open forever.
			ln.Close()
			tracker.closeAll()
		case <-watcherDone:
		}
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept on remote socket: %w", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			onConn(1)
			defer onConn(-1)

			tracker.add(conn)
			defer tracker.remove(conn)

			local, err := target(ctx)
			if err != nil {
				// The local API surface being momentarily unavailable must not
				// stop the accept loop: the forward outlives any one request.
				slog.Warn("forward target dial failed", "error", err)
				conn.Close()
				return
			}
			tracker.add(local)
			defer tracker.remove(local)

			Pump(conn, local)
		}()
	}
}

// connTracker tracks the connections currently being relayed so they can be
// force-closed on cancellation instead of waiting for both directions to
// reach EOF on their own.
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[net.Conn]struct{})}
}

func (t *connTracker) add(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[c] = struct{}{}
}

func (t *connTracker) remove(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, c)
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c := range t.conns {
		_ = c.Close()
	}
}

// Pump relays bytes in both directions until either side ends, then closes
// both. Half-close is attempted where the transport supports it (CloseWrite),
// so a client that shuts down its write side gets the response it is waiting
// for rather than a truncated stream.
//
// The trailing Close calls are load-bearing, not redundant with copyDir's own
// fallback: a connection type that implements CloseWrite (a real TCP or Unix
// socket, or x/crypto's forwarded-channel conn) never reaches copyDir's
// dst.Close() fallback branch at all, since CloseWrite only half-closes the
// write side. Without the trailing closes, a CloseWrite-capable connection
// pair is fully readable-but-idle after Pump returns and both ends leak.
//
// Payload bytes are never logged: the forwarded stream carries Vault tokens.
func Pump(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		dst.Close()
	}

	go copyDir(a, b)
	go copyDir(b, a)
	wg.Wait()

	a.Close()
	b.Close()
}

// removeRemoteFile unlinks path on the remote over an exec channel, guarded
// on the remote actually being a socket. Only ever called with the exact
// configured socket path, and only once liveListenerAt has already proven
// nothing is listening there — the guard here is a second, independent line
// of defence against deleting the wrong kind of file: a remote_socket that
// (via typo or a stale config edit) happens to name an existing regular file
// must never be silently destroyed. If path is not a socket the whole command
// fails and the caller treats this as an ordinary bind failure rather than
// retrying against a file it just deleted.
func removeRemoteFile(ctx context.Context, cl *ssh.Client, path string) error {
	sess, err := cl.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	q := shellQuote(path)
	cmd := "[ -S " + q + " ] && rm -f -- " + q

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("rm -f %s: %w", path, err)
		}
		return nil
	}
}

// shellQuote single-quotes s for a POSIX shell. remote_socket is validated
// upstream (no NUL, no ".." segments, no control characters in the expanded
// result), but it still reaches a shell via rm -f, so it is quoted here
// rather than trusted.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sshRunner runs a command over an SSH session, satisfying CommandRunner so
// ExpandRemotePath (home.go) can resolve a "~/" remote_socket prefix.
type sshRunner struct{ cl *ssh.Client }

func (r sshRunner) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := r.cl.NewSession()
	if err != nil {
		return "", fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.Output(cmd)
		done <- result{out, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return "", fmt.Errorf("run %q: %w", cmd, r.err)
		}
		return string(r.out), nil
	}
}
