package sshfwd

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/goodtune/dotvault/internal/observability"
)

// recordSSHForwardFailure is observability.RecordSSHForwardFailure indirected
// through a package-level var, mirroring the seam remote.go uses for its own
// Record* calls, so a test can substitute a spy.
var recordSSHForwardFailure = observability.RecordSSHForwardFailure

// ErrBind marks a failure to bind the remote Unix socket. The usual causes are
// AllowStreamLocalForwarding being off on the remote sshd, an unwritable
// parent directory, or a stale socket left by a crashed session.
var ErrBind = errors.New("bind remote socket failed")

// ErrSocketDir marks a failure to create the remote socket's parent
// directory. Kept distinct from ErrBind because the two need different
// answers from a human: ErrBind's causes are sshd policy or something
// already occupying the path, whereas this one is a directory that could not
// be created — an unwritable home, a read-only filesystem, or a path
// component that exists as a non-directory.
//
// It only ever reaches a caller alongside a bind failure, never on its own:
// creating the directory is best-effort (see ensureRemoteSocketDir), so a
// mkdir that fails on a host where the bind then succeeds is not an error at
// all. When both fail the returned error wraps this and ErrBind together, and
// Classify reports the socket-dir class — that is the one a human can act on.
var ErrSocketDir = errors.New("create remote socket directory failed")

// Dialer opens a connection to the local API surface the forward targets.
type Dialer func(ctx context.Context) (net.Conn, error)

// ServeForward binds socket on the remote and relays every accepted connection
// to target, returning when ctx is cancelled or the transport dies. host
// labels the forward-failure metric recorded for a target dial that fails
// mid-accept-loop (see serveListener) — it is otherwise unused here, so a
// caller with no meaningful host identity may pass "".
//
// A bind failure alone does not prove the path is stale. sshd's default
// StreamLocalBindUnlink=no makes bind() fail EADDRINUSE for *any* existing
// path entry — a stale socket left by a crashed session and a live socket a
// real `ssh -R` session is using right now are indistinguishable from the
// filesystem alone. So a bind failure triggers liveListenerAt, which decides
// whether the path is actually safe to reclaim — see its doc for the full
// rule, which is more subtle than "dial it and see" — and only when it says
// yes is the path unlinked, at most once, with one retry.
//
// The socket's parent directory is created first, best-effort (see
// ensureRemoteSocketDir and withSocketDirCause): the default remote_socket
// lives under ~/.ssh, which a fresh remote account need not have, and sshd
// cannot bind into a directory that does not exist — but a host that forbids
// command execution altogether forwarded perfectly well before dotvault ever
// ran a mkdir, and must keep doing so.
func ServeForward(ctx context.Context, cl *ssh.Client, host, socket string, target Dialer, onConn func(delta int)) error {
	dirErr := ensureRemoteSocketDir(ctx, cl, socket)
	fail := withSocketDirCause(dirErr)

	ln, err := cl.ListenUnix(socket)
	if err != nil {
		bindErr := err
		slog.Debug("remote socket bind failed; checking whether a live listener already owns it", "socket", socket, "error", bindErr)

		live, probeErr := liveListenerAt(ctx, cl, socket)
		if probeErr != nil {
			return fail(fmt.Errorf("%w: %s: %w (stale-socket probe was inconclusive: %v)", ErrBind, socket, bindErr, probeErr))
		}
		if live {
			// A successful direct-streamlocal dial proves something is
			// actively listening at this path right now. Unlinking here would
			// silently hijack that session — exactly the outcome this probe
			// exists to prevent.
			return fail(fmt.Errorf("%w: %s: %w (a live listener already owns this path)", ErrBind, socket, bindErr))
		}

		if rmErr := removeRemoteFile(ctx, cl, socket); rmErr != nil {
			return fail(fmt.Errorf("%w: %s: %w (stale-socket cleanup also failed: %v)", ErrBind, socket, bindErr, rmErr))
		}
		ln, err = cl.ListenUnix(socket)
		if err != nil {
			return fail(fmt.Errorf("%w: %s: %w", ErrBind, socket, err))
		}
		slog.Info("reclaimed stale remote socket", "socket", socket)
	}
	defer ln.Close()

	if dirErr != nil {
		// The bind is the only thing the directory was needed for, and it
		// worked: the directory already existed, or the remote refused the
		// mkdir for a reason (no exec channel, a non-POSIX shell) that has no
		// bearing on a forward that is now running. Nothing is wrong, so this
		// is not a warning.
		slog.Debug("creating the remote socket's parent directory failed, but the bind succeeded anyway",
			"host", host, "socket", socket, "error", dirErr)
	}

	return serveListener(ctx, ln, host, target, onConn)
}

// liveListenerAt reports whether something is actively listening at socket on
// the remote, by attempting a direct-streamlocal dial through the same SSH
// connection.
//
// A successful dial is conclusive on its own: something answered, so a live
// listener is running (the probe connection is closed immediately — this only
// asks the question, it never uses the answer).
//
// A rejection with ssh.ConnectionFailed is NOT conclusive on its own, despite
// looking like it should be. OpenSSH's server_input_channel_open initialises
// its rejection reason to SSH2_OPEN_CONNECT_FAILED and only its
// direct-tcpip handler ever overrides it — the direct-streamlocal handler
// never does — so "nobody is listening at this path" and
// "AllowStreamLocalForwarding disallows client-initiated direct-streamlocal
// entirely" are indistinguishable on the wire: both surface as
// ConnectionFailed. Treating it as proof would make a genuine `ssh -R`
// session's live socket, under AllowStreamLocalForwarding remote, read as
// stale and get unlinked out from under the user.
//
// So a ConnectionFailed on the real path only becomes trustworthy once
// directStreamLocalWorks confirms the mechanism itself functions against this
// sshd at all, via a differential probe against a path this call controls.
// Any other rejection reason (Prohibited, UnknownChannelType, ...) or a
// transport error is inconclusive on its own and must not be read as "safe to
// unlink" either.
func liveListenerAt(ctx context.Context, cl *ssh.Client, socket string) (live bool, err error) {
	conn, dialErr := cl.DialContext(ctx, "unix", socket)
	if dialErr == nil {
		conn.Close()
		return true, nil
	}
	var openErr *ssh.OpenChannelError
	if !errors.As(dialErr, &openErr) || openErr.Reason != ssh.ConnectionFailed {
		return false, dialErr
	}

	works, probeErr := directStreamLocalWorks(ctx, cl, socket)
	if probeErr != nil {
		return false, fmt.Errorf("could not confirm whether ConnectionFailed on %s is meaningful: %w", socket, probeErr)
	}
	if !works {
		return false, fmt.Errorf("sshd rejects client-initiated direct-streamlocal opens entirely, so ConnectionFailed on %s does not prove it is stale", socket)
	}
	return false, nil
}

// directStreamLocalWorks binds a scratch path this call alone controls,
// dials it, and reports whether the dial succeeded — i.e. whether
// client-initiated direct-streamlocal opens can reach a live listener on this
// sshd at all. If they cannot (any rejection, including a ConnectionFailed
// against a path we ourselves just bound), a ConnectionFailed on the real
// socket path proves nothing, and the caller must not unlink on its basis.
//
// The scratch listener is always torn down, on every path including a probe
// dial failure: this call owns that name, so a leftover is always safe to
// remove. A failure to *bind* the scratch path answers nothing either way —
// it is not treated as permission to trust the real probe's ConnectionFailed.
func directStreamLocalWorks(ctx context.Context, cl *ssh.Client, socket string) (bool, error) {
	scratch, err := scratchProbePath(socket)
	if err != nil {
		return false, fmt.Errorf("generate scratch probe path: %w", err)
	}

	ln, err := cl.ListenUnix(scratch)
	if err != nil {
		return false, fmt.Errorf("bind scratch probe path %s: %w", scratch, err)
	}
	defer func() {
		ln.Close()
		if rmErr := removeRemoteFile(ctx, cl, scratch); rmErr != nil {
			slog.Debug("failed to remove scratch probe socket", "socket", scratch, "error", rmErr)
		}
	}()

	conn, dialErr := cl.DialContext(ctx, "unix", scratch)
	if dialErr == nil {
		conn.Close()
		// Dialing our own scratch listener makes sshd connect to the socket it
		// is listening on for us, which in turn delivers a matching
		// forwarded-streamlocal@openssh.com channel-open back to this ln — a
		// second, independent notification of the same connection, mirroring
		// what a real peer's connection would deliver. If nothing ever calls
		// Accept on it, x/crypto leaves that channel-open permanently
		// unanswered (no confirmation or rejection is ever sent back to
		// sshd), so it must be drained before ln.Close() discards the queue.
		drainPendingForward(ln)
		return true, nil
	}
	var openErr *ssh.OpenChannelError
	if errors.As(dialErr, &openErr) {
		// A rejection dialing a path we just bound ourselves — including
		// ConnectionFailed — means client-initiated direct-streamlocal opens
		// don't work here at all, not that this particular path is unlucky.
		return false, nil
	}
	return false, dialErr
}

// drainPendingForwardTimeout bounds drainPendingForward's wait. The
// corresponding forwarded-streamlocal channel-open, when one arrives, is a
// round trip over the SSH connection we already have open — no new network
// hop — so it should arrive promptly; this is a safety bound against it
// never materialising, not a real budget.
const drainPendingForwardTimeout = 500 * time.Millisecond

// drainPendingForward accepts and immediately closes one pending connection
// on ln, if one is already waiting or arrives promptly. Bounded so a forward
// that (unexpectedly) never materialises cannot hang the caller; the
// subsequent ln.Close() discards anything still queued regardless.
func drainPendingForward(ln net.Listener) {
	done := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			done <- c
		} else {
			done <- nil
		}
	}()
	select {
	case c := <-done:
		if c != nil {
			c.Close()
		}
	case <-time.After(drainPendingForwardTimeout):
	}
}

// scratchProbePath derives a probe-only path from socket, in the same
// directory (so it exercises the same sshd policy and filesystem
// permissions) but with the basename replaced rather than suffixed: a
// suffixed name grows with the original basename's length, and a legitimate
// but already-long remote_socket could push the combined path over the
// sun_path budget (108 bytes on Linux, 104 on the BSDs) — turning a working
// stale-socket reclaim into a probe failure that blames the wrong thing. A
// replaced, fixed-length basename keeps the scratch path's length governed by
// the directory portion alone, the same as the original path. The random
// suffix is so concurrent probes (or a probe racing its own retry) don't
// collide.
func scratchProbePath(socket string) (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return path.Join(path.Dir(socket), fmt.Sprintf(".dotvault-probe-%x", suffix)), nil
}

// serveListener is the transport-agnostic accept loop, split out so it is
// testable without an SSH server. host labels dotvault.ssh.forward_failure_total
// (see the target-dial-failure branch below) — it carries no other meaning
// here, so a caller with nothing meaningful to label with may pass "".
func serveListener(ctx context.Context, ln net.Listener, host string, target Dialer, onConn func(delta int)) error {
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
				slog.Warn("forward target dial failed", "host", host, "error", err)
				recordSSHForwardFailure(ctx, host)
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
//
// closeAll runs exactly once, at cancel. Without the closed flag, a
// connection registered *after* that moment — the narrow window between
// Accept returning and add(conn), or the wide window spanning the whole
// target dial, where conn is tracked but local is only added once the dial
// returns — would never be closed by anyone: Pump only returns once both
// directions EOF, so serveListener's deferred wg.Wait() would block forever,
// taking ServeForward, the caller's reconnect, and shutdown down with it.
// Recording closed under the same lock and having add close-on-arrival once
// it is set collapses both windows without serveListener needing to depend on
// target's own ctx-awareness for its shutdown guarantee.
type connTracker struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[net.Conn]struct{})}
}

func (t *connTracker) add(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		_ = c.Close()
		return
	}
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
	t.closed = true
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

// remoteSocketDirCommand is the shell command ensureRemoteSocketDir runs to
// create dir. Split out so a test can exercise the exact command against a
// real POSIX mkdir rather than restating the flags it hopes are there.
//
// mkdir -p is deliberately the whole operation. It succeeds when the
// directory already exists, which is the required behaviour on every run
// after the first, and it creates missing intermediate components. The mode
// is only ever applied to directories mkdir itself creates — POSIX defines
// -m as applying to the final directory operand as created, and mkdir -p
// short-circuits before that when the operand already exists — so a user's
// deliberate permissions on an existing ~/.ssh are left untouched. 0700 is
// the right mode to *create* it with: that directory conventionally holds
// private keys, so anything wider would be poor hygiene, and a socket
// dotvault forwards Vault tokens over does not want a group- or
// world-traversable parent either.
//
// The known gap, stated rather than papered over: POSIX applies -m to the
// final operand only, so intermediate directories -p creates get the remote
// account's umask instead. That is invisible for the default
// ~/.ssh/dotvault.sock (whose parent is the final operand), but a nested
// remote_socket such as ~/a/b/c.sock can leave ~/a group- or
// world-traversable. Closing it would mean a second command chmod'ing each
// component, which would then also have to decide what to do about
// components the user created deliberately — a worse trade than documenting
// it, so an operator who cares about a nested path should create and mode
// the intermediates themselves.
func remoteSocketDirCommand(dir string) string {
	return "mkdir -p -m 700 -- " + shellQuote(dir)
}

// ensureRemoteSocketDir creates the parent directory of remotePath on the
// remote, over an exec channel, before anything tries to bind there. sshd's
// bind() cannot create the directory itself, and the *default* remote_socket
// (~/.ssh/dotvault.sock) sits in a directory a freshly provisioned account
// need not have — so without this the out-of-the-box configuration fails, and
// fails misleadingly: ServeForward's bind-failure path reads any failure as a
// possibly-stale socket and reports a stale-socket cleanup error for what is
// simply an absent directory.
//
// It is best-effort, and its error must never on its own fail a forward. An
// absolute remote_socket needed no exec channel at all before this existed
// (see ExpandRemotePath, which only probes for a "~/" prefix, and for the
// same reason), so a remote that permits streamlocal forwarding but not
// command execution — an authorized_keys command= restriction, ForceCommand,
// a restricted shell, a Windows OpenSSH account whose shell is cmd.exe —
// worked perfectly well and must keep working. Callers therefore retain this
// error, attempt the bind regardless, and only surface it if the bind then
// fails too (withSocketDirCause), where it is the actionable root cause.
//
// The parent is derived with path.Dir, not filepath.Dir: remotePath names a
// location on the remote, which is POSIX regardless of the OS this daemon
// runs on, so a Windows daemon must not split it on backslashes. remotePath
// has already been through ExpandRemotePath, so it is absolute and any "~/"
// prefix is gone.
func ensureRemoteSocketDir(ctx context.Context, cl *ssh.Client, remotePath string) error {
	dir := path.Dir(remotePath)
	if _, err := (sshRunner{cl: cl}).Run(ctx, remoteSocketDirCommand(dir)); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSocketDir, dir, err)
	}
	return nil
}

// withSocketDirCause returns a decorator for a bind failure that folds in
// dirErr, the earlier best-effort ensureRemoteSocketDir failure, when there
// was one. A mkdir that failed on a host where the bind then succeeded is not
// an error at all; a mkdir that failed on a host where the bind then failed
// is very likely *why* it failed, and is the half a human can act on — so it
// has to be visible in the message rather than swallowed. The two are joined
// with a double %w so errors.Is finds both ErrSocketDir and ErrBind, and
// Classify (state.go) reports the socket-dir class in preference.
func withSocketDirCause(dirErr error) func(error) error {
	if dirErr == nil {
		return func(err error) error { return err }
	}
	return func(err error) error {
		return fmt.Errorf("%w (creating the socket's parent directory failed first, which is the likely cause: %w)", err, dirErr)
	}
}

// removeRemoteFile unlinks path on the remote over an exec channel, guarded
// on the remote actually being a socket. Only ever called with the exact
// configured socket path, and only once liveListenerAt has already proven
// nothing is listening there — the guard here is a second, independent line
// of defence against deleting the wrong kind of file: a remote_socket that
// (via typo or a stale config edit) happens to name an existing regular file
// must never be silently destroyed. If path exists and is not a socket the
// whole command fails and the caller treats this as an ordinary bind failure
// rather than retrying against a file it just deleted.
//
// A path that is already absent is success, not failure: sshd itself
// typically unlinks a streamlocal forward's socket when the client cancels it
// (Close), so by the time a caller gets here to clean up a scratch probe path
// it has often already vanished — and callers should not report that as
// "cleanup failed" (see directStreamLocalWorks, whose deferred cleanup would
// otherwise log an error on every successful probe).
func removeRemoteFile(ctx context.Context, cl *ssh.Client, remotePath string) error {
	sess, err := cl.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	q := shellQuote(remotePath)
	cmd := "[ -e " + q + " ] || exit 0; [ -S " + q + " ] && rm -f -- " + q

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("rm -f %s: %w", remotePath, err)
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
// ExpandRemotePath (home.go) can resolve a "~/" remote_socket prefix, and
// serving ensureRemoteSocketDir's mkdir as well.
//
// Stderr is captured and folded into the returned error. Without it every
// remote failure collapses to the exit status — "Process exited with status
// 1" says nothing about whether the home is unwritable, the filesystem is
// read-only, or a path component exists as a file, and the remote already
// wrote exactly that distinction to stderr.
type sshRunner struct{ cl *ssh.Client }

func (r sshRunner) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := r.cl.NewSession()
	if err != nil {
		return "", fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	var stderr bytes.Buffer
	sess.Stderr = &stderr

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
		// Deliberately does not touch stderr: the session goroutine may still
		// be writing into it, and there is nothing to report anyway.
		return "", ctx.Err()
	case res := <-done:
		if res.err != nil {
			// Safe to read now: Output has returned, so nothing is still
			// writing to the buffer.
			return "", fmt.Errorf("run %q: %w%s", cmd, res.err, stderrDetail(stderr.String()))
		}
		return string(res.out), nil
	}
}

// stderrDetailLimit bounds how much remote stderr is quoted into an error. A
// remote can emit arbitrarily much (a shell startup file gone wrong, a
// banner); the first line or two is where the cause is.
const stderrDetailLimit = 200

// stderrDetail renders remote stderr as a parenthesised suffix for an error
// message, or "" when the remote said nothing. Control characters — newlines
// included, but equally the terminal escapes a remote is perfectly capable of
// emitting into a message this daemon will log — are folded to spaces, and
// the result is capped: this is a diagnostic hint, not a transcript.
func stderrDetail(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	if runes := []rune(s); len(runes) > stderrDetailLimit {
		s = string(runes[:stderrDetailLimit]) + "…"
	}
	return " (stderr: " + s + ")"
}
