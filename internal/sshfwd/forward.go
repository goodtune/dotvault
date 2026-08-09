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
// Bind ordering is load-bearing. x/crypto/ssh does not unlink a stale socket
// and sshd will not bind over one, so a leftover file from a crashed session
// would block the forward forever. But unlinking pre-emptively — the effect of
// OpenSSH's StreamLocalBindUnlink=yes — would destroy a *live* socket owned by
// a real `ssh -R` session the user is currently using. So: bind first, and
// only on failure unlink once and retry once.
func ServeForward(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(delta int)) error {
	ln, err := cl.ListenUnix(socket)
	if err != nil {
		slog.Debug("remote socket bind failed; attempting stale-socket cleanup", "socket", socket, "error", err)
		if rmErr := removeRemoteFile(ctx, cl, socket); rmErr != nil {
			return fmt.Errorf("%w: %s: %w (cleanup also failed: %v)", ErrBind, socket, err, rmErr)
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

// serveListener is the transport-agnostic accept loop, split out so it is
// testable without an SSH server.
func serveListener(ctx context.Context, ln net.Listener, target Dialer, onConn func(delta int)) error {
	go func() {
		<-ctx.Done()
		ln.Close()
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

			local, err := target(ctx)
			if err != nil {
				// The local API surface being momentarily unavailable must not
				// stop the accept loop: the forward outlives any one request.
				slog.Warn("forward target dial failed", "error", err)
				conn.Close()
				return
			}
			Pump(conn, local)
		}()
	}
}

// Pump relays bytes in both directions until either side ends, then closes
// both. Half-close is attempted where the transport supports it (CloseWrite),
// so a client that shuts down its write side gets the response it is waiting
// for rather than a truncated stream.
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

// removeRemoteFile unlinks a path on the remote over an exec channel. Only
// ever called with the exact configured socket path, and only after a bind
// failure has already proven nothing usable is listening there.
func removeRemoteFile(ctx context.Context, cl *ssh.Client, path string) error {
	sess, err := cl.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	done := make(chan error, 1)
	go func() { done <- sess.Run("rm -f -- " + shellQuote(path)) }()

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
