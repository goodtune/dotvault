package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrAuth marks an SSH authentication failure. x/crypto/ssh returns a plain
// error for this, so it is wrapped here to keep Classify free of string
// matching against a message that is not part of any API contract.
var ErrAuth = errors.New("ssh authentication failed")

// ErrHandshake marks a transport or handshake failure that is neither auth nor
// host key.
var ErrHandshake = errors.New("ssh handshake failed")

// DialConfig is everything needed to establish one SSH transport.
type DialConfig struct {
	Host    string
	Port    int
	User    string
	Signers []ssh.Signer
	HostKey *HostKeyPolicy

	// Observed receives the presented host key even when the dial is rejected,
	// so `dotvault ssh add` can report a fingerprint to confirm. May be nil.
	//
	// x/crypto invokes the HostKeyCallback on every key exchange, including a
	// server-initiated rekey, not just the initial handshake — so *Observed is
	// written by the transport's own goroutine for the life of the connection.
	// Safe for the short-lived dial `ssh add` performs to fetch a fingerprint;
	// a caller that holds a long-lived *ssh.Client and reads Observed later
	// races with that goroutine.
	Observed *ssh.PublicKey

	Timeout time.Duration
}

// DefaultDialTimeout bounds a single connection attempt. Long enough for a
// slow VPN handshake, short enough that a black-holed route does not hold a
// reconnect slot open for the OS TCP timeout.
const DefaultDialTimeout = 20 * time.Second

// Dial establishes an SSH transport. Every failure is wrapped in a sentinel so
// the caller can classify it without inspecting messages.
func Dial(ctx context.Context, c DialConfig) (*ssh.Client, error) {
	if len(c.Signers) == 0 {
		return nil, fmt.Errorf("%w: no SSH identities available from the agent backend", ErrAuth)
	}
	if c.HostKey == nil {
		// c.HostKey.Callback below would otherwise panic inside x/crypto's own
		// handshake goroutine — a process crash rather than a returned error.
		return nil, fmt.Errorf("%w: no host key policy configured", ErrHandshake)
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultDialTimeout
	}
	port := c.Port
	if port == 0 {
		port = DefaultPort
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))

	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(c.Signers...)},
		HostKeyCallback: c.HostKey.Callback(c.Observed),
		Timeout:         timeout,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// ssh.NewClientConn takes no context and blocks for the whole handshake, so
	// ctx cancellation would otherwise only be *noticed* after it returned —
	// bounded by the conn deadline set above, i.e. up to Timeout (20s). That is
	// not hypothetical at shutdown: against a host that accepts the TCP
	// connection but never completes the handshake (a wedged sshd, a
	// black-holed route — the same failure Keepalive exists to catch), the run
	// loop spends most of its time right here, so a Ctrl-C lands inside the
	// handshake and stop() waits the full dial timeout out.
	//
	// Closing the underlying conn is what actually interrupts it; net.Conn is
	// safe to Close concurrently with the reads NewClientConn is performing.
	// The watcher is torn down as this function returns, so a cancellation
	// arriving after a successful dial does not touch the returned client — its
	// lifetime belongs to the caller from that point on. A cancel racing a
	// just-completed handshake may close a conn that is about to be returned;
	// that is benign, since the caller's ctx is dead and its very next act is
	// to abandon the connection anyway.
	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-handshakeDone:
		}
	}()

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		// A handshake the watcher above aborted reports whatever the closed
		// conn produced ("use of closed network connection"), which is not a
		// useful classification. Report the cancellation itself so the caller
		// can tell a shutdown from a genuine handshake failure.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, ErrHostKeyUnknown) {
			return nil, err
		}
		// A rejected or mismatched host key surfaces here as *knownhosts.KeyError
		// (there is no ssh.KeyError — that type does not exist in x/crypto/ssh).
		// Returned unwrapped so Classify's own errors.As(err, &knownhosts.KeyError)
		// check maps it to ClassHostKey rather than the generic handshake class.
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			return nil, err
		}
		// x/crypto reports a rejected credential as a plain handshake error;
		// distinguish it here so the state machine can apply the auth floor.
		if isAuthFailure(err) {
			return nil, fmt.Errorf("%w: %w", ErrAuth, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(sc, chans, reqs), nil
}

// isAuthFailure recognises the handshake error x/crypto returns when every
// offered credential was rejected. There is no exported sentinel for it, so
// this is the one place a message is inspected — kept narrow and commented so
// a future x/crypto change is easy to find.
//
// The matched text can include a server-supplied disconnect message, so a
// hostile server could in principle induce this classification on a failure
// that isn't really an auth rejection. The blast radius is limited to which
// backoff floor Classify applies (ClassAuth vs. ClassHandshake), not to any
// security decision, so that is acceptable.
func isAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain")
}

// requestSender is the one method Keepalive needs from an SSH transport,
// narrowed from *ssh.Client so the strike state machine is unit-testable
// without a live SSH connection.
type requestSender interface {
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

// errKeepaliveTimeout marks a keepalive request that received no reply within
// one interval — treated as a strike, mirroring OpenSSH's ServerAliveCountMax.
var errKeepaliveTimeout = errors.New("keepalive request timed out")

// Keepalive sends keepalive@openssh.com every interval until the context is
// cancelled or strikes consecutive requests fail (including timing out),
// returning the failure that tripped it.
//
// SSH-level rather than TCP: TCP keepalive does not detect a wedged sshd, and
// a laptop resuming from sleep needs the dead transport surfaced in seconds
// rather than after the OS TCP timeout.
//
// Each request is bounded to at most one interval and run on its own
// goroutine. Both are load-bearing: SendRequest is a blocking call, so
// against a wedged sshd (TCP alive, requests unserviced) or a black-holed
// route (VPN drop, Wi-Fi handover, a laptop's lid closing) it would otherwise
// block on this function's own goroutine until the OS TCP timeout — minutes —
// during which neither the strike counter nor ctx cancellation would be
// observed at all. Bounding the wait turns "unanswered" into a strike instead
// of a silent stall.
func Keepalive(ctx context.Context, cl requestSender, interval time.Duration, strikes int) error {
	if interval <= 0 {
		return fmt.Errorf("keepalive interval must be positive, got %s", interval)
	}
	if strikes <= 0 {
		return fmt.Errorf("keepalive strikes must be positive, got %d", strikes)
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	var consecutive int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			err := keepaliveOnce(ctx, cl, interval)
			if err == nil {
				consecutive = 0
				continue
			}
			// A request that failed because ctx was cancelled while it was in
			// flight is a shutdown, not a strike: report the cancellation
			// directly rather than folding it into the failure count.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			consecutive++
			if consecutive >= strikes {
				return fmt.Errorf("keepalive failed %d times: %w", consecutive, err)
			}
		}
	}
}

// keepaliveOnce sends one keepalive request, bounded to at most timeout and
// also returning early on ctx cancellation. The result channel is buffered so
// the request goroutine can always deliver its outcome and exit even after
// this call has already returned via the timeout or cancellation branch —
// it cannot leak.
func keepaliveOnce(ctx context.Context, cl requestSender, timeout time.Duration) error {
	res := make(chan error, 1)
	go func() {
		_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
		res <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-res:
		return err
	case <-time.After(timeout):
		return errKeepaliveTimeout
	}
}
