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

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
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
func isAuthFailure(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain") ||
		strings.Contains(msg, "handshake failed: ssh: unable to authenticate")
}

// Keepalive sends keepalive@openssh.com until the context is cancelled or the
// strike limit is reached, returning the failure that tripped it.
//
// SSH-level rather than TCP: TCP keepalive does not detect a wedged sshd, and
// a laptop resuming from sleep needs the dead transport surfaced in seconds
// rather than after the OS TCP timeout.
func Keepalive(ctx context.Context, cl *ssh.Client, interval time.Duration, strikes int) error {
	t := time.NewTicker(interval)
	defer t.Stop()

	var consecutive int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil {
				consecutive = 0
				continue
			}
			consecutive++
			if consecutive >= strikes {
				return fmt.Errorf("keepalive failed %d times: %w", consecutive, err)
			}
		}
	}
}
