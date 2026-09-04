package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// queryTimeout bounds the whole status query — the connect AND the agent
// protocol exchange that follows. Both halves need a bound, and the second is
// the one that bites: under systemd socket activation the socket node exists
// and the kernel completes connect() into systemd's listen backlog whether or
// not anything is accepting, so a dial against a daemon that has not yet
// started serving the agent succeeds instantly and then blocks forever waiting
// for a reply. A daemon idling for a Vault token it can never obtain (no local
// token, no peer to borrow from) never starts serving, so "forever" is literal
// — `dotvault status` hung until Ctrl+C. A live local endpoint answers in
// microseconds, so this only ever fires on the pathological case.
const queryTimeout = 5 * time.Second

// ErrListIdentities tags a failure that happened *after* the endpoint answered:
// the daemon is running and serving the socket or pipe, but every identity
// source erred. Reporting that as an unreachable endpoint would send an
// operator looking for a daemon that is in fact healthy — the common cause is
// a Vault-CA source unable to mint for a moment, not a missing daemon.
var ErrListIdentities = errors.New("agent could not list identities")

// QueryListening connects to a running daemon's agent endpoint and returns the
// identities it is currently serving, obtained over the SSH agent protocol —
// the equivalent of `ssh-add -l`. This reports what the live daemon actually
// offers (the cached minted certificate with its true remaining validity, the
// keys presently discoverable in Vault) rather than a static description of
// config, and it never creates the endpoint.
//
// A dial failure — or a connected endpoint that does not answer within
// queryTimeout — is returned to the caller: when the agent is configured as
// enabled, an unreachable or unresponsive endpoint is an unexpected condition
// (the daemon isn't running) and the caller should surface it as such rather
// than silently substituting config. "Not yet authenticated" is no longer one
// of the causes: the daemon serves the agent before it holds a token, and
// answers an empty identity list until it does.
//
// A failure to *list* over an endpoint that answered promptly is a different
// diagnosis again, and is tagged ErrListIdentities so a caller can say so: the
// daemon is running and serving, it just cannot resolve any identity right now.
func QueryListening(ctx context.Context, addr string) ([]IdentityStatus, error) {
	// A caller-supplied deadline earlier than queryTimeout wins, per
	// context's own semantics — which is how tests exercise the
	// accepted-but-silent case without waiting out the full budget.
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	conn, err := dialEndpoint(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// The deadline covers the request and the reply. Belt-and-braces with the
	// watcher below: SetDeadline is what bounds a peer that accepted and went
	// quiet, while closing the conn is what unblocks a read if the caller's
	// own context is cancelled first (Ctrl+C) or the transport ignores
	// deadlines.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	keys, err := agent.NewClient(conn).List()
	if err != nil {
		// Report the timeout as itself. The underlying error from a closed or
		// deadline-expired conn ("use of closed network connection", "i/o
		// timeout") describes the symptom, not the cause an operator needs.
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		if isTransportFailure(ctx, err) {
			return nil, fmt.Errorf("agent at %s accepted the connection but did not respond (daemon not yet serving the agent?): %w", addr, err)
		}
		// The endpoint answered, promptly and over a transport that stayed up,
		// so the failure is the agent's own — every identity source erred.
		return nil, fmt.Errorf("%w: %w", ErrListIdentities, err)
	}
	return keysToStatuses(keys), nil
}

// isTransportFailure reports whether err is the connection dying or timing out
// rather than the agent answering with a failure.
//
// The distinction is the whole point of ErrListIdentities: tagging every
// non-nil error would tell an operator "serving, but no identities could be
// resolved" about a daemon that had just exited mid-exchange, which is exactly
// the misdiagnosis the sentinel exists to prevent — only inverted. The
// deadline is checked from the error as well as the context because the conn
// deadline and the context timer are set to the same instant, so an `i/o
// timeout` can surface a hair before ctx.Err() flips.
func isTransportFailure(ctx context.Context, err error) bool {
	return errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// keysToStatuses converts the agent-protocol key list into the IdentityStatus
// shape, parsing each advertised blob so a certificate's true remaining
// validity is recovered from the wire rather than re-derived from config. A
// blob that fails to parse is surfaced as a placeholder rather than dropped, so
// a discrepancy between what the daemon advertises and what the client can read
// is visible rather than silent. Kept separate from QueryListening so the parse
// behaviour is unit-testable without a live endpoint.
func keysToStatuses(keys []*agent.Key) []IdentityStatus {
	out := make([]IdentityStatus, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			out = append(out, IdentityStatus{
				Comment:     k.Comment,
				Fingerprint: fmt.Sprintf("(unparseable: %v)", err),
			})
			continue
		}
		id := Identity{PubKey: pub, Comment: k.Comment}
		if cert, ok := pub.(*ssh.Certificate); ok {
			id.Expiry = certExpiry(cert)
		}
		out = append(out, identityStatus(id))
	}
	return out
}
