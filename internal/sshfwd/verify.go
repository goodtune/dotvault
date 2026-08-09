package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// liveVerifier is the production Verifier: it dials the candidate remote for
// real, over the network, and proves every precondition ServeForward will
// later need — a working credential, an acceptable host key or certificate,
// a resolvable remote socket path, and permission to bind it — then tears
// the connection down again without leaving anything running or mutating
// anything on the remote. `dotvault ssh add` runs this before Registry.Add
// ever touches ssh.yaml, so a host that cannot actually be forwarded to
// never gets persisted as if it could.
type liveVerifier struct {
	deps Deps
}

// NewVerifier returns a Verifier backed by d. See the Verifier and
// VerifyResult doc comments in registry.go for the contract this
// implementation must uphold.
func NewVerifier(d Deps) Verifier {
	return liveVerifier{deps: d}
}

// Verify dials r, checks its host key or certificate against the policy d.Policy
// returns for it, and — once connected — resolves and bind-tests the remote
// socket. Nothing about the connection survives the call: the client is
// always closed before Verify returns, on every path.
func (v liveVerifier) Verify(ctx context.Context, r Remote) (VerifyResult, error) {
	signers, err := v.deps.Signers()
	if err != nil {
		return VerifyResult{}, err
	}
	user, err := v.deps.User()
	if err != nil {
		return VerifyResult{}, err
	}

	policy := v.deps.Policy(r)

	// Observed is set so that even a rejected dial (ErrHostKeyUnknown, the
	// confirmable case) still yields a fingerprint to hand back to a human —
	// see HostKeyPolicy.Callback in hostkey.go, which records the presented
	// key before any accept/reject decision.
	var observed ssh.PublicKey
	cl, err := Dial(ctx, DialConfig{
		Host:     r.Host,
		Port:     r.PortOrDefault(),
		User:     user,
		Signers:  signers,
		HostKey:  policy,
		Observed: &observed,
	})
	if err != nil {
		if errors.Is(err, ErrHostKeyUnknown) {
			// ErrHostKeyUnknown is the ONLY dial outcome that becomes a
			// confirmable result: return what was observed with a nil
			// error so Registry.Add can run the fingerprint-confirmation
			// handshake (ErrConfirmHostKey). Every other failure —
			// ErrHostKeyMismatch above all, but equally an auth failure, an
			// expired or wrong-principal certificate, or a certificate from
			// an unconfigured CA — falls through to the plain-error return
			// below and must never be mistaken for something a fingerprint
			// could confirm past.
			if observed == nil {
				// Callback always records into *Observed before returning
				// ErrHostKeyUnknown (see hostkey.go), so this should not
				// happen; failing with the original error is safer than
				// fabricating a result with no key.
				return VerifyResult{}, err
			}
			return VerifyResult{
				HostKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(observed))),
				Fingerprint: ssh.FingerprintSHA256(observed),
			}, nil
		}
		return VerifyResult{}, err
	}
	defer cl.Close()

	socket := r.RemoteSocket
	if socket == "" {
		socket = DefaultRemoteSocket
	}
	resolved, err := ExpandRemotePath(ctx, sshRunner{cl: cl}, socket)
	if err != nil {
		return VerifyResult{}, err
	}

	// Bind-and-immediately-release, never bind-and-serve: this is a dry run
	// of a host that is not yet, and may never be, managed by this daemon.
	// Binding at all is what actually proves the two failure modes that
	// nothing short of a real bind attempt can catch — AllowStreamLocalForwarding
	// no on the remote sshd, and an unwritable parent directory for the
	// socket path — so the check has to be a real ListenUnix, not a stat.
	//
	// This deliberately does NOT run ServeForward's stale-socket reclaim
	// (liveListenerAt / removeRemoteFile in forward.go) on a bind failure.
	// That logic exists to distinguish a crashed session's leftover socket
	// from one a live `ssh -R` is actively using, and it is only safe to act
	// on for a remote the daemon already owns and is reconciling. `ssh add`
	// is verifying a host before Registry has persisted anything about it —
	// it must never delete a file on that host on the strength of one failed
	// bind. A plain bind failure here is reported as an error and the
	// caller tries again once whatever is occupying the path is resolved.
	ln, err := cl.ListenUnix(resolved)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: %s: %w", ErrBind, resolved, err)
	}
	if err := ln.Close(); err != nil {
		return VerifyResult{}, fmt.Errorf("close verification listener for %s: %w", resolved, err)
	}

	// A successful Dial never falls through with a *new* key to report:
	// either policy.Insecure accepted the connection with nothing actually
	// checked, the offered key matched an existing pin, or a configured CA
	// covered the presented certificate. VerifyResult.HostKey's contract
	// covers exactly those cases with "leave it empty" — a certificate-
	// authority host has nothing to pin, a matched pin has nothing new to
	// report (Registry.Add falls back to the stored pin), and an
	// insecure-policy connection was never actually authenticated, so
	// nothing it observed may be reported as key material at all (see
	// HostKeyPolicy.Callback's doc comment: observed is populated before the
	// Insecure short-circuit, and reporting it here would let it be
	// persisted as a trusted pin that outlives the flag). So HostKey and
	// Fingerprint are left zero-valued on every success path; Verified is
	// the only signal that distinguishes a genuine check from an
	// insecure-policy connection.
	return VerifyResult{
		Verified:       !policy.Insecure,
		ResolvedSocket: resolved,
	}, nil
}
