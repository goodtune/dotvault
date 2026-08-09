package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Verifier verifies a candidate remote's host key or certificate and reports
// what it observed. It is the seam Add calls through before persisting a new
// or changed entry, so the CLI and the web UI share exactly one verification
// path and cannot drift.
//
// Contract for implementations: a nil error means the connection is safe to
// trust — either because a configured certificate authority already covers
// the host, or because the key is unpinned and a human still needs to
// confirm it (Registry.Add owns that decision, via Fingerprint below). Any
// other verification failure — a mismatched pinned key, a certificate the
// configured CAs reject, an expired or wrong-principal certificate — must be
// returned as a plain error. Registry.Add treats every non-nil error as
// final and unconfirmable; see ErrConfirmHostKey.
//
// An implementation running under an insecure policy (the system config's
// insecure_ignore_host_key escape hatch) must leave VerifyResult.HostKey and
// VerifyResult.Fingerprint empty. Add pins exactly what it is told and
// nothing else, so a Verifier that reports a key it did not actually check
// would cause Add to persist an unverified pin — the vulnerability
// HostKeyPolicy.Callback's own doc comment warns about. Nothing on the
// Registry side can detect that misbehaviour after the fact; it is enforced
// by this contract alone.
type Verifier interface {
	Verify(ctx context.Context, r Remote) (VerifyResult, error)
}

// VerifyResult carries what a Verifier observed about a remote.
type VerifyResult struct {
	// HostKey is the remote's key in authorized_keys form, ready to store on
	// Remote.HostKey. Empty when a configured certificate authority covers
	// the host instead, or when nothing was actually verified (see Verifier).
	HostKey string

	// Fingerprint is the SHA256 fingerprint of HostKey, present exactly when
	// HostKey is: it is what Add asks a human to confirm via
	// AddOptions.AcceptFingerprint before pinning an unpinned host.
	Fingerprint string

	// ResolvedSocket is the remote socket path after ~ expansion against the
	// account Verify connected as, for display back to the caller. It is
	// informational only: Add stores the entry's RemoteSocket exactly as
	// given (defaulted, unexpanded), so the file stays portable if the
	// remote account's home moves.
	ResolvedSocket string
}

// AddOptions controls how Add treats an unverified or newly-observed host
// key.
type AddOptions struct {
	// Force skips verification entirely and persists the entry as given.
	// This is the documented escape for registering a host that is offline
	// at registration time; the caller accepts that no key was checked.
	Force bool

	// AcceptFingerprint must equal the fingerprint a prior call returned via
	// ErrConfirmHostKey for Add to pin that host's key. Requiring the exact
	// value to be echoed back — rather than a boolean "yes" — is what keeps
	// this from degrading into blind trust-on-first-use: the caller must
	// repeat a value the daemon just observed for itself, not merely assent.
	AcceptFingerprint string
}

// Patch names the fields of an existing Remote to change. A nil field leaves
// the current value untouched. Host and HostKey are deliberately not
// patchable here: Host is the entry's identity, and re-pinning a host key
// goes through Add's verification/confirmation gate, not a bare field edit.
type Patch struct {
	Enabled      *bool
	RemoteSocket *string
	Port         *int
}

// ErrConfirmHostKey is returned by Add when the host's key is neither pinned
// nor CA-signed. It is not a failure: it is the one point at which a human
// decides to trust a host. The caller re-submits with AddOptions.
// AcceptFingerprint set to the fingerprint carried here.
//
// Requiring the fingerprint to be echoed — rather than a bare "yes" flag — is
// what keeps the browser path from degrading into blind trust-on-first-use:
// neither surface can commit without repeating back a value the daemon just
// observed for itself.
//
// This is the only confirmable outcome. Every other verification failure —
// ErrHostKeyMismatch above all, but also an expired certificate, a
// wrong-principal certificate, or a certificate from an unconfigured CA — is
// returned by Verify as a plain error and passed straight through by Add
// with no wrapping into this sentinel, so it can never reach a caller as
// something a fingerprint could confirm past.
var ErrConfirmHostKey = errors.New("host key requires confirmation")

// HostKeyConfirmation carries the fingerprint a caller must echo back to
// commit an Add for a previously-unpinned host.
type HostKeyConfirmation struct {
	Host        string
	Fingerprint string
}

func (e *HostKeyConfirmation) Error() string {
	return fmt.Sprintf("%s: %v (offered %s)", e.Host, ErrConfirmHostKey, e.Fingerprint)
}

func (e *HostKeyConfirmation) Unwrap() error { return ErrConfirmHostKey }

// Registry is the single service layer through which every mutation of
// ssh.yaml passes. Both the CLI and the web UI are thin clients of it, so
// validation and the host-key confirmation gesture cannot drift between the
// two surfaces.
//
// A sync.Mutex serialises every read-modify-write. The daemon is the sole
// writer of ssh.yaml — the CLI reaches it through the web API, not the
// filesystem — so no cross-process lock is needed, but two concurrent web
// requests are entirely possible and must not race each other's Load/Save.
// Each mutation re-loads the file under the lock (rather than trusting an
// in-memory copy) so a concurrent Add from another request is never
// clobbered, and calls Manager.Reconcile inside the same critical section as
// the Save so the on-disk file and the daemon's running set cannot diverge.
type Registry struct {
	path string
	mgr  *Manager
	v    Verifier

	mu sync.Mutex
}

// NewRegistry returns a Registry backed by the ssh.yaml at path, reconciling
// the given Manager on every mutation and verifying host keys through v.
func NewRegistry(path string, mgr *Manager, v Verifier) *Registry {
	return &Registry{path: path, mgr: mgr, v: v}
}

// List returns every configured remote.
func (g *Registry) List() ([]Remote, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f, err := Load(g.path)
	if err != nil {
		return nil, err
	}
	return f.Remotes, nil
}

// Add registers r, or updates the existing entry for r.Host (Add is
// idempotent on host — see Remote's doc comment).
//
// Add is transactional: nothing is persisted that has not been verified.
// Verification and the fingerprint confirmation gate both run before the
// file is ever loaded for writing, so a rejected, unconfirmed, or
// unverifiable Add leaves ssh.yaml exactly as it found it. Force bypasses
// verification entirely — the verifier is not called at all — for the
// documented case of registering a host that is offline right now.
func (g *Registry) Add(ctx context.Context, r Remote, opts AddOptions) (*Remote, error) {
	if r.RemoteSocket == "" {
		r.RemoteSocket = DefaultRemoteSocket
	}
	if err := ValidateRemote(r); err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if !opts.Force {
		result, err := g.v.Verify(ctx, r)
		if err != nil {
			// Every verification failure other than "unpinned, needs
			// confirmation" surfaces here as a plain error — see Verifier's
			// and ErrConfirmHostKey's doc comments. It is never wrapped into
			// something a caller could confirm past.
			return nil, err
		}

		// Fingerprint is set exactly when there is a key to pin (see
		// VerifyResult). A CA-covered host, or one verified under an
		// insecure policy that reported nothing (see Verifier's contract),
		// carries no fingerprint and needs no confirmation.
		if result.Fingerprint != "" {
			switch {
			case opts.AcceptFingerprint == "":
				return nil, &HostKeyConfirmation{Host: r.Host, Fingerprint: result.Fingerprint}
			case opts.AcceptFingerprint != result.Fingerprint:
				return nil, fmt.Errorf(
					"host key confirmation for %s does not match: verifier offered %s, caller confirmed %s",
					r.Host, result.Fingerprint, opts.AcceptFingerprint)
			}
		}

		// Pin exactly what Verify reported, and nothing more: an entry
		// verified with no fingerprint (CA-covered, or insecure) is stored
		// with no host_key rather than inheriting whatever the caller
		// happened to pass in r.HostKey.
		r.HostKey = result.HostKey
	}

	f, err := Load(g.path)
	if err != nil {
		return nil, err
	}
	f.Upsert(r)
	if err := Save(g.path, f); err != nil {
		return nil, err
	}
	if err := g.mgr.Reconcile(ctx, f.Remotes); err != nil {
		return nil, err
	}

	got := r
	return &got, nil
}

// Patch applies non-nil fields of p to the existing entry for host. It
// returns an error, and leaves ssh.yaml untouched, if host is not
// configured or the patched entry fails validation.
func (g *Registry) Patch(ctx context.Context, host string, p Patch) (*Remote, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f, err := Load(g.path)
	if err != nil {
		return nil, err
	}
	i, ok := f.Find(host)
	if !ok {
		return nil, fmt.Errorf("no remote configured for host %q", host)
	}

	r := f.Remotes[i]
	if p.Enabled != nil {
		r.Enabled = p.Enabled
	}
	if p.RemoteSocket != nil {
		r.RemoteSocket = *p.RemoteSocket
	}
	if p.Port != nil {
		r.Port = *p.Port
	}
	if err := ValidateRemote(r); err != nil {
		return nil, err
	}

	f.Remotes[i] = r
	if err := Save(g.path, f); err != nil {
		return nil, err
	}
	if err := g.mgr.Reconcile(ctx, f.Remotes); err != nil {
		return nil, err
	}

	got := r
	return &got, nil
}

// Remove deletes the entry for host, reporting whether one was present.
// Removing an unknown host is not an error: Remove is idempotent, matching
// File.Remove.
func (g *Registry) Remove(ctx context.Context, host string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f, err := Load(g.path)
	if err != nil {
		return false, err
	}
	if !f.Remove(host) {
		return false, nil
	}
	if err := Save(g.path, f); err != nil {
		return false, err
	}
	if err := g.mgr.Reconcile(ctx, f.Remotes); err != nil {
		return false, err
	}
	return true, nil
}
