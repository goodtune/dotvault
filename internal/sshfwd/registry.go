package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
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
// Verified must be false whenever the connection was not actually
// authenticated against anything — the system config's
// insecure_ignore_host_key escape hatch above all. Add pins a key only when
// Verified is true, so an insecure-policy result that still happens to carry
// an observed HostKey/Fingerprint (HostKeyPolicy.Callback records the
// observed key before its own Insecure short-circuit) does not get persisted
// as a trusted pin. This is enforced structurally by Add, not merely
// documented here — see the Verified check and the HostKey/Fingerprint
// consistency check inside Add.
type Verifier interface {
	Verify(ctx context.Context, r Remote, opts VerifyOptions) (VerifyResult, error)
}

// VerifyOptions modifies how Verify checks a candidate remote. The zero value
// runs every check.
type VerifyOptions struct {
	// SkipBindProof skips the bind-and-release proof of the remote socket
	// path (see liveVerifier.Verify). Registry.Add sets this when
	// Manager.Status() already reports the host as connected: the daemon
	// itself owns that live forward, so a fresh bind attempt would race its
	// own listener and fail with EADDRINUSE (sshd's default
	// StreamLocalBindUnlink=no makes bind() fail for any existing path
	// entry — see ServeForward's doc comment) — a false verification
	// failure on a perfectly healthy host, not evidence anything is wrong.
	// Dial, auth, and host-key/certificate verification still run
	// unconditionally, so the trust decision Verify exists to make is
	// unchanged; only the socket-bind side effect is skipped, and only
	// because the running Manager is already live proof that the path
	// works.
	SkipBindProof bool
}

// VerifyResult carries what a Verifier observed about a remote.
type VerifyResult struct {
	// HostKey is the remote's key in authorized_keys form, ready to store on
	// Remote.HostKey. Empty when a configured certificate authority covers
	// the host instead, when Verified is false, or when the offered key
	// matched the pin Add passed in as the Remote's HostKey (see Add) — a
	// successful match confirms nothing new, so there is no fresh key to
	// report. Add falls back to the pin it already had on file in that
	// last case, so a Verifier must NOT echo the pin back defensively "to
	// be safe": doing so is harmless (it is the same value), but leaving
	// HostKey empty on a matched pin is the expected, supported way to say
	// "no change" and must not be read as "unpin this host".
	HostKey string

	// Fingerprint is the SHA256 fingerprint of HostKey, present exactly when
	// HostKey is: it is what Add asks a human to confirm via
	// AddOptions.AcceptFingerprint before pinning an unpinned host. Add
	// independently re-derives the fingerprint from HostKey and refuses to
	// pin if the two disagree, so this field cannot smuggle a mismatched
	// pair past the confirmation gate.
	Fingerprint string

	// Verified reports whether this result came from an actual check —
	// against a pinned key, a configured CA, or (for a brand-new key) via
	// Add's own fingerprint-confirmation gate. False means nothing was
	// authenticated (an insecure-policy connection): Add never pins a key
	// when this is false, regardless of what HostKey/Fingerprint say.
	Verified bool

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
	// at registration time; the caller accepts that no key was checked. It
	// does not blank an existing pin — see Add's doc comment.
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

// ErrHostNotFound is returned by Patch when the given host has no configured
// entry. A sentinel (rather than a bare fmt.Errorf, which Remove still uses
// for its own not-found case — Remove reports absence via its bool return,
// not an error) lets a caller distinguish "no such host" from a genuine
// validation failure via errors.Is, the same pattern ErrConfirmHostKey
// establishes for Add. The web API maps this to 404, and everything else
// Patch can return to 400.
var ErrHostNotFound = errors.New("host not configured")

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
// Two locks, with distinct jobs.
//
// txMu serialises whole mutations. Every mutation (Add's write phase,
// Patch, Remove) and Resync holds it across its own Load -> Save ->
// Reconcile, so the on-disk file and the daemon's running set cannot
// diverge: a caller cannot read the file before another's removal is saved
// and then reconcile after that removal's own Reconcile has run,
// resurrecting a just-removed remote. That divergence was a real bug on
// this branch, and this lock is what closes it.
//
// mu guards only the file read and the file write, and is held for exactly
// as long as each takes. The daemon is the sole writer of ssh.yaml — the
// CLI reaches it through the web API, not the filesystem — so no
// cross-process lock is needed, but two concurrent web requests are
// entirely possible and must not race each other's Load/Save.
//
// The split exists because Manager.Reconcile's stop phase can block for a
// while: it waits for each victim runner to exit, and a runner sitting
// inside ssh.NewClientConn is bounded only by the 20s dial deadline (see
// dial.go). Under a single lock, one Patch touching N changed remotes would
// wedge List — a read-only status call — for up to N x 20s. It cannot be
// fixed by moving Reconcile out of the transaction without reopening the
// divergence above, so the fix is to keep the transaction serialised and
// take the *file* lock out of it. List and Add's pre-dial read of the
// stored pin therefore never queue behind a slow or unreachable host.
//
// The residual, deliberately accepted: List can observe a file a
// still-in-flight Reconcile has not yet applied to the running set. That
// window is inherent — Save necessarily precedes Reconcile — and List is
// informational; the divergence that mattered was between two concurrent
// mutations, and txMu still prevents it.
type Registry struct {
	path string
	mgr  *Manager
	v    Verifier

	txMu sync.Mutex
	mu   sync.RWMutex

	// resyncDelay, when set, is invoked by Resync between its Load and
	// Reconcile calls, still holding the transaction lock. Production code
	// never sets it; it exists purely so a test can widen the window a
	// concurrent Add/Patch/Remove would need to sneak into, to prove they
	// genuinely block on this same lock rather than merely losing a fast
	// race by luck. Set via SetResyncDelayForTest.
	resyncDelay func()
}

// loadFile and saveFile are the only paths that touch ssh.yaml. They hold
// the file lock for the duration of the I/O and nothing more — in
// particular, never across a Reconcile. See Registry's doc comment.
func (g *Registry) loadFile() (*File, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return Load(g.path)
}

func (g *Registry) saveFile(f *File) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Save(g.path, f)
}

// NewRegistry returns a Registry backed by the ssh.yaml at path, reconciling
// the given Manager on every mutation and verifying host keys through v.
func NewRegistry(path string, mgr *Manager, v Verifier) *Registry {
	return &Registry{path: path, mgr: mgr, v: v}
}

// List returns every configured remote.
func (g *Registry) List() ([]Remote, error) {
	f, err := g.loadFile()
	if err != nil {
		return nil, err
	}
	return f.Remotes, nil
}

// storedHostKey returns the HostKey currently pinned for host, or "" if the
// host is not configured yet. Read-locked only: it is consulted before
// Verify's network dial, not as part of the write transaction — see Add.
func (g *Registry) storedHostKey(host string) (string, error) {
	f, err := g.loadFile()
	if err != nil {
		return "", err
	}
	if i, ok := f.Find(host); ok {
		return f.Remotes[i].HostKey, nil
	}
	return "", nil
}

// alreadyConnected reports whether the running Manager already shows host as
// connected, so Add can tell Verify to skip the bind proof (see
// VerifyOptions.SkipBindProof). It reads the Manager's own live status
// rather than the file, so a host that is merely configured but not
// currently connected — including one this daemon has never reconciled yet —
// still gets the full bind check.
func (g *Registry) alreadyConnected(host string) bool {
	for _, st := range g.mgr.Status() {
		if strings.EqualFold(st.Host, host) && st.State == string(StateConnected) {
			return true
		}
	}
	return false
}

// Add registers r, or updates the existing entry for r.Host (Add is
// idempotent on host — see Remote's doc comment).
//
// Add is transactional: nothing is persisted that has not been verified.
// Verification and the fingerprint confirmation gate both run before the
// file is ever loaded for writing, so a rejected, unconfirmed, or
// unverifiable Add leaves ssh.yaml exactly as it found it. Verify itself
// runs with no lock held: it is a network dial to a possibly-unreachable
// host, and holding the write lock across that handshake would block every
// other Registry call — List above all — behind one slow or offline host.
// The read-modify-write against the file is still fully serialised, under
// the write lock, against a freshly reloaded copy.
//
// Force bypasses verification entirely — the verifier is not called at all
// — for the documented case of registering a host that is offline right
// now. It does not touch an existing pin: Force changes configuration
// (port, socket, enabled), not trust. Re-pinning still goes through
// verification and the fingerprint gate, even under Force, unless the
// caller explicitly supplies a new r.HostKey to replace the stored one.
//
// On a re-Add of an already-configured host, the stored pin (if any) is
// folded into the value handed to Verify before the dial, not the bare
// caller-supplied r. Registry is the only component that knows the stored
// pin; without this, a Verifier building its trust decision from the Remote
// it is given would see an empty pin on every re-Add and treat an
// already-trusted host as brand new — turning an active MITM's changed key
// into a fresh, confirmable "first use" prompt instead of a rejected
// mismatch, exactly what ErrConfirmHostKey's doc comment says must never
// happen.
//
// The stored pin also protects the write on the way out: a Verify success
// that reports no HostKey (a match against the pin it was handed, or a
// CA-covered host) falls back to the existing pin rather than blanking it —
// see VerifyResult.HostKey. Without that fallback, every ordinary re-Add of
// an already-pinned host would silently unpin it the moment a Verifier
// implementation chose the natural "nothing changed, nothing to report"
// shape for a match.
func (g *Registry) Add(ctx context.Context, r Remote, opts AddOptions) (*Remote, error) {
	if r.RemoteSocket == "" {
		r.RemoteSocket = DefaultRemoteSocket
	}
	if err := ValidateRemote(r); err != nil {
		return nil, err
	}

	// The caller's own HostKey, if supplied (an explicit re-pin or a BYO
	// import), takes priority over whatever is currently stored — both for
	// what Force preserves and for what gets handed to Verify.
	explicitHostKey := r.HostKey

	existingHostKey, err := g.storedHostKey(r.Host)
	if err != nil {
		return nil, err
	}

	if opts.Force {
		if explicitHostKey == "" {
			r.HostKey = existingHostKey
		}
	} else {
		verifyInput := r
		if verifyInput.HostKey == "" {
			verifyInput.HostKey = existingHostKey
		}

		// A re-Add of a host the running Manager already reports connected
		// skips only the bind-and-release proof — see VerifyOptions.SkipBindProof.
		result, verr := g.v.Verify(ctx, verifyInput, VerifyOptions{SkipBindProof: g.alreadyConnected(r.Host)})
		if verr != nil {
			// Every verification failure other than "unpinned, needs
			// confirmation" surfaces here as a plain error — see Verifier's
			// and ErrConfirmHostKey's doc comments. It is never wrapped into
			// something a caller could confirm past. Because verifyInput
			// carried the stored pin, a changed key on an already-pinned
			// host reaches this branch as ErrHostKeyMismatch rather than
			// the confirmable "unknown" case.
			return nil, verr
		}

		if result.HostKey != "" {
			// Defense in depth for "never pin an unverified key": a
			// fingerprint must accompany any key, and must actually be
			// that key's fingerprint. This does not take Verifier's
			// contract on faith — a pin is a trust anchor, and Verifier's
			// only implementation lives in a later task, so this check is
			// what makes the invariant hold even if that implementation
			// gets it wrong.
			if result.Fingerprint == "" {
				return nil, fmt.Errorf(
					"verifier reported a host key for %s with no fingerprint; refusing to pin an unconfirmed key",
					r.Host)
			}
			pk, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(result.HostKey))
			if perr != nil {
				return nil, fmt.Errorf("verifier reported an unparseable host key for %s: %w", r.Host, perr)
			}
			if got := ssh.FingerprintSHA256(pk); got != result.Fingerprint {
				return nil, fmt.Errorf(
					"verifier reported fingerprint %s for %s but its host key's real fingerprint is %s; refusing to pin",
					result.Fingerprint, r.Host, got)
			}
		}

		switch {
		case !result.Verified:
			// Not authenticated against anything (e.g. an insecure
			// policy): never pin what this connection observed, no matter
			// what HostKey/Fingerprint say. Keep the existing pin rather
			// than blanking it — same reasoning as the Fingerprint == ""
			// case below. Blanking would mean an ordinary re-Add under a
			// temporarily-enabled insecure_ignore_host_key destroys a
			// verified pin, so that turning the flag back off leaves the
			// host unpinned and an MITM meets a confirmable first-use
			// prompt instead of ErrHostKeyMismatch. Nothing unverified is
			// written either way: existingHostKey is a value that was
			// itself verified before it was stored.
			r.HostKey = existingHostKey
		case result.Fingerprint == "":
			// Verified with nothing new to confirm: CA-covered (HostKey
			// legitimately empty), or the offered key already matched the
			// stored pin (HostKey empty per the "no change" convention
			// documented on VerifyResult.HostKey — see R1). Falling back to
			// existingHostKey rather than blanking means a bare
			// "it matched" result can never unpin an already-trusted host,
			// on the everyday re-Add path and not just under Force.
			if result.HostKey != "" {
				r.HostKey = result.HostKey
			} else {
				r.HostKey = existingHostKey
			}
		case opts.AcceptFingerprint == "":
			return nil, &HostKeyConfirmation{Host: r.Host, Fingerprint: result.Fingerprint}
		case opts.AcceptFingerprint != result.Fingerprint:
			return nil, fmt.Errorf(
				"host key confirmation for %s does not match: verifier offered %s, caller confirmed %s",
				r.Host, result.Fingerprint, opts.AcceptFingerprint)
		default:
			r.HostKey = result.HostKey
		}
	}

	g.txMu.Lock()
	defer g.txMu.Unlock()

	f, err := g.loadFile()
	if err != nil {
		return nil, err
	}

	// Compare-and-swap on the pin. existingHostKey was read before the dial,
	// outside this transaction — deliberately, so a slow or offline host
	// cannot wedge every other mutation behind its handshake. That leaves a
	// window in which another Add could commit a re-pin for the same host,
	// which this Add would then silently revert to the older key. Refusing,
	// and telling the caller to retry, is the only correct resolution: this
	// Add's verification decision was made against a pin that is no longer
	// current, so committing it would mean writing a trust anchor nobody
	// verified against the file as it now stands.
	if i, ok := f.Find(r.Host); ok && f.Remotes[i].HostKey != existingHostKey {
		return nil, fmt.Errorf(
			"host key for %s changed concurrently while this request was verifying it; retry", r.Host)
	}

	f.Upsert(r)
	if err := g.saveFile(f); err != nil {
		return nil, err
	}
	if rerr := g.mgr.Reconcile(ctx, f.Remotes); rerr != nil {
		// The file already reflects the change; only the running set does
		// not yet. Returning the committed value alongside the error, and
		// saying plainly that it was saved, keeps a caller from reading a
		// non-nil error as "nothing happened" when ssh.yaml already moved.
		got := r
		return &got, fmt.Errorf("saved %s but could not apply it to the running set: %w", g.path, rerr)
	}

	got := r
	return &got, nil
}

// Patch applies non-nil fields of p to the existing entry for host. It
// returns an error, and leaves ssh.yaml untouched, if host is not
// configured or the patched entry fails validation.
func (g *Registry) Patch(ctx context.Context, host string, p Patch) (*Remote, error) {
	g.txMu.Lock()
	defer g.txMu.Unlock()

	f, err := g.loadFile()
	if err != nil {
		return nil, err
	}
	i, ok := f.Find(host)
	if !ok {
		return nil, fmt.Errorf("no remote configured for host %q: %w", host, ErrHostNotFound)
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
	if err := g.saveFile(f); err != nil {
		return nil, err
	}
	if rerr := g.mgr.Reconcile(ctx, f.Remotes); rerr != nil {
		got := r
		return &got, fmt.Errorf("saved %s but could not apply it to the running set: %w", g.path, rerr)
	}

	got := r
	return &got, nil
}

// Remove deletes the entry for host, reporting whether one was present.
// Removing an unknown host is not an error: Remove is idempotent, matching
// File.Remove.
func (g *Registry) Remove(ctx context.Context, host string) (bool, error) {
	g.txMu.Lock()
	defer g.txMu.Unlock()

	f, err := g.loadFile()
	if err != nil {
		return false, err
	}
	if !f.Remove(host) {
		return false, nil
	}
	if err := g.saveFile(f); err != nil {
		return false, err
	}
	if rerr := g.mgr.Reconcile(ctx, f.Remotes); rerr != nil {
		return true, fmt.Errorf("removed from %s but could not apply it to the running set: %w", g.path, rerr)
	}
	return true, nil
}

// Resync re-reads ssh.yaml and reconciles the Manager against it, under the
// same write lock Add/Patch/Remove use.
//
// This is what the daemon's config-refresh loop calls to pick up a hand-edit
// of ssh.yaml on its periodic tick, instead of calling sshfwd.Load and
// Manager.Reconcile directly. The lock matters: every other mutation
// (Add/Patch/Remove) holds g.mu across its own Load -> Save -> Reconcile so
// the file and the running set can never be observed to disagree. A caller
// that read the file and reconciled outside that lock could race a
// concurrent Add/Patch/Remove — read the file before a removal is saved,
// then reconcile after the removal's own Reconcile has already run,
// resurrecting the just-removed remote until the next call closes the
// window. Resync closes that window by taking the identical lock.
func (g *Registry) Resync(ctx context.Context) error {
	g.txMu.Lock()
	defer g.txMu.Unlock()

	f, err := g.loadFile()
	if err != nil {
		return err
	}
	if g.resyncDelay != nil {
		g.resyncDelay()
	}
	return g.mgr.Reconcile(ctx, f.Remotes)
}

// SetResyncDelayForTest installs a hook Resync invokes — still holding its
// write lock — between reading ssh.yaml and reconciling the Manager against
// it. Test-only seam: it exists so a test can deterministically prove Resync
// serializes against a concurrent Add/Patch/Remove (rather than merely
// racing fast enough not to notice), by giving it a reliable window in which
// to attempt, and observe blocked, a concurrent mutation.
func (g *Registry) SetResyncDelayForTest(f func()) {
	g.txMu.Lock()
	defer g.txMu.Unlock()
	g.resyncDelay = f
}
