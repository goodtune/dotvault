package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/goodtune/dotvault/internal/securestore"
	"github.com/goodtune/dotvault/internal/tmpl"
	"github.com/goodtune/dotvault/internal/vault"
)

// MTLSParams carries everything the cert-auth flow needs. It is populated by
// the daemon (cmd/dotvault) from the validated vault.mtls config and attached
// to a Manager whose AuthMethod is "mtls", "mtls+tpm", or "mtls+os".
type MTLSParams struct {
	// Connectivity for building a cert-presenting login client.
	VaultAddress  string
	CACert        string
	TLSSkipVerify bool

	Method          string // "mtls" | "mtls+tpm" | "mtls+os"
	BootstrapMethod string
	BootstrapMount  string
	CertMount       string
	CertRole        string
	PKIMount        string
	PKIRole         string
	KeyType         string
	KeyBits         int    // RSA modulus size; 0 = backend default (2048). Ignored for EC.
	CommonName      string // template over {{.user}}
	TTL             string
	ReissueBefore   time.Duration
	SealToPCRs      bool
	StorageDir      string
	BYOCert         string
	BYOKey          string
}

// authenticateMTLS runs the certificate-auth flow: reuse an in-window
// credential where possible, otherwise seed one (BYO or LDAP/OIDC bootstrap →
// PKI), then log in against Vault's cert auth method and adopt the operational
// token onto the Manager's client.
func (m *Manager) authenticateMTLS(ctx context.Context) error {
	p := m.MTLS
	if p == nil {
		return fmt.Errorf("auth method %q selected but vault.mtls is not configured", m.AuthMethod)
	}

	store, err := securestore.Open(securestore.ModeForMethod(p.Method))
	if err != nil {
		switch p.Method {
		case "mtls+tpm":
			return fmt.Errorf("mtls+tpm requested but no hardware backend is available on this host (%w); re-run with auth_method: mtls to store the key on disk, or provision a TPM", err)
		case "mtls+os":
			return fmt.Errorf("mtls+os requested but the OS-native certificate store is unavailable (%w); mtls+os is Windows-only — re-run with auth_method: mtls to store the key on disk", err)
		}
		return fmt.Errorf("open secure store: %w", err)
	}
	defer store.Close()

	// 1. Try an existing credential.
	cred, err := loadCredential(p.StorageDir)
	if err != nil {
		slog.Warn("existing mtls credential unusable, will re-seed", "error", err)
		cred = nil
	}
	if cred != nil {
		if reused, err := m.tryExistingCredential(ctx, store, cred); err != nil {
			// A failure to honour no-token-at-rest is not a broken credential,
			// so re-seeding is the wrong response: the certificate is fine and
			// a fresh one would hit the same undeletable file. Falling through
			// would cost an interactive bootstrap prompt and a wasted PKI
			// issuance on every startup, and still fail.
			if errors.Is(err, ErrTokenAtRest) {
				return err
			}
			slog.Warn("existing mtls credential failed, re-seeding", "error", err)
		} else if reused {
			// Operational-login success: emit the transition notice exactly
			// once here, not in certLogin — certLogin is also reached by the
			// inner reissue (and the periodic ReissueIfDue), which would
			// otherwise double-warn on rotation or spam it every rotation cycle.
			WarnUnrestrictedPolicy(m.Policy)
			return nil
		}
	}

	// 2. Seed a fresh credential (BYO or bootstrap), then cert-login.
	newCred, signer, err := m.seedCredential(ctx, store)
	if err != nil {
		return err
	}
	// The seed is in the store but not yet authoritative; roll it back unless
	// both persistence and the cert login succeed. seedCredential deliberately
	// hands it over intact rather than committing, because only here do we know
	// the replacement actually works.
	committed := false
	defer func() {
		if !committed {
			rollbackCertRotation(store, newCred.Handle)
		}
	}()
	// Log in before persisting: certLogin consumes only the in-memory cert and
	// signer, so proving the replacement works first means a failed login never
	// makes the new envelope authoritative. On a first enrolment credential.json
	// is simply never written; on a re-seed the previous envelope survives
	// untouched — either way the deferred rollback discards the abandoned
	// replacement and no reader is left pointing at a credential the store no
	// longer holds.
	if err := m.certLogin(ctx, newCred, signer); err != nil {
		return err
	}
	if err := saveCredential(p.StorageDir, newCred); err != nil {
		return fmt.Errorf("persist mtls credential: %w", err)
	}
	committed = true
	// Retire whatever this replaced. cred is nil on a first enrolment and
	// non-nil when an existing credential was present but unusable (expired,
	// wrong identity, failed login) — in which case its container and leaf are
	// exactly the stale artefacts that must not linger.
	var oldHandle []byte
	if cred != nil {
		oldHandle = cred.Handle
	}
	// Deliberately swept but NOT revoked, unlike reissue. This path is reached
	// because the old credential could not be used, and "could not be used" is
	// not proof it should be retired at the CA: a transient Vault error, a
	// clock skew, or a cert-role change all land here with a certificate that
	// is still perfectly valid, and revoking on that evidence would destroy a
	// working credential every other host sharing it still depends on. Rotation
	// is the case where supersession is certain, because dotvault just minted
	// the replacement from the original. Any backlog the old envelope carried
	// is preserved for the same reason it exists — those serials were retired
	// deliberately and are merely awaiting the CA.
	commitCertRotation(store, newCred.Handle, oldHandle)
	if cred != nil {
		newCred.PendingRevocations = cred.PendingRevocations
		m.persistPendingRevocations(newCred, cred.PendingRevocations)
	}
	WarnUnrestrictedPolicy(m.Policy)
	return nil
}

// tryExistingCredential loads the stored signer, optionally rotates a cert
// inside the re-issue window, and logs in. Returns (true, nil) when the
// Manager's client now holds an operational token.
// ErrNoCertCredential marks a certificate-login failure whose cause is local to
// this host — no credential enrolled, an unreadable envelope, an expired or
// wrong-identity certificate, or an unavailable secure store — as opposed to a
// failure talking to Vault.
//
// The distinction is load-bearing for the public client facade. A Vault that is
// unreachable, rate-limited, or 5xx-ing is a retry condition; a missing or
// unusable credential means the host must be enrolled. A transport failure
// carries no HTTP response, so a caller cannot reliably tell the two apart by
// inspecting the error alone — hence an explicit sentinel rather than a
// heuristic. See client.AuthenticateCached.
var ErrNoCertCredential = errors.New("no usable certificate credential on this host")

// ErrTokenAtRest marks a login that succeeded at Vault but could not honour the
// no-token-at-rest guarantee, because a token file already on disk could not be
// removed (on Windows, typically a sharing violation from antivirus, backup, or
// indexing holding it open).
//
// It exists so callers can tell this apart from "the credential on this host is
// unusable". They look identical — both are just an error out of certLogin —
// but they call for opposite responses: an unusable credential should be
// re-seeded, whereas here the certificate is perfectly good and re-seeding
// fixes nothing. Without the distinction authenticateMTLS treats an undeletable
// file as a broken credential and falls through to a full interactive bootstrap
// (an OIDC browser flow or an LDAP TTY prompt) plus a fresh PKI issuance, which
// then hits the same undeletable file and fails anyway — so a file the OS
// briefly will not unlink costs a human prompt and a wasted certificate on
// every startup.
var ErrTokenAtRest = errors.New("token file could not be removed")

// CertLoginFromStore mints a fresh operational token by performing the
// certificate login against the credential this host already holds. It is the
// non-interactive half of certificate auth, split out so callers that must
// never involve a human can use it:
//
//   - the daemon's unattended token recovery (LifecycleManager.SetRecover),
//     which is what makes certificate auth headless in steady state — the cert
//     login otherwise happens only at startup, and ReissueIfDue rotates the
//     *certificate*, not the token, so an expired token used to strand the
//     daemon until a restart despite the credential sitting right there;
//   - the public client facade (client.AuthenticateCached), where a consumer
//     on a cert-auth host can obtain a token without a cached one and without
//     ever prompting.
//
// It deliberately does NOT fall back to the bootstrap flow. Bootstrap needs a
// human; these callers have none — a background goroutine with nobody
// attached, or a library inside someone else's process. Spontaneously
// launching a browser, or blocking on a login that will never come, would be
// worse than reporting the failure. A host whose certificate is missing or
// expired past re-issue reports an error here and is handled by the caller.
//
// It also does not rotate the certificate (see loginWithCredential): rotation
// belongs to the startup path and the hourly re-issue check, which own it and
// must not race a second writer.
//
// Safe to call repeatedly: it re-reads the credential each time and does
// nothing beyond a fresh login.
func (m *Manager) CertLoginFromStore(ctx context.Context) error {
	p := m.MTLS
	if p == nil {
		return fmt.Errorf("%w: vault.mtls is not configured", ErrNoCertCredential)
	}
	if p.StorageDir == "" {
		// An empty storage directory would make loadCredential probe a
		// cwd-relative "credential.json" (filepath.Join("", …)) and authenticate
		// as whatever certificate happens to sit in the working directory. Treat
		// it as "no credential" instead — the same reasoning DefaultTokenFile
		// uses to return "" rather than a cwd-relative token path. This arises
		// only from the client facade's home-less-host fallback
		// (defaultMTLSStorageDir → ""); the daemon always sets StorageDir.
		return fmt.Errorf("%w: no credential storage directory", ErrNoCertCredential)
	}
	store, err := securestore.Open(securestore.ModeForMethod(p.Method))
	if err != nil {
		return fmt.Errorf("%w: open secure store: %w", ErrNoCertCredential, err)
	}
	defer store.Close()

	cred, err := loadCredential(p.StorageDir)
	if err != nil {
		return fmt.Errorf("%w: load certificate credential: %w", ErrNoCertCredential, err)
	}
	if cred == nil {
		return fmt.Errorf("%w: a bootstrap is required", ErrNoCertCredential)
	}

	// Login only — deliberately NOT tryExistingCredential, which also rotates
	// the certificate when inside the re-issue window. Rotation is the hourly
	// ReissueIfDue goroutine's job; doing it here too would let a recovery and
	// that goroutine mint certificates concurrently and race on the credential
	// envelope. Recovery's job is to obtain a token, nothing more.
	return m.loginWithCredential(ctx, store, cred)
}

// loginWithCredential validates a stored credential and performs the cert
// login. It is the shared core of the startup path (tryExistingCredential,
// which additionally rotates a near-expiry certificate) and unattended
// recovery (CertLoginFromStore, which must not).
func (m *Manager) loginWithCredential(ctx context.Context, store securestore.Storage, cred *sealedCredential) error {
	if cred.Identity != "" && m.Username != "" && cred.Identity != m.Username {
		return fmt.Errorf("%w: credential belongs to %q, not the current user %q", ErrNoCertCredential, cred.Identity, m.Username)
	}
	if !cred.NotAfter.IsZero() && time.Now().After(cred.NotAfter) {
		return fmt.Errorf("%w: certificate expired at %s", ErrNoCertCredential, cred.NotAfter.Format(time.RFC3339))
	}
	signer, err := store.Load(cred.Handle)
	if err != nil {
		return fmt.Errorf("%w: load key from secure store: %w", ErrNoCertCredential, err)
	}
	return m.certLogin(ctx, cred, signer)
}

func (m *Manager) tryExistingCredential(ctx context.Context, store securestore.Storage, cred *sealedCredential) (bool, error) {
	if err := m.loginWithCredential(ctx, store, cred); err != nil {
		return false, err
	}

	// Proactively rotate if we are inside the re-issue window. A failure here
	// is non-fatal: we already hold an operational token on the valid cert.
	if m.MTLS.ReissueBefore > 0 && !cred.NotAfter.IsZero() &&
		time.Now().After(cred.NotAfter.Add(-m.MTLS.ReissueBefore)) {
		if err := m.reissue(ctx, store, cred); err != nil {
			slog.Warn("certificate re-issuance failed; continuing on the current certificate",
				"not_after", cred.NotAfter.Format(time.RFC3339), "error", err)
		}
	}
	return true, nil
}

// ReissueIfDue rotates the certificate when it is inside the re-issue window,
// using the current operational Vault token (no human). It is a no-op for
// non-cert methods, when no credential exists, or when the cert is not yet due
// for rotation. The daemon calls this periodically so a long-running process
// whose token keeps renewing still rotates its certificate before expiry —
// without this, a warm daemon never re-enters the cert flow and the cert could
// expire unrotated. Safe to call repeatedly: after one successful rotation the
// fresh NotAfter moves out of the window and subsequent calls return nil.
func (m *Manager) ReissueIfDue(ctx context.Context) error {
	if m.MTLS == nil || BaseMethod(m.AuthMethod) != "mtls" || m.MTLS.ReissueBefore <= 0 {
		return nil
	}
	cred, err := loadCredential(m.MTLS.StorageDir)
	if err != nil || cred == nil {
		return err
	}
	if cred.NotAfter.IsZero() || time.Now().Before(cred.NotAfter.Add(-m.MTLS.ReissueBefore)) {
		return nil // not due
	}
	store, err := securestore.Open(securestore.ModeForMethod(m.MTLS.Method))
	if err != nil {
		return fmt.Errorf("open secure store: %w", err)
	}
	defer store.Close()
	return m.reissue(ctx, store, cred)
}

// reissue mints a fresh certificate using the current (still-valid) Vault
// token, writes a new envelope, and adopts the new operational token.
func (m *Manager) reissue(ctx context.Context, store securestore.Storage, old *sealedCredential) error {
	slog.Info("rotating mtls certificate before expiry", "not_after", old.NotAfter.Format(time.RFC3339))
	cn, err := m.renderCommonName()
	if err != nil {
		return err
	}
	signer, handle, err := store.Generate(securestore.KeyType(m.MTLS.KeyType), m.MTLS.KeyBits, m.MTLS.SealToPCRs)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	// From here the replacement exists in the store but is not yet
	// authoritative. Every failure path must roll it back, or a store that
	// accumulates state (the OS-native backend: one CNG container and one
	// CurrentUser\My leaf per rotation) is left holding an orphan — and, for
	// the leaf, a second simultaneously valid client identity a browser could
	// offer. The old credential remains usable throughout, which is the point
	// of doing this two-phase.
	committed := false
	newHandle := handle
	defer func() {
		if !committed {
			rollbackCertRotation(store, newHandle)
		}
	}()

	issued, err := m.signOrIssue(ctx, m.VaultClient, signer, cn)
	if err != nil {
		return err
	}
	newCred, err := m.buildCredential(store, issued, handle)
	if err != nil {
		return err
	}
	if err := storeCertInNativeStore(store, newCred); err != nil {
		return err
	}
	// StoreCert may re-key the handle (the OS backend records the installed
	// leaf), so roll back whatever the credential now carries.
	newHandle = newCred.Handle
	// Log in before persisting: certLogin consumes only the in-memory cert and
	// signer, so a failed login leaves the old envelope authoritative (the
	// deferred rollback discards the replacement's container and leaf) rather
	// than stranding credential.json on a credential that was just rolled back.
	if err := m.certLogin(ctx, newCred, signer); err != nil {
		return err
	}
	if err := saveCredential(m.MTLS.StorageDir, newCred); err != nil {
		return fmt.Errorf("persist rotated credential: %w", err)
	}
	// Persisted and operational: the replacement is now authoritative, so the
	// superseded container and leaf can go.
	committed = true
	// Only once the superseded certificate is actually gone from the OS-native
	// store is it safe to revoke it at the CA — and "actually gone" means the
	// sweep's outcome, not merely this call's position in the function. See
	// retireSupersededCertificates for why.
	swept := commitCertRotation(store, newCred.Handle, old.Handle)
	m.persistPendingRevocations(newCred, m.retireSupersededCertificates(ctx, old, swept))
	return nil
}

// persistPendingRevocations records the serials that still need revoking onto
// the now-authoritative envelope, so the next rotation retries them.
//
// It is a second write of a file saved moments ago, which is worth the cost
// only because the alternative loses the serial entirely: the envelope has
// already been overwritten with the replacement, so a failed revocation would
// survive nowhere but one WARN line. The common case writes nothing — there is
// no list to record when every revocation succeeded, which is almost always.
//
// Its own failure is advisory for the usual reason: the rotation is complete
// and the credential is in use. The cost is only that these serials are not
// retried, which is where they already were.
func (m *Manager) persistPendingRevocations(cred *sealedCredential, pending []string) {
	if len(pending) == 0 && len(cred.PendingRevocations) == 0 {
		return
	}
	cred.PendingRevocations = pending
	if err := saveCredential(m.MTLS.StorageDir, cred); err != nil {
		slog.Warn("could not record certificates still awaiting revocation; they will not be retried",
			"serials", pending, "error", err)
	}
}

// maxPendingRevocations bounds the retry list carried in the envelope. A
// deployment whose policy lacks pki/revoke accumulates one entry per rotation
// forever, and an unbounded list would grow the envelope without ever helping:
// past the cap the oldest entries are the least worth retrying, being the
// closest to expiring on their own.
const maxPendingRevocations = 16

// revocationTimeout bounds the revoke calls so a slow or hung Vault cannot
// hold up a rotation that has, by this point, already succeeded.
const revocationTimeout = 30 * time.Second

// retireSupersededCertificates revokes the certificate a rotation replaced —
// plus any earlier ones whose revocation has not yet succeeded — and returns
// the serials still outstanding, for the caller to carry forward.
//
// The OS-store sweep and this are two halves of one retirement and neither
// substitutes for the other: removing the leaf from CurrentUser\My stops *this
// host* offering it, but the certificate remains valid at Vault until its own
// NotAfter, so any copy taken before the rotation keeps working for the rest of
// that lifetime. Only the CA can end it.
//
// It must run AFTER the sweep, and only when the sweep actually succeeded —
// position in the flow is not the guarantee, the outcome is. A certificate
// revoked while still installed is one every browser and client on the host may
// go on choosing, and because a sweep failure is not retried it stays installed
// permanently, so revoking anyway would convert a successful rotation into
// indefinitely broken mTLS. Declining to revoke leaves the milder state: a
// certificate that still works and can be retired later.
//
// Failures are logged and returned as outstanding work, never surfaced as an
// error: by this point the replacement is persisted, operational, and the old
// artefacts are gone. Failing here would report a broken rotation for a
// credential the daemon is already using and, because the caller retries, mint
// a fresh certificate on every attempt. The retry list is what stops that
// leniency from silently accumulating valid certificates — the failure mode
// this whole feature exists to close — when the cause is persistent, which the
// commonest one (a policy without pki/revoke) is.
func (m *Manager) retireSupersededCertificates(ctx context.Context, old *sealedCredential, swept error) []string {
	if old == nil {
		return nil
	}
	// Inherited backlog first: these were swept in an earlier rotation, so
	// nothing is presenting them and only the CA half is outstanding.
	outstanding := append([]string(nil), old.PendingRevocations...)

	if swept != nil {
		slog.Warn("not revoking the superseded certificate: it is still installed in the OS certificate store, "+
			"and revoking one the host may still present would break mTLS for it",
			"serial", supersededSerial(old), "error", swept)
	} else if serial := supersededSerial(old); serial != "" {
		outstanding = append(outstanding, serial)
	}

	// The rotation itself is already complete, so this must not inherit a
	// cancellation that would otherwise strand the serials — but it must not
	// hang either.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationTimeout)
	defer cancel()

	var failed []string
	for _, serial := range outstanding {
		if err := m.VaultClient.RevokeCertificate(rctx, m.MTLS.PKIMount, serial); err != nil {
			slog.Warn("could not revoke a superseded certificate; it stays valid at Vault until it expires. "+
				"Grant update on <pki_mount>/revoke to this host's Vault policy, or revoke it manually with "+
				"`vault write "+m.MTLS.PKIMount+"/revoke serial_number=<serial>`",
				"serial", serial, "pki_mount", m.MTLS.PKIMount, "error", err)
			failed = append(failed, serial)
			continue
		}
		slog.Info("revoked a superseded mtls certificate", "serial", serial)
	}
	if len(failed) > maxPendingRevocations {
		dropped := failed[:len(failed)-maxPendingRevocations]
		slog.Warn("too many certificates are awaiting revocation; dropping the oldest, which are closest to expiring anyway",
			"dropped", dropped, "limit", maxPendingRevocations)
		failed = failed[len(failed)-maxPendingRevocations:]
	}
	return failed
}

// supersededSerial derives the serial to revoke from the credential's own
// certificate, falling back to the recorded field.
//
// The certificate is the authority and the field is not, because the field has
// had two provenances: a Vault-signed credential records the colon-hex serial
// Vault returned, while a BYO import recorded big.Int.String() — a decimal
// string naming nothing Vault has heard of. Normalising new writes fixes new
// envelopes only; envelopes already on disk from an earlier build still carry
// the decimal form, and those are exactly the ones a first post-upgrade
// rotation would try to revoke. Deriving from CertPEM sidesteps the provenance
// question entirely and needs no migration.
func supersededSerial(cred *sealedCredential) string {
	if leaf, err := leafCert(cred.CertPEM); err == nil {
		if serial := vault.FormatSerial(leaf.SerialNumber); serial != "" {
			return serial
		}
	}
	// An envelope written before serials were recorded, or one whose CertPEM
	// will not parse, leaves nothing to name; the caller sends nothing rather
	// than a serial Vault would reject.
	return cred.Serial
}

// seedCredential produces a fresh credential via BYO or LDAP/OIDC bootstrap.
func (m *Manager) seedCredential(ctx context.Context, store securestore.Storage) (*sealedCredential, crypto.Signer, error) {
	p := m.MTLS
	cn, err := m.renderCommonName()
	if err != nil {
		return nil, nil, err
	}

	// BYO: import an existing cert+key, skipping bootstrap.
	if p.BYOCert != "" {
		signer, handle, certPEM, notAfter, serial, err := m.importBYO(store)
		if err != nil {
			return nil, nil, err
		}
		cred := &sealedCredential{
			Method:   p.Method,
			Backend:  store.Capabilities().Name,
			CertPEM:  certPEM,
			Handle:   handle,
			Serial:   serial,
			NotAfter: notAfter,
			Identity: m.Username,
			IssuedAt: time.Now(),
		}
		return cred, signer, nil
	}

	// Bootstrap: human login → PKI sign/issue.
	slog.Info("no usable mtls certificate; bootstrapping via human login", "method", p.BootstrapMethod)
	bootClient, err := m.runBootstrap(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap login: %w", err)
	}
	signer, handle, err := store.Generate(securestore.KeyType(p.KeyType), p.KeyBits, p.SealToPCRs)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	// As in reissue: past this point a replacement exists in the store but is
	// not authoritative until the caller has persisted it and completed the
	// cert login. Any failure here must not leave an orphaned container or a
	// second usable leaf behind. The caller commits (see authenticateMTLS).
	seeded := false
	newHandle := handle
	defer func() {
		if !seeded {
			rollbackCertRotation(store, newHandle)
		}
	}()
	// PKI sign runs on the bootstrap client, not m.VaultClient: the broad,
	// PKI-capable bootstrap token must never be installed on the shared client
	// (which the web server exposes via /api/v1/token before the final cert
	// login). Only certLogin adopts the final, downscoped cert-auth token.
	issued, err := m.signOrIssue(ctx, bootClient, signer, cn)
	if err != nil {
		return nil, nil, err
	}
	cred, err := m.buildCredential(store, issued, handle)
	if err != nil {
		return nil, nil, err
	}
	if err := storeCertInNativeStore(store, cred); err != nil {
		return nil, nil, err
	}
	newHandle = cred.Handle
	// Handed to the caller intact; it owns persistence, the cert login, and the
	// commit that finally retires the superseded credential.
	seeded = true
	return cred, signer, nil
}

// commitCertRotation finalises a rotation whose replacement credential is
// persisted and operational, letting a CertLifecycle backend drop the
// superseded key container and leaf certificate. A no-op — and so a success —
// for backends without the capability (file, tpm), where the handle IS the key
// material and overwriting the envelope is the whole transaction.
//
// It logs its own failure and the caller must not fail the rotation over one:
// the replacement is already live, and rejecting a working daemon because a
// stale artefact could not be swept would be the worse trade. The error is
// nonetheless returned, because one caller does need the outcome — revocation
// is only safe once the certificate is actually gone from the store, and a
// swallowed error there produces a revoked certificate the host keeps
// presenting. Reporting is this function's job; deciding is the caller's.
func commitCertRotation(store securestore.Storage, newHandle, oldHandle []byte) error {
	cl, ok := store.(securestore.CertLifecycle)
	if !ok {
		return nil
	}
	if err := cl.CommitCert(newHandle, oldHandle); err != nil {
		slog.Warn("could not remove the superseded certificate credential; it remains in the store", "error", err)
		return err
	}
	return nil
}

// rollbackCertRotation discards a replacement credential that never became
// operational, so a failed rotation leaves no orphaned key container or leaf
// certificate behind and the previous credential stays authoritative. Like
// commitCertRotation it is a no-op without the capability, and its errors are
// advisory — the caller is already returning the failure that matters.
func rollbackCertRotation(store securestore.Storage, newHandle []byte) {
	cl, ok := store.(securestore.CertLifecycle)
	if !ok {
		return
	}
	if err := cl.RollbackCert(newHandle); err != nil {
		slog.Warn("could not clean up the abandoned replacement credential", "error", err)
	}
}

// storeCertInNativeStore pushes the issued certificate into the OS-native
// certificate store when the secure-store backend supports it (the "os"
// backend), so other software — browsers above all — can present it for mTLS.
// For the file and tpm backends, which hold only the key (the cert lives in the
// credential envelope), it is a no-op. It updates cred.Handle with the value to
// persist going forward.
func storeCertInNativeStore(store securestore.Storage, cred *sealedCredential) error {
	cs, ok := store.(securestore.CertStorer)
	if !ok {
		return nil
	}
	newHandle, err := cs.StoreCert(cred.Handle, cred.CertPEM)
	if err != nil {
		return fmt.Errorf("store certificate in OS-native store: %w", err)
	}
	cred.Handle = newHandle
	return nil
}

// runBootstrap runs the configured human-credential method to obtain a
// short-lived token authorised for PKI issuance, returning the isolated client
// that holds it. The bootstrap login runs on a *sibling* of m.VaultClient
// (same connection, separate token), never on m.VaultClient itself: the broad,
// PKI-capable bootstrap token must not be installed on the shared client, which
// the web server starts before auth and exposes via /api/v1/token — otherwise
// that broad token would be retrievable during bootstrap and would linger if a
// later step (PKI sign, cert login, downscope) failed. The caller uses the
// returned client for PKI signing; only certLogin adopts the final, downscoped
// cert-auth token onto m.VaultClient.
//
// The bootstrap Manager carries no TokenFilePath, so the broad token is never
// written to the on-disk cache either (WriteTokenFile treats "" as a no-op).
//
// When m.BootstrapLogin is set it replaces the CLI oidc/ldap dispatch entirely:
// the daemon obtains the transient token another way (the web login view) and
// hands it back here. Everything else is unchanged.
func (m *Manager) runBootstrap(ctx context.Context) (*vault.Client, error) {
	bootClient, err := m.VaultClient.NewSibling("")
	if err != nil {
		return nil, fmt.Errorf("build bootstrap client: %w", err)
	}
	// Browser-driven bootstrap: when the daemon supplies a BootstrapLogin (the
	// web login view's flow), use the token it returns instead of running a CLI
	// oidc/ldap flow, which needs a browser or TTY on this host. The same
	// invariants hold either way — the token is installed on the sibling only,
	// never downscoped, never written to a token file, and never accompanied by
	// the transition notice.
	if m.BootstrapLogin != nil {
		token, err := m.BootstrapLogin(ctx)
		if err != nil {
			return nil, err
		}
		if token == "" {
			return nil, fmt.Errorf("bootstrap login returned an empty token")
		}
		bootClient.SetToken(token)
		return bootClient, nil
	}

	boot := &Manager{
		VaultClient:      bootClient,
		AuthMethod:       m.MTLS.BootstrapMethod,
		AuthMount:        m.MTLS.BootstrapMount,
		AuthRole:         m.AuthRole,
		Username:         m.Username,
		OIDCCallbackPort: m.OIDCCallbackPort,
	}
	// Dispatch the bootstrap login directly rather than through boot.Login: the
	// bootstrap token is transient and never operational, so it must not emit
	// the "set vault.policies" transition notice that Login attaches to a real
	// oidc/ldap login. The rest of Login is a no-op for a bootstrap anyway —
	// boot has no TokenSocket (no peer borrow) and bootstrap_method is plain
	// oidc/ldap (never +tpm, so no TPM preflight), both validated at config
	// load — so the only behavioural difference of bypassing Login is skipping
	// the notice.
	switch BaseMethod(boot.AuthMethod) {
	case "oidc":
		if err := boot.authenticateOIDC(ctx); err != nil {
			return nil, err
		}
	case "ldap":
		if err := boot.authenticateLDAP(ctx); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported mtls bootstrap_method %q (want oidc or ldap)", m.MTLS.BootstrapMethod)
	}
	return bootClient, nil
}

// signOrIssue mints a certificate for the signer's public key. It prefers the
// PKI sign endpoint (the private key never leaves the host); if the role
// forbids signing it can be retried via issue, but issue would discard our
// hardware key, so it is only attempted when no PKI role offers sign — left as
// the sign path for v1.
func (m *Manager) signOrIssue(ctx context.Context, vc *vault.Client, signer crypto.Signer, commonName string) (*vault.IssuedCert, error) {
	csrPEM, err := buildCSR(signer, commonName)
	if err != nil {
		return nil, err
	}
	issued, err := vc.SignCSR(ctx, m.MTLS.PKIMount, m.MTLS.PKIRole, csrPEM, commonName, m.MTLS.TTL)
	if err != nil {
		return nil, fmt.Errorf("PKI sign: %w", err)
	}
	return issued, nil
}

// buildCredential assembles an envelope from a freshly signed certificate.
func (m *Manager) buildCredential(store securestore.Storage, issued *vault.IssuedCert, handle []byte) (*sealedCredential, error) {
	leaf, err := leafCert(issued.CertPEM)
	if err != nil {
		return nil, err
	}
	return &sealedCredential{
		Method:   m.MTLS.Method,
		Backend:  store.Capabilities().Name,
		CertPEM:  issued.CertPEM,
		Handle:   handle,
		Serial:   issued.Serial,
		NotAfter: leaf.NotAfter,
		Identity: m.Username,
		IssuedAt: time.Now(),
	}, nil
}

// importBYO loads, validates, and seals a bring-your-own certificate and key.
func (m *Manager) importBYO(store securestore.Storage) (crypto.Signer, []byte, string, time.Time, string, error) {
	certPEM, err := os.ReadFile(m.MTLS.BYOCert)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("read byo cert: %w", err)
	}
	keyPEM, err := os.ReadFile(m.MTLS.BYOKey)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("read byo key: %w", err)
	}
	leaf, err := leafCert(string(certPEM))
	if err != nil {
		return nil, nil, "", time.Time{}, "", err
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("byo certificate is not currently valid (%s – %s)",
			leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("parse byo key: %w", err)
	}
	signer, handle, err := store.Import(key, m.MTLS.SealToPCRs)
	if err != nil {
		return nil, nil, "", time.Time{}, "", fmt.Errorf("import byo key into secure store: %w", err)
	}
	return signer, handle, string(certPEM), leaf.NotAfter, vault.FormatSerial(leaf.SerialNumber), nil
}

// certLogin assembles a tls.Certificate from the stored cert and signer, dials
// Vault's cert auth method on a dedicated cert-presenting client, and adopts
// the operational token onto the Manager's main client and token file.
func (m *Manager) certLogin(ctx context.Context, cred *sealedCredential, signer crypto.Signer) error {
	tlsCert, err := buildTLSCertificate(cred.CertPEM, signer)
	if err != nil {
		return err
	}
	certClient, err := vault.NewClient(vault.Config{
		Address:       m.MTLS.VaultAddress,
		CACert:        m.MTLS.CACert,
		TLSSkipVerify: m.MTLS.TLSSkipVerify,
		ClientCert:    &tlsCert,
	})
	if err != nil {
		return fmt.Errorf("build cert-auth client: %w", err)
	}
	if err := certClient.LoginCert(ctx, m.MTLS.CertMount, m.MTLS.CertRole); err != nil {
		return err
	}
	// Downscope through certClient (which presents the client certificate), not
	// m.VaultClient: on a Vault listener that requires a client cert on every
	// request, the auth/token/create call must present it too. certClient's
	// sibling inherits the cert via NewSibling. m.VaultClient adopts only the
	// resulting downscoped token.
	token, err := Downscope(ctx, certClient, certClient.Token(), m.Policy)
	if err != nil {
		return err
	}
	// The two arms straddle adoption deliberately (see PersistTokenAtRest for
	// which methods take which). Removal runs BEFORE the token is installed, so
	// a login that cannot honour the no-token-at-rest guarantee installs no new
	// token — adopting first and erroring afterwards would report a failed login
	// while leaving a live token on the shared client, which in daemon+web mode
	// GET /api/v1/token would serve. Ordering it first needs no rollback, and so
	// has no rollback to forget. Unlike the write below, which only warns, a
	// removal failure is fatal: a token that could not be removed is a token
	// still on disk.
	persist := PersistTokenAtRest(m.AuthMethod)
	if !persist {
		if err := RemoveTokenFile(m.TokenFilePath); err != nil {
			return fmt.Errorf("auth_method %s requires no token at rest, but the existing token file could not be removed: %w: %w", m.AuthMethod, ErrTokenAtRest, err)
		}
	}
	m.VaultClient.SetToken(token)
	if persist {
		if err := WriteTokenFile(m.TokenFilePath, token, SealTokenAtRest(m.AuthMethod)); err != nil {
			slog.Warn("failed to write token file", "error", err)
		}
	}
	slog.Info("mtls authentication successful", "method", m.MTLS.Method, "serial", cred.Serial,
		"not_after", cred.NotAfter.Format(time.RFC3339))
	return nil
}

func (m *Manager) renderCommonName() (string, error) {
	cn := m.MTLS.CommonName
	if cn == "" {
		return m.Username, nil
	}
	rendered, err := tmpl.Render("mtls-common-name", cn, map[string]any{"user": m.Username})
	if err != nil {
		return "", fmt.Errorf("render common_name template: %w", err)
	}
	return rendered, nil
}

// buildCSR creates a PEM-encoded CSR over the given signer.
func buildCSR(signer crypto.Signer, commonName string) (string, error) {
	tmplCSR := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmplCSR, signer)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// buildTLSCertificate assembles a tls.Certificate from a PEM chain and a
// crypto.Signer (which may be hardware-backed).
func buildTLSCertificate(certPEM string, signer crypto.Signer) (tls.Certificate, error) {
	var der [][]byte
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = append(der, block.Bytes)
		}
	}
	if len(der) == 0 {
		return tls.Certificate{}, fmt.Errorf("no CERTIFICATE block in credential")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return tls.Certificate{Certificate: der, PrivateKey: signer, Leaf: leaf}, nil
}

// leafCert parses the first CERTIFICATE block from a PEM chain.
func leafCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in PEM input")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePrivateKey decodes a PEM private key in PKCS#8, EC, or PKCS#1 form.
func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}
