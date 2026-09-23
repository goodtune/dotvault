package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/goodtune/dotvault/internal/peer"
	"github.com/goodtune/dotvault/internal/securestore"
	"github.com/goodtune/dotvault/internal/vault"
)

// hardwareAvailable is the TPM preflight, indirected for testing. It reports
// nil when the platform hardware backend can be opened, else why it cannot.
var hardwareAvailable = securestore.HardwareAvailable

// Manager orchestrates Vault authentication.
type Manager struct {
	VaultClient   *vault.Client
	TokenFilePath string
	// AuthMethod is the configured method: "oidc", "ldap", "token", "mtls",
	// "mtls+tpm", or "mtls+os". A "+tpm" suffix on any base method (e.g.
	// "oidc+tpm") also requests TPM-sealing of the cached token file at rest;
	// for "mtls+tpm" that is in addition to the cert key the cert flow already
	// seals. The "mtls+os" modifier instead stores the cert key in the OS-native
	// certificate store (it does not seal the token).
	AuthMethod string
	AuthMount  string // auth mount path
	AuthRole   string // optional role
	Username   string
	// OIDCCallbackPort is the fixed local TCP port authenticateOIDC binds for
	// the OAuth redirect_uri (vault.oidc_callback_port). Zero defaults to
	// 8250 (the `vault` CLI's own default); if that port is unavailable,
	// authenticateOIDC falls back to a random port. See oidc.go.
	OIDCCallbackPort int
	// Borrower, when non-nil, is tried first by Login: a live token borrowed
	// from a peer dotvault (dotvault-to-dotvault sharing) means no browser,
	// TTY or TPM is needed. Callers pass a *peer.Pool built from
	// config.TokenBorrowSockets. Best-effort; a nil Borrower is skipped.
	Borrower peer.Borrower
	// Policy narrows a freshly-minted login token to a least-privilege child
	// token (vault.policies / vault.no_default_policy). The zero value applies
	// no narrowing — the token carries every policy the auth role granted,
	// today's behaviour. Consulted by the oidc/ldap/mtls flows; the bootstrap
	// login that mints an mtls cert is deliberately left un-narrowed because it
	// needs the pki/sign capability.
	Policy PolicyConstraint
	// MTLS is required when the base auth method is "mtls".
	MTLS *MTLSParams
	// BootstrapLogin, when non-nil, supplies the transient bootstrap token for
	// the mTLS certificate bootstrap instead of running the CLI oidc/ldap flow.
	// It returns a raw Vault token that MUST NOT have been downscoped (the
	// bootstrap needs pki/sign, which an operational policy set would strip) and
	// MUST NOT have been adopted onto any shared client.
	BootstrapLogin func(ctx context.Context) (string, error)
}

// Authenticate attempts to authenticate with Vault.
// It first tries to reuse an existing token, then falls back to the configured method.
func (m *Manager) Authenticate(ctx context.Context) error {
	// Step 1: Try existing token.
	//
	// Under a method that keeps no token at rest (mtls+os) the file is excluded:
	// anything found there is stale, and ADOPTING it is worse than merely
	// leaving it — reuse returns before Login, so certLogin never runs and never
	// removes it. A sync-only host would then use a plaintext token
	// indefinitely, which is precisely the exposure this method exists to close.
	// DOTVAULT_TOKEN still applies: it is operator-supplied in the environment,
	// not something dotvault persisted.
	token := ReadTokenEnv()
	if PersistTokenAtRest(m.AuthMethod) {
		token = ResolveToken(m.TokenFilePath)
	}
	if token != "" {
		m.VaultClient.SetToken(token)
		_, err := m.VaultClient.LookupSelf(ctx)
		if err == nil {
			slog.Info("reusing existing vault token")
			return nil
		}
		slog.Warn("existing token invalid, proceeding to fresh auth", "error", err)
		m.VaultClient.SetToken("")
	}

	return m.Login(ctx)
}

// borrow is a nil-safe Borrow.
func borrow(ctx context.Context, b peer.Borrower) (string, string) {
	if b == nil {
		return "", ""
	}
	return b.Borrow(ctx)
}

// Login runs the configured fresh-auth flow unconditionally, without
// attempting to reuse an existing token. Used by `dotvault login` and as
// the fallback path inside Authenticate.
func (m *Manager) Login(ctx context.Context) error {
	// Peer token borrow. Before running an interactive flow, try to fetch a
	// live token from a peer dotvault (dotvault-to-dotvault sharing). This
	// runs ahead of the TPM preflight and the method switch so a host that
	// can borrow never needs a browser, a TTY, or a TPM. Best-effort: no
	// borrower, or an unusable token, falls through to the configured auth
	// method exactly as before. The borrowed token is held in memory only
	// (not written to the token file), so the peer stays the single owner
	// and we re-borrow on the next login rather than caching a copy that
	// could go stale — and the "+tpm" sealing question never arises for it.
	if token, source := borrow(ctx, m.Borrower); token != "" {
		m.VaultClient.SetToken(token)
		if _, err := m.VaultClient.LookupSelf(ctx); err == nil {
			slog.Info("using vault token borrowed from peer socket", "socket", source)
			return nil
		}
		slog.Warn("token from peer socket is not usable, proceeding to configured auth flow", "socket", source)
		m.VaultClient.SetToken("")
	}

	base := BaseMethod(m.AuthMethod)

	// Preflight: a "+tpm" method on a host with no TPM must fail fast and
	// clearly, rather than authenticating and then silently failing to persist
	// the sealed token. The "mtls" flow owns its own (more specific) hardware
	// check for the cert key, so skip the generic preflight there.
	if base != "mtls" && SealTokenAtRest(m.AuthMethod) {
		if err := hardwareAvailable(); err != nil {
			return fmt.Errorf("auth_method %q requests TPM token sealing but no hardware backend is available on this host (%w); use auth_method %q to keep the cached token on disk, or provision a TPM",
				m.AuthMethod, err, base)
		}
	}

	switch base {
	case "oidc":
		if err := m.authenticateOIDC(ctx); err != nil {
			return err
		}
	case "ldap":
		if err := m.authenticateLDAP(ctx); err != nil {
			return err
		}
	case "mtls":
		// authenticateMTLS emits the transition notice once per operational
		// login itself (and suppresses it on the bootstrap sub-login and on
		// certificate reissue), so Login does not warn for mtls.
		return m.authenticateMTLS(ctx)
	case "token":
		return fmt.Errorf("auth method 'token' requires a valid token in %s or DOTVAULT_TOKEN env", m.TokenFilePath)
	default:
		return fmt.Errorf("unsupported auth method: %q", m.AuthMethod)
	}
	// Reached only by the oidc/ldap base methods, which adopt the operational
	// token directly above. The mtls bootstrap reaches authenticateOIDC/LDAP
	// through runBootstrap, not this dispatch, so it never warns here.
	WarnUnrestrictedPolicy(m.Policy)
	return nil
}
