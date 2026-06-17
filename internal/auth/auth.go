package auth

import (
	"context"
	"fmt"
	"log/slog"

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
	// AuthMethod is the configured method: "oidc", "ldap", "token", "mtls", or
	// "mtls+tpm". A "+tpm" suffix on any base method (e.g. "oidc+tpm") also
	// requests TPM-sealing of the cached token file at rest; for "mtls+tpm"
	// that is in addition to the cert key the cert flow already seals.
	AuthMethod string
	AuthMount  string // auth mount path
	AuthRole   string // optional role
	Username   string
	// MTLS is required when the base auth method is "mtls".
	MTLS *MTLSParams
}

// Authenticate attempts to authenticate with Vault.
// It first tries to reuse an existing token, then falls back to the configured method.
func (m *Manager) Authenticate(ctx context.Context) error {
	// Step 1: Try existing token
	token := ResolveToken(m.TokenFilePath)
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

// Login runs the configured fresh-auth flow unconditionally, without
// attempting to reuse an existing token. Used by `dotvault login` and as
// the fallback path inside Authenticate.
func (m *Manager) Login(ctx context.Context) error {
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
		return m.authenticateOIDC(ctx)
	case "ldap":
		return m.authenticateLDAP(ctx)
	case "mtls":
		return m.authenticateMTLS(ctx)
	case "token":
		return fmt.Errorf("auth method 'token' requires a valid token in %s or DOTVAULT_TOKEN env", m.TokenFilePath)
	default:
		return fmt.Errorf("unsupported auth method: %q", m.AuthMethod)
	}
}
