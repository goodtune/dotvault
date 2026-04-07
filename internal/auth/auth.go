package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/goodtune/dotvault/internal/vault"
)

// Manager orchestrates Vault authentication.
type Manager struct {
	VaultClient   *vault.Client
	TokenFilePath string
	AuthMethod    string // "oidc", "ldap", "token"
	AuthMount     string // auth mount path
	AuthRole      string // optional role
	Username      string
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

	// Step 2: Authenticate with configured method
	switch m.AuthMethod {
	case "oidc":
		return m.authenticateOIDC(ctx)
	case "ldap":
		return m.authenticateLDAP(ctx)
	case "token":
		return fmt.Errorf("auth method 'token' requires a valid token in %s or VAULT_TOKEN env", m.TokenFilePath)
	default:
		return fmt.Errorf("unsupported auth method: %q", m.AuthMethod)
	}
}
