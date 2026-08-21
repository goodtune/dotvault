package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/goodtune/dotvault/internal/auth"
)

// policyConstraint projects the server's vault config onto the least-privilege
// downscoping constraint applied to freshly-minted web-login tokens. It mirrors
// the CLI flows (auth.Manager.Policy) so a token obtained through the web UI is
// narrowed identically to one obtained on the terminal.
func (s *Server) policyConstraint() auth.PolicyConstraint {
	return auth.PolicyConstraint{
		Policies:        s.vaultCfg.Policies,
		NoDefaultPolicy: s.vaultCfg.NoDefaultPolicy,
	}
}

// WaitForAuth blocks until authentication completes or the context is cancelled.
func (s *Server) WaitForAuth(ctx context.Context) error {
	select {
	case <-s.authDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("authentication cancelled: %w", ctx.Err())
	}
}

func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	mount := s.loginMount("oidc")

	callbackURL := fmt.Sprintf("http://%s/auth/oidc/callback", s.listenAddr)

	data := map[string]interface{}{
		"redirect_uri": callbackURL,
		"role":         s.authRole,
	}
	secret, err := s.vault.Raw().Logical().WriteWithContext(r.Context(),
		fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		slog.Error("failed to get OIDC auth URL", "error", err)
		http.Error(w, "Failed to initiate authentication", http.StatusInternalServerError)
		return
	}
	if secret == nil || secret.Data == nil {
		slog.Error("nil or empty response getting OIDC auth URL from Vault")
		http.Error(w, "Failed to get authentication URL", http.StatusInternalServerError)
		return
	}

	authURL, ok := secret.Data["auth_url"].(string)
	if !ok || authURL == "" {
		slog.Error("no auth_url in OIDC response")
		http.Error(w, "Failed to get authentication URL", http.StatusInternalServerError)
		return
	}

	slog.Info("redirecting to OIDC provider")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		errMsg := r.URL.Query().Get("error")
		if errMsg == "" {
			errMsg = "unknown error"
		}
		slog.Error("OIDC auth callback error", "error", errMsg)
		http.Error(w, "Authentication failed: "+errMsg, http.StatusBadRequest)
		return
	}
	if state == "" {
		slog.Error("OIDC auth callback missing state parameter")
		http.Error(w, "Authentication failed: missing state parameter", http.StatusBadRequest)
		return
	}

	mount := s.loginMount("oidc")

	callbackPath := fmt.Sprintf("auth/%s/oidc/callback", mount)
	loginData := map[string][]string{
		"code":  {code},
		"state": {state},
	}
	loginSecret, err := s.vault.Raw().Logical().ReadWithDataWithContext(r.Context(),
		callbackPath, loginData)
	if err != nil {
		slog.Error("OIDC token exchange failed", "error", err)
		http.Error(w, "Authentication failed during token exchange", http.StatusInternalServerError)
		return
	}
	if loginSecret == nil || loginSecret.Auth == nil {
		slog.Error("no auth data in OIDC callback response")
		http.Error(w, "Authentication failed: no auth data", http.StatusInternalServerError)
		return
	}

	// Token adoption (including the bootstrap divert) is shared with the
	// LDAP flow — see consumeLoginToken for why a bootstrap token must never
	// be downscoped, persisted, or installed.
	bootstrapped, err := s.consumeLoginToken(r.Context(), loginSecret.Auth.ClientToken)
	if err != nil {
		slog.Error("downscoping token to least privilege failed", "error", err)
		http.Error(w, "Authentication failed during token downscoping", http.StatusInternalServerError)
		return
	}
	if bootstrapped {
		slog.Info("OIDC bootstrap login successful via web UI")
		// issuing=1 tells the login view that the credential step is done
		// and the daemon is now minting the certificate, so it shows the
		// issuance message rather than the generic sign-in one.
		http.Redirect(w, r, "/?issuing=1", http.StatusSeeOther)
		return
	}

	slog.Info("OIDC authentication successful via web UI")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
