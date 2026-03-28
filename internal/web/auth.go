package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/goodtune/dotvault/internal/auth"
)

// AuthStartURL returns the URL to open in a browser to start OIDC auth.
// It uses the actual bound listener address so it works even with ephemeral ports.
func (s *Server) AuthStartURL() string {
	return fmt.Sprintf("http://%s/auth/oidc/start", s.listenAddr)
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
	mount := s.authMount
	if mount == "" {
		mount = "oidc"
	}

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

	mount := s.authMount
	if mount == "" {
		mount = "oidc"
	}

	loginData := map[string]interface{}{
		"code":  code,
		"state": state,
	}
	loginSecret, err := s.vault.Raw().Logical().WriteWithContext(r.Context(),
		fmt.Sprintf("auth/%s/oidc/callback", mount), loginData)
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

	token := loginSecret.Auth.ClientToken
	s.vault.SetToken(token)

	if err := auth.WriteTokenFile(s.tokenFilePath, token); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}

	slog.Info("OIDC authentication successful via web UI")

	// Signal auth completion (non-blocking).
	select {
	case s.authDone <- struct{}{}:
	default:
	}

	fmt.Fprint(w, "Authentication successful! You can close this window.")
}

// --- LDAP and Token stubs (implemented in Task 5) ---

func (s *Server) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleLDAPStatus(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleLDAPTOTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
