package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

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

func (s *Server) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"username and password required"}`, http.StatusBadRequest)
		return
	}

	sessionID, err := generateSessionID()
	if err != nil {
		slog.Error("failed to generate session ID", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	mount := s.authMount
	if mount == "" {
		mount = "ldap"
	}

	s.login.StartLogin(sessionID, mount, req.Username, req.Password)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{"session_id": sessionID})
}

func (s *Server) handleLDAPStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, `{"error":"session parameter required"}`, http.StatusBadRequest)
		return
	}

	status := s.login.GetStatus(sessionID)
	if status == nil {
		http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	// If authenticated, consume the token server-side.
	if status.State == "authenticated" && status.Token != "" {
		s.vault.SetToken(status.Token)
		if err := auth.WriteTokenFile(s.tokenFilePath, status.Token); err != nil {
			slog.Warn("failed to write token file", "error", err)
		}
		s.login.Clear(sessionID)

		slog.Info("LDAP authentication successful via web UI")

		// Signal auth completion.
		select {
		case s.authDone <- struct{}{}:
		default:
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleLDAPTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Passcode  string `json:"passcode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.SessionID == "" || req.Passcode == "" {
		http.Error(w, `{"error":"session_id and passcode required"}`, http.StatusBadRequest)
		return
	}

	s.login.SubmitTOTP(req.SessionID, req.Passcode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "submitted"})
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, `{"error":"token required"}`, http.StatusBadRequest)
		return
	}

	// Validate the token.
	s.vault.SetToken(req.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.vault.LookupSelf(ctx); err != nil {
		s.vault.SetToken("")
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	if err := auth.WriteTokenFile(s.tokenFilePath, req.Token); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}

	slog.Info("token authentication successful via web UI")

	// Signal auth completion.
	select {
	case s.authDone <- struct{}{}:
	default:
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"state": "authenticated"})
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
