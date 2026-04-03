package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
)

// OAuthManager manages OAuth2 state parameters for CSRF protection.
type OAuthManager struct {
	mu     sync.Mutex
	states map[string]string // state -> rule name
}

// NewOAuthManager creates a new OAuth state manager.
func NewOAuthManager() *OAuthManager {
	return &OAuthManager{
		states: make(map[string]string),
	}
}

// CreateState generates a cryptographically random state parameter for an OAuth flow.
func (om *OAuthManager) CreateState(ruleName string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate OAuth state: %w", err)
	}
	state := hex.EncodeToString(b)

	om.mu.Lock()
	om.states[state] = ruleName
	om.mu.Unlock()

	return state, nil
}

// ValidateState checks and consumes a state parameter. Returns the rule name and true if valid.
func (om *OAuthManager) ValidateState(state string) (string, bool) {
	om.mu.Lock()
	defer om.mu.Unlock()

	rule, ok := om.states[state]
	if ok {
		delete(om.states, state)
	}
	return rule, ok
}

// handleOAuthStart initiates an OAuth2 flow for a given rule.
//
// NOTE: This handler is a placeholder. It is not yet wired to the Vault
// secrets engine API that would provide the real OAuth authorization URL.
// The current implementation generates a valid CSRF state token but
// redirects to the local callback with a dummy code. This is acceptable
// for the current implementation scope and will be completed when the
// Vault OAuth engine integration is built.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	ruleName := r.PathValue("rule")

	// Find the rule
	var found bool
	for _, rule := range s.rules {
		if rule.Name == ruleName && rule.OAuth != nil {
			found = true

			// Generate state
			state, err := s.oauth.CreateState(ruleName)
			if err != nil {
				slog.Error("failed to create OAuth state", "error", err)
				writeError(w, "internal server error", http.StatusInternalServerError)
				return
			}

			// Build auth URL — in a real implementation this would come from
			// the Vault engine or the OAuth config. For now, construct a
			// placeholder that the Vault engine would provide.
			slog.Warn("OAuth start is a placeholder; not yet wired to Vault engine API", "rule", ruleName, "provider", rule.OAuth.Provider)
			authURL := fmt.Sprintf("/api/v1/oauth/callback?state=%s&code=placeholder", state)

			slog.Info("OAuth flow started", "rule", ruleName, "provider", rule.OAuth.Provider)
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}
	}

	if !found {
		writeError(w, "rule not found or has no OAuth config", http.StatusNotFound)
	}
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		writeError(w, "missing state or code", http.StatusBadRequest)
		return
	}

	ruleName, valid := s.oauth.ValidateState(state)
	if !valid {
		slog.Warn("OAuth callback with invalid state", "state", state)
		writeError(w, "invalid state parameter", http.StatusBadRequest)
		return
	}

	slog.Info("OAuth callback received", "rule", ruleName, "code_length", len(code))

	// In a full implementation, this would:
	// 1. Find the rule's OAuth config
	// 2. Exchange the code via the Vault engine API
	// 3. Store the resulting credential
	// 4. Trigger a sync for this rule

	// For now, redirect back to the UI with success
	http.Redirect(w, r, "/?oauth=success&rule="+ruleName, http.StatusFound)
}
