package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := s.vault != nil && s.vault.Token() != ""
	status := map[string]any{
		"authenticated": authenticated,
		"auth_method":   s.authMethod,
		"time":          time.Now().Format(time.RFC3339),
		"version":       s.version,
	}

	// Only expose Vault connection details to authenticated sessions.
	if authenticated {
		status["vault_address"] = s.vaultAddress
		status["kv_mount"] = s.kvMount
		status["user_prefix"] = s.userPrefix
		status["username"] = s.username
	}

	if s.loginTextHTML != "" {
		status["login_text"] = s.loginTextHTML
	}
	if s.secretViewTextHTML != "" {
		status["secret_view_text"] = s.secretViewTextHTML
	}

	if s.vault != nil && s.vault.Token() != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		secret, err := s.vault.LookupSelf(ctx)
		if err == nil && secret != nil {
			status["token_ttl"] = secret.Data["ttl"]
			status["token_renewable"] = secret.Data["renewable"]
		}
	}

	if s.engine != nil {
		rules := s.engine.State().Rules()
		ruleStatuses := make(map[string]any)
		for name, rs := range rules {
			ruleStatuses[name] = map[string]any{
				"vault_version": rs.VaultVersion,
				"last_synced":   rs.LastSynced.Format(time.RFC3339),
			}
		}
		status["rules"] = ruleStatuses
	}

	writeJSON(w, status)
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	type ruleResponse struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		VaultKey      string `json:"vault_key"`
		TargetPath    string `json:"target_path"`
		Format        string `json:"format"`
		HasOAuth      bool   `json:"has_oauth,omitempty"`
		OAuthProvider string `json:"oauth_provider,omitempty"`
	}

	rules := make([]ruleResponse, len(s.rules))
	for i, r := range s.rules {
		rules[i] = ruleResponse{
			Name:        r.Name,
			Description: r.Description,
			VaultKey:    r.VaultKey,
			TargetPath:  r.Target.Path,
			Format:      r.Target.Format,
		}
		if r.OAuth != nil {
			rules[i].HasOAuth = true
			rules[i].OAuthProvider = r.OAuth.Provider
		}
	}

	writeJSON(w, map[string]any{"rules": rules})
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	// Extract path after /api/v1/secrets/
	secretPath := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	reveal := r.URL.Query().Get("reveal") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	fullPath := s.userKVPrefix() + secretPath

	if secretPath == "" || strings.HasSuffix(secretPath, "/") {
		// List keys
		keys, err := s.vault.ListKVv2(ctx, s.kvMount, fullPath)
		if err != nil {
			slog.Error("list secrets failed", "path", fullPath, "error", err)
			writeError(w, "failed to list secrets", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"keys": keys, "path": secretPath})
		return
	}

	// Read specific secret
	secret, err := s.vault.ReadKVv2(ctx, s.kvMount, fullPath)
	if err != nil {
		slog.Error("read secret failed", "path", fullPath, "error", err)
		writeError(w, "failed to read secret", http.StatusInternalServerError)
		return
	}
	if secret == nil {
		writeError(w, "secret not found", http.StatusNotFound)
		return
	}

	if reveal {
		slog.Info("secret revealed via web UI", "path", secretPath)
		writeJSON(w, map[string]any{
			"path":    secretPath,
			"version": secret.Version,
			"fields":  secret.Data,
		})
	} else {
		// Field names only
		fieldNames := make([]string, 0, len(secret.Data))
		for k := range secret.Data {
			fieldNames = append(fieldNames, k)
		}
		writeJSON(w, map[string]any{
			"path":    secretPath,
			"version": secret.Version,
			"fields":  fieldNames,
		})
	}
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeError(w, "sync engine not available", http.StatusServiceUnavailable)
		return
	}

	slog.Info("sync triggered via web UI")
	s.engine.TriggerSync()
	writeJSON(w, map[string]any{"status": "sync triggered"})
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
