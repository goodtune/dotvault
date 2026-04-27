package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
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
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
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

	// Only expose enrolment state to authenticated sessions.
	if authenticated {
		if runner := s.getEnrolRunner(); runner != nil {
			status["enrolments"] = runner.States()
		}
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

// handleConfig returns the effective service configuration: managed files
// (sync rules) and active enrolments. It is a view-only endpoint and never
// includes secret values such as the Vault CA certificate or stored
// credentials. Available only to authenticated sessions.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil || s.vault.Token() == "" {
		writeError(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	type targetView struct {
		Path        string `json:"path"`
		Format      string `json:"format"`
		Merge       string `json:"merge,omitempty"`
		HasTemplate bool   `json:"has_template"`
	}
	type oauthView struct {
		Provider   string   `json:"provider"`
		EnginePath string   `json:"engine_path,omitempty"`
		Scopes     []string `json:"scopes,omitempty"`
	}
	type ruleView struct {
		Name        string     `json:"name"`
		Description string     `json:"description,omitempty"`
		VaultKey    string     `json:"vault_key"`
		Target      targetView `json:"target"`
		OAuth       *oauthView `json:"oauth,omitempty"`
	}
	type enrolmentView struct {
		Key        string         `json:"key"`
		Engine     string         `json:"engine"`
		EngineName string         `json:"engine_name,omitempty"`
		Fields     []string       `json:"fields,omitempty"`
		Settings   map[string]any `json:"settings,omitempty"`
		Status     string         `json:"status,omitempty"`
	}

	rules := make([]ruleView, len(s.rules))
	for i, rule := range s.rules {
		rules[i] = ruleView{
			Name:        rule.Name,
			Description: rule.Description,
			VaultKey:    rule.VaultKey,
			Target: targetView{
				Path:        rule.Target.Path,
				Format:      rule.Target.Format,
				Merge:       rule.Target.Merge,
				HasTemplate: rule.Target.Template != "",
			},
		}
		if rule.OAuth != nil {
			rules[i].OAuth = &oauthView{
				Provider:   rule.OAuth.Provider,
				EnginePath: rule.OAuth.EnginePath,
				Scopes:     rule.OAuth.Scopes,
			}
		}
	}

	statuses := map[string]EnrolStateInfo{}
	if runner := s.getEnrolRunner(); runner != nil {
		for _, st := range runner.States() {
			statuses[st.Key] = st
		}
	}

	enrolmentMap := s.getEnrolments()
	keys := make([]string, 0, len(enrolmentMap))
	for k := range enrolmentMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	enrolments := make([]enrolmentView, 0, len(keys))
	for _, k := range keys {
		e := enrolmentMap[k]
		ev := enrolmentView{
			Key:      k,
			Engine:   e.Engine,
			Settings: redactEnrolmentSettings(e.Settings),
		}
		if st, ok := statuses[k]; ok {
			ev.EngineName = st.EngineName
			ev.Fields = st.Fields
			ev.Status = st.Status
		}
		enrolments = append(enrolments, ev)
	}

	syncInterval := s.syncCfg.RawInterval
	if syncInterval == "" && s.syncCfg.Interval > 0 {
		syncInterval = s.syncCfg.Interval.String()
	}

	resp := map[string]any{
		"vault": map[string]any{
			"address":               s.vaultCfg.Address,
			"kv_mount":              s.kvMount,
			"user_prefix":           s.userPrefix,
			"auth_method":           s.authMethod,
			"auth_mount":            s.authMount,
			"auth_role":             s.authRole,
			"tls_skip_verify":       s.vaultCfg.TLSSkipVerify,
			"has_ca_cert":           s.vaultCfg.CACert != "",
			"disable_token_renewal": s.vaultCfg.DisableTokenRenewal,
		},
		"sync": map[string]any{
			"interval": syncInterval,
		},
		"web": map[string]any{
			"enabled": s.cfg.Enabled,
			"listen":  s.cfg.Listen,
		},
		"rules":      rules,
		"enrolments": enrolments,
	}
	writeJSON(w, resp)
}

// redactEnrolmentSettings returns a copy of settings with values masked for
// keys that look credential-bearing. Engine settings should only ever hold
// configuration (URLs, scopes, IDs) — this is a defensive belt-and-braces
// pass so a misconfigured YAML can't leak through the read-only UI.
// Recursion handles nested maps and slices so a sensitive key buried deep
// in the tree is still redacted.
func redactEnrolmentSettings(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out, _ := redactEnrolmentValue(in).(map[string]any)
	return out
}

func redactEnrolmentValue(v any) any {
	switch vv := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(vv))
		for k, nested := range vv {
			if isSensitiveSettingKey(k) {
				out[k] = "***"
				continue
			}
			out[k] = redactEnrolmentValue(nested)
		}
		return out
	case []any:
		out := make([]any, len(vv))
		for i, nested := range vv {
			out[i] = redactEnrolmentValue(nested)
		}
		return out
	default:
		return v
	}
}

// isSensitiveSettingKey reports whether a settings key looks like it carries
// a credential. It uses an exact-name list and a suffix list rather than a
// loose substring match so that legitimate configuration knobs are not
// false-positive redacted — e.g. `token_ttl` (JFrog engine duration knob)
// must remain visible, only `*_token` / `oauth_token` / `access_token` etc
// are masked.
func isSensitiveSettingKey(k string) bool {
	lk := strings.ToLower(k)
	switch lk {
	case "password", "passphrase", "secret", "credential", "credentials",
		"api_key", "apikey", "private_key", "privatekey",
		"oauth_token", "access_token", "refresh_token",
		"bearer_token", "auth_token":
		return true
	}
	for _, suffix := range []string{
		"_token", "_secret", "_password", "_passphrase",
		"_credential", "_credentials", "_apikey", "_api_key",
		"_private_key",
	} {
		if strings.HasSuffix(lk, suffix) {
			return true
		}
	}
	return false
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	// Extract path after /api/v1/secrets/
	secretPath := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	reveal := r.URL.Query().Get("reveal") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
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

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil || s.vault.Token() == "" {
		writeError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	slog.Info("vault token retrieved via web UI", "username", s.username)
	writeJSON(w, map[string]any{"token": s.vault.Token()})
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

func (s *Server) handleEnrolPrompt(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	s.enrolPromptMu.RLock()
	label := s.enrolPromptLabel
	pending := s.enrolPromptCh != nil
	s.enrolPromptMu.RUnlock()

	writeJSON(w, map[string]any{
		"pending": pending,
		"label":   label,
	})
}

func (s *Server) handleEnrolSecret(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.enrolPromptMu.Lock()
	ch := s.enrolPromptCh
	if ch == nil {
		s.enrolPromptMu.Unlock()
		writeError(w, "no pending prompt", http.StatusConflict)
		return
	}

	select {
	case ch <- req.Value:
		s.enrolPromptCh = nil
		s.enrolPromptLabel = ""
		s.enrolPromptMu.Unlock()
		writeJSON(w, map[string]any{"status": "accepted"})
	default:
		s.enrolPromptMu.Unlock()
		writeError(w, "prompt already answered", http.StatusConflict)
	}
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
