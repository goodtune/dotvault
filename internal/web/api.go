package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/regfile"
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

	// SSH agent status (listed identities, per-cert TTL, source errors),
	// parallel to the per-rule sync state above. Authenticated only — it
	// reaches into Vault to resolve identities.
	if authenticated && s.agentStatus != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		status["agent"] = s.agentStatus.Status(ctx)
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
		syncInterval = formatDuration(s.syncCfg.Interval)
	}

	web := map[string]any{
		"enabled": s.cfg.Enabled,
		"listen":  s.cfg.Listen,
	}
	// listen_effective surfaces the actually-bound address, which differs
	// from the configured value when the user gave a port like ":0".
	if s.listenAddr != "" {
		web["listen_effective"] = s.listenAddr
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
		"web":        web,
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
// a credential. The key is first normalized so that camelCase, kebab-case
// and snake_case variants all collapse to the same form (`accessToken`,
// `access-token`, `access_token` → `access_token`). Matching then uses an
// exact-name list and a suffix list rather than a loose substring match so
// that legitimate configuration knobs are not false-positive redacted —
// e.g. `token_ttl` must remain visible, only `token`, `*_token`,
// `oauth_token`, `access_token`, `clientSecret`, `privateKey` etc are
// masked.
func isSensitiveSettingKey(k string) bool {
	nk := normalizeKey(k)
	switch nk {
	case "password", "passphrase", "secret", "credential", "credentials",
		"api_key", "apikey", "private_key", "privatekey",
		"token", "oauth_token", "access_token", "refresh_token",
		"bearer_token", "auth_token":
		return true
	}
	for _, suffix := range []string{
		"_token", "_secret", "_password", "_passphrase",
		"_credential", "_credentials", "_apikey", "_api_key",
		"_private_key",
	} {
		if strings.HasSuffix(nk, suffix) {
			return true
		}
	}
	return false
}

// normalizeKey lower-cases a key and converts camelCase / kebab-case into
// snake_case so the redaction matcher can treat all naming conventions
// uniformly. Examples: `clientSecret` → `client_secret`,
// `access-token` → `access_token`, `OAuthToken` → `oauth_token`,
// `XMLToken` → `xml_token`. Acronym boundaries (an upper-case run
// followed by a capitalized word) are split so that defensive matching
// still catches keys like `JWTToken` or `APIKey`.
func normalizeKey(k string) string {
	var b strings.Builder
	b.Grow(len(k) + 4)
	runes := []rune(k)
	for i, r := range runes {
		switch {
		case r == '-':
			b.WriteByte('_')
		case unicode.IsUpper(r):
			if i > 0 {
				prev := runes[i-1]
				nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
				prevPrevIsUpper := i > 1 && unicode.IsUpper(runes[i-2])
				if unicode.IsLower(prev) || unicode.IsDigit(prev) ||
					(unicode.IsUpper(prev) && nextIsLower && prevPrevIsUpper) {
					b.WriteByte('_')
				}
			}
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// formatDuration is a tidier alternative to time.Duration.String() that
// trims trailing zero-valued units (so 15m renders as "15m" instead of
// "15m0s", 1h as "1h" instead of "1h0m0s"). Used for the effective sync
// interval when the configured raw form was empty (i.e. fell back to the
// 15m default).
//
// The trim is unit-aware: a "0m" or "0s" tail is only stripped when the
// preceding character is itself a unit letter (h/m/s), so multi-digit
// values like "30m" or "1h30m0s" are not mangled.
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	s := d.String()
	s = stripZeroUnit(s, 's')
	s = stripZeroUnit(s, 'm')
	return s
}

func stripZeroUnit(s string, unit byte) string {
	needle := "0" + string(unit)
	if !strings.HasSuffix(s, needle) {
		return s
	}
	pre := s[:len(s)-2]
	if pre == "" {
		return s
	}
	switch pre[len(pre)-1] {
	case 'h', 'm', 's':
		return pre
	}
	return s
}

// handleConfigDownload returns the daemon's in-memory configuration as a
// downloadable file in either YAML or Windows .reg form. The endpoint is
// gated on the daemon itself being authenticated to Vault — the same
// global state the rest of the API checks — and serves the unredacted
// config so a downloaded YAML is a usable replacement for the source
// file (and a .reg can be re-applied to a Windows registry without
// fields silently disappearing).
//
// Unlike /api/v1/config (which redacts CA certs, CA bundles, and
// credential-shaped settings for UI viewing) this endpoint exists
// specifically to round-trip the running config back to disk, so
// redaction would defeat its purpose. The compensating boundaries are:
//   - the web UI binds to loopback only (a hard invariant in
//     paths.ValidateLoopback) so the response cannot reach the network
//   - the middleware rejects requests whose Host header is not a
//     loopback alias, defeating DNS-rebinding attacks that would
//     otherwise let a hostile origin read the response
//   - the daemon must be authenticated to Vault, gating the endpoint
//     behind the same proof-of-trust used for /api/v1/token
//   - the response is marked Cache-Control: no-store to keep proxies
//     and browser disk caches from persisting the body
//
// The format is selected via ?format=yaml|reg (default yaml).
func (s *Server) handleConfigDownload(w http.ResponseWriter, r *http.Request) {
	// no-store applies to every response this handler emits — the
	// success body, the 401 from the auth gate, the 400 on bad
	// format, and the 500 on render failures. (A request that fails
	// the middleware-level Host allowlist is rejected before this
	// handler runs and gets its own no-store via writeError's JSON
	// envelope on /api/ routes.) Even the error pages should not be
	// cached because they can reveal whether the daemon is currently
	// authenticated.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if s.vault == nil || s.vault.Token() == "" {
		writeError(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "yaml"
	}

	cfg := s.buildEffectiveConfig()

	switch format {
	case "yaml":
		data, err := regfile.MarshalYAML(cfg)
		if err != nil {
			slog.Error("marshal yaml for download", "error", err)
			writeError(w, "failed to render YAML", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="dotvault-config.yaml"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
	case "reg":
		data, err := regfile.Generate(cfg)
		if err != nil {
			slog.Error("generate reg for download", "error", err)
			writeError(w, "failed to render REG", http.StatusInternalServerError)
			return
		}
		// application/octet-stream: .reg is UTF-16LE binary, not text/plain.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="dotvault-config.reg"`)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
	default:
		writeError(w, "unsupported format (use yaml or reg)", http.StatusBadRequest)
	}
}

// buildEffectiveConfig reassembles the *config.Config the daemon is running
// from the per-section copies the web server holds. The result is suitable
// for round-trip through regfile.MarshalYAML or regfile.Generate.
//
// We rebuild rather than retain a single *config.Config because the server
// already has each section in a typed field for direct API use; pulling
// them back together for download keeps the in-memory representation
// authoritative.
//
// One subtle fix-up: when the source YAML omitted `sync.interval`,
// (*Config).validate populates Sync.Interval with the 15m default but
// leaves Sync.RawInterval empty. The renderers serialise RawInterval
// (so the .reg form stays diff-stable when the user actually wrote
// "15m"), so we'd otherwise emit `interval: ""` here even though the
// daemon is using 15m. Materialise RawInterval from Interval whenever
// it's empty so the download reflects the effective configuration.
func (s *Server) buildEffectiveConfig() *config.Config {
	rules := make([]config.Rule, len(s.rules))
	copy(rules, s.rules)

	enrolments := s.getEnrolments()

	syncCfg := s.syncCfg
	if syncCfg.RawInterval == "" && syncCfg.Interval > 0 {
		syncCfg.RawInterval = formatDuration(syncCfg.Interval)
	}

	// Mirror the syncCfg fix-up for observability.export_interval:
	// if the user only set it programmatically (parsed) and not via
	// the RawInterval YAML field, materialise the raw form so the
	// download reflects the effective configuration.
	//
	// observability.headers (which may hold OTLP bearer tokens) are
	// emitted verbatim: config conversion is lossless in every
	// direction, so the download reflects the effective configuration
	// including header values. s.obsCfg retains them for this reason
	// (see NewServer). Operators who want tokens kept out of a
	// downloaded config should set them via OTEL_EXPORTER_OTLP_HEADERS
	// in a per-user EnvironmentFile (see docs/admin/deployment.md) and
	// leave the headers map empty.
	obsCfg := s.obsCfg
	if obsCfg.RawInterval == "" && obsCfg.ExportInterval > 0 {
		obsCfg.RawInterval = formatDuration(obsCfg.ExportInterval)
	}

	return &config.Config{
		Vault:         s.vaultCfg,
		Sync:          syncCfg,
		Web:           s.cfg,
		Observability: obsCfg,
		Agent:         s.agentCfg,
		Rules:         rules,
		Enrolments:    enrolments,
	}
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	// Extract path after /api/v1/secrets/
	secretPath := strings.TrimPrefix(r.URL.Path, "/api/v1/secrets/")
	reveal := r.URL.Query().Get("reveal") == "true"

	// Defence in depth: the path is always meant to be relative to this user's
	// KV prefix (users/<username>/). Reject an absolute path or any ".."
	// segment so a crafted request can't walk outside that prefix — even though
	// Vault treats logical path segments literally and wouldn't collapse "..",
	// keeping the constraint explicit avoids relying on that as a guarantee.
	if strings.HasPrefix(secretPath, "/") {
		writeError(w, "invalid secret path", http.StatusBadRequest)
		return
	}
	for _, seg := range strings.Split(secretPath, "/") {
		if seg == ".." {
			writeError(w, "invalid secret path", http.StatusBadRequest)
			return
		}
	}

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

// handleHealthz reports daemon liveness — the process is running and
// serving HTTP. Always returns 200 with a tiny JSON envelope so the
// OTel httpcheckreceiver (and any other liveness probe) can rely on it
// regardless of Vault state.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"status":  "ok",
		"version": s.version,
	})
}

// handleReadyz reports daemon readiness. Mirrors the systemd
// sd_notify(READY=1) contract so k8s readinessProbe consumers and
// the OTel httpcheckreceiver see green only after the daemon has
// authenticated to Vault AND completed its initial sync cycle —
// i.e. secrets are actually on disk. Either condition unmet
// produces a 503 with a JSON envelope describing which gate
// hasn't cleared, so a startup-gated dependency can poll until
// ready.
//
// The token-presence check reflects the *cached* in-memory token,
// not a per-probe LookupSelf against Vault. A token that expires
// or is revoked between lifecycle checks (default cadence 5
// minutes) will keep /readyz green until the lifecycle goroutine
// next runs — at which point it triggers OnReauth, which clears
// the in-memory token and flips /readyz back to 503. This is
// deliberate: a per-probe Vault round-trip would multiply the
// daemon's Vault load by every readiness probe and provide
// little extra signal — operators wanting confirmed Vault
// reachability should poll the engine's per-rule sync state
// (via /api/v1/status) rather than /readyz.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	authenticated := s.vault != nil && s.vault.Token() != ""
	initialSyncDone := s.InitialSyncComplete()
	payload := map[string]any{
		"status":            "ready",
		"version":           s.version,
		"authenticated":     authenticated,
		"initial_sync_done": initialSyncDone,
	}
	if !authenticated || !initialSyncDone {
		payload["status"] = "not_ready"
		writeJSONStatus(w, http.StatusServiceUnavailable, payload)
		return
	}
	writeJSON(w, payload)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// writeJSONStatus is the explicit-status sibling of writeJSON for
// handlers that need to set a non-default status (e.g. /readyz's
// 503 envelope, which carries a structured payload rather than the
// generic {"error": …} shape writeError provides).
func writeJSONStatus(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, message string, code int) {
	writeJSONStatus(w, code, map[string]string{"error": message})
}
