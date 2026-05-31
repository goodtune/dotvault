package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

func TestHandleStatus(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	s.handleStatus(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if _, ok := resp["authenticated"]; !ok {
		t.Error("response missing 'authenticated' field")
	}
}

func TestHandleRules(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	w := httptest.NewRecorder()

	s.handleRules(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	rules, ok := resp["rules"]
	if !ok {
		t.Fatal("response missing 'rules' field")
	}
	ruleList, ok := rules.([]any)
	if !ok {
		t.Fatalf("rules is %T, want []any", rules)
	}
	if len(ruleList) == 0 {
		t.Error("rules list is empty")
	}
}

func TestHandleSyncRequiresCSRF(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("POST", "/api/v1/sync", nil)
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleSync)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid or missing CSRF token" {
		t.Errorf("error = %q, want %q", resp["error"], "invalid or missing CSRF token")
	}
}

func TestWriteError_ContentTypeAndBody(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, "something went wrong", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if resp["error"] != "something went wrong" {
		t.Errorf("error = %q, want %q", resp["error"], "something went wrong")
	}
}

func TestHandleStatus_VersionAlwaysPresent(t *testing.T) {
	s := testServer(t)
	s.version = "1.2.3"

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["version"] != "1.2.3" {
		t.Errorf("version = %v, want %q", resp["version"], "1.2.3")
	}
}

func TestHandleStatus_VaultFieldsHiddenWhenUnauthenticated(t *testing.T) {
	s := testServer(t)
	s.vaultAddress = "http://127.0.0.1:8200"

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	for _, field := range []string{"vault_address", "kv_mount", "user_prefix", "username"} {
		if _, ok := resp[field]; ok {
			t.Errorf("unauthenticated response should not contain %q", field)
		}
	}
}

func TestHandleStatus_AuthMethod(t *testing.T) {
	s := testServer(t)
	s.authMethod = "ldap"

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["auth_method"] != "ldap" {
		t.Errorf("auth_method = %v, want %q", resp["auth_method"], "ldap")
	}
}

func TestHandleConfig_Unauthenticated(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()

	s.handleConfig(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleConfigDownload_Unauthenticated(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest("GET", "/api/v1/config/download", nil)
	w := httptest.NewRecorder()

	s.handleConfigDownload(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	// Cache headers must apply even to the unauthenticated response so
	// a 401 doesn't get persisted in any intermediate cache. The
	// handler comment claims this is invariant on every path.
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control on 401 = %q, want no-store", cc)
	}
	if p := w.Header().Get("Pragma"); p != "no-cache" {
		t.Errorf("Pragma on 401 = %q, want no-cache", p)
	}
}

func TestHandleConfigDownload_DefaultIntervalMaterialised(t *testing.T) {
	// When the source YAML omitted sync.interval, validate() sets
	// Interval to 15m but leaves RawInterval empty. The download must
	// reflect the effective interval, not the empty raw value.
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{Address: "https://vault.example.com:8200"}
	s.syncCfg = config.SyncConfig{Interval: 15 * time.Minute}
	s.rules = []config.Rule{
		{
			Name:     "r",
			VaultKey: "r",
			Target:   config.Target{Path: "/tmp/r", Format: "text"},
		},
	}

	req := httptest.NewRequest("GET", "/api/v1/config/download?format=yaml", nil)
	w := httptest.NewRecorder()
	s.handleConfigDownload(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "interval: 15m") {
		t.Errorf("expected materialised interval `15m`; got:\n%s", body)
	}
	if strings.Contains(body, `interval: ""`) {
		t.Errorf("download emitted empty interval; should have materialised the default:\n%s", body)
	}
}

// TestHandleConfigDownload_IncludesObservability verifies the
// effective-config builder threads the observability block through to
// the downloaded YAML. Previously buildEffectiveConfig dropped it
// entirely, so a daemon with metrics enabled would download a config
// missing the observability section and re-importing it would silently
// turn metrics off.
func TestHandleConfigDownload_IncludesObservability(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{Address: "https://vault.example.com:8200"}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}
	s.obsCfg = config.ObservabilityConfig{
		Enabled:        true,
		Endpoint:       "127.0.0.1:4317",
		Protocol:       "grpc",
		Insecure:       true,
		ExportInterval: 15 * time.Second,
		Headers: map[string]string{
			"authorization": "Bearer super-secret-token",
		},
	}
	s.rules = []config.Rule{
		{
			Name:     "r",
			VaultKey: "r",
			Target:   config.Target{Path: "/tmp/r", Format: "text"},
		},
	}

	req := httptest.NewRequest("GET", "/api/v1/config/download?format=yaml", nil)
	w := httptest.NewRecorder()
	s.handleConfigDownload(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "observability:") {
		t.Errorf("expected observability block; got:\n%s", body)
	}
	if !strings.Contains(body, "endpoint: 127.0.0.1:4317") {
		t.Errorf("expected observability.endpoint; got:\n%s", body)
	}
	// export_interval was supplied via the parsed field only — the
	// raw form should be materialised so the download round-trips.
	if !strings.Contains(body, "export_interval: 15s") {
		t.Errorf("expected materialised export_interval `15s`; got:\n%s", body)
	}
	// observability.headers (which may carry bearer tokens) round-trip
	// verbatim: config conversion is lossless in every direction, so the
	// download reflects the effective configuration including header
	// values. Operators who want tokens kept out of a downloaded config
	// set them via OTEL_EXPORTER_OTLP_HEADERS instead.
	if !strings.Contains(body, "authorization:") {
		t.Errorf("expected observability.headers key in download; got:\n%s", body)
	}
	if !strings.Contains(body, "Bearer super-secret-token") {
		t.Errorf("expected observability.headers value in download; got:\n%s", body)
	}
}

// TestHandleConfigDownload_IncludesAgent verifies the effective-config builder
// threads the agent block through to the download. buildEffectiveConfig
// reassembles the config from per-section copies, so a section it forgets is
// silently dropped — and re-importing the result would turn the agent off.
// This pins the agent section into the round-trip, the same way the
// observability test does for metrics.
func TestHandleConfigDownload_IncludesAgent(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{Address: "https://vault.example.com:8200"}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}
	s.agentCfg = config.AgentConfig{
		Enabled: true,
		Windows: config.AgentWindowsConfig{Pipe: `\\.\pipe\dotvault-agent`},
		Keys: []config.AgentKeySource{
			{Source: "kv", PathPrefix: "ssh/"},
			{Source: "vault-ca", Mount: "ssh-client-signer", Role: "dotvault-user", Principals: []string{"{{.vault_username}}"}, TTL: "15m", EphemeralKey: true},
		},
	}
	s.rules = []config.Rule{
		{Name: "r", VaultKey: "r", Target: config.Target{Path: "/tmp/r", Format: "text"}},
	}

	req := httptest.NewRequest("GET", "/api/v1/config/download?format=yaml", nil)
	w := httptest.NewRecorder()
	s.handleConfigDownload(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"agent:",
		"path_prefix: ssh/",
		"mount: ssh-client-signer",
		"role: dotvault-user",
		"ephemeral_key: true",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("agent download missing %q; got:\n%s", want, body)
		}
	}
}

func TestHandleConfigDownload_YAML(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{Address: "https://vault.example.com:8200"}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}
	s.cfg = config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"}
	s.rules = []config.Rule{
		{
			Name:     "gh",
			VaultKey: "gh",
			Target: config.Target{
				Path:   "~/.config/gh/hosts.yml",
				Format: "yaml",
			},
		},
	}
	s.enrolments = map[string]config.Enrolment{
		"gh": {Engine: "github"},
	}

	req := httptest.NewRequest("GET", "/api/v1/config/download?format=yaml", nil)
	w := httptest.NewRecorder()

	s.handleConfigDownload(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "dotvault-config.yaml") {
		t.Errorf("Content-Disposition = %q, want filename=dotvault-config.yaml", got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/x-yaml") {
		t.Errorf("Content-Type = %q, want application/x-yaml", ct)
	}
	// Sensitive content must not be cached by browsers/proxies. We assert
	// both Cache-Control: no-store and the legacy Pragma header so an HTTP/1.0
	// intermediate cannot persist the body.
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if p := w.Header().Get("Pragma"); p != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", p)
	}
	body := w.Body.String()
	if !strings.Contains(body, "address: https://vault.example.com:8200") {
		t.Errorf("body missing vault address:\n%s", body)
	}
	if !strings.Contains(body, "interval: 15m") {
		t.Errorf("body missing sync interval:\n%s", body)
	}
}

func TestHandleConfigDownload_REG(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{Address: "https://vault.example.com:8200"}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}
	s.rules = []config.Rule{
		{
			Name:     "gh",
			VaultKey: "gh",
			Target: config.Target{
				Path:   "~/.config/gh/hosts.yml",
				Format: "yaml",
			},
		},
	}

	req := httptest.NewRequest("GET", "/api/v1/config/download?format=reg", nil)
	w := httptest.NewRecorder()

	s.handleConfigDownload(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body length = %d", w.Code, w.Body.Len())
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "dotvault-config.reg") {
		t.Errorf("Content-Disposition = %q, want filename=dotvault-config.reg", got)
	}
	body := w.Body.Bytes()
	// UTF-16LE BOM at the start of the canonical reg output.
	if len(body) < 2 || body[0] != 0xFF || body[1] != 0xFE {
		t.Errorf("REG download missing UTF-16LE BOM; first bytes: %x", body[:min(8, len(body))])
	}
}

func TestHandleConfigDownload_BadFormat(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{Address: "https://vault.example.com:8200"}
	s.rules = []config.Rule{
		{
			Name:     "r",
			VaultKey: "r",
			Target:   config.Target{Path: "/tmp/r", Format: "text"},
		},
	}

	req := httptest.NewRequest("GET", "/api/v1/config/download?format=xml", nil)
	w := httptest.NewRecorder()

	s.handleConfigDownload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unknown format", w.Code)
	}
}

func TestHandleConfig_Authenticated(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{
		Address:       "http://127.0.0.1:8200",
		CACert:        "-----BEGIN CERTIFICATE-----\nsecret\n-----END CERTIFICATE-----",
		TLSSkipVerify: true,
	}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}
	s.cfg = config.WebConfig{Enabled: true, Listen: "127.0.0.1:0"}
	s.listenAddr = "127.0.0.1:43217"
	s.rules = []config.Rule{
		{
			Name:        "gh",
			Description: "GitHub host config",
			VaultKey:    "gh",
			Target: config.Target{
				Path:     "~/.config/gh/hosts.yml",
				Format:   "yaml",
				Merge:    "deep",
				Template: "{{ . }}",
			},
			OAuth: &config.OAuthConfig{
				Provider:   "github",
				EnginePath: "github",
				Scopes:     []string{"repo"},
			},
		},
	}
	s.enrolments = map[string]config.Enrolment{
		"gh": {
			Engine: "github",
			Settings: map[string]any{
				"client_id": "abc123",
				"scopes":    []any{"repo"},
				// A defensively-redacted key — engines never do this in
				// practice, but a malformed YAML must not leak through.
				"oauth_token": "ghp_should_not_appear",
			},
		},
	}

	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	w := httptest.NewRecorder()

	s.handleConfig(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	vault, ok := resp["vault"].(map[string]any)
	if !ok {
		t.Fatalf("vault is %T, want map", resp["vault"])
	}
	if vault["address"] != "http://127.0.0.1:8200" {
		t.Errorf("vault.address = %v, want %q", vault["address"], "http://127.0.0.1:8200")
	}
	if vault["has_ca_cert"] != true {
		t.Errorf("vault.has_ca_cert = %v, want true", vault["has_ca_cert"])
	}
	if vault["tls_skip_verify"] != true {
		t.Errorf("vault.tls_skip_verify = %v, want true", vault["tls_skip_verify"])
	}
	if _, leaked := vault["ca_cert"]; leaked {
		t.Error("vault.ca_cert must not be exposed")
	}
	if body := w.Body.String(); strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Error("response body must not contain CA certificate contents")
	}

	syncCfg, ok := resp["sync"].(map[string]any)
	if !ok {
		t.Fatalf("sync is %T, want map", resp["sync"])
	}
	if syncCfg["interval"] != "15m" {
		t.Errorf("sync.interval = %v, want %q", syncCfg["interval"], "15m")
	}

	web, ok := resp["web"].(map[string]any)
	if !ok {
		t.Fatalf("web is %T, want map", resp["web"])
	}
	if web["listen"] != "127.0.0.1:0" {
		t.Errorf("web.listen = %v, want configured value", web["listen"])
	}
	if web["listen_effective"] != "127.0.0.1:43217" {
		t.Errorf("web.listen_effective = %v, want bound address", web["listen_effective"])
	}

	rules, ok := resp["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules = %v, want one rule", resp["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["name"] != "gh" {
		t.Errorf("rule.name = %v, want %q", rule["name"], "gh")
	}
	target := rule["target"].(map[string]any)
	if target["has_template"] != true {
		t.Errorf("rule.target.has_template = %v, want true", target["has_template"])
	}
	if _, leaked := target["template"]; leaked {
		t.Error("rule.target.template body must not be exposed")
	}
	if oauth, ok := rule["oauth"].(map[string]any); !ok || oauth["provider"] != "github" {
		t.Errorf("rule.oauth = %v, want provider=github", rule["oauth"])
	}

	enrolments, ok := resp["enrolments"].([]any)
	if !ok || len(enrolments) != 1 {
		t.Fatalf("enrolments = %v, want one entry", resp["enrolments"])
	}
	enrol := enrolments[0].(map[string]any)
	if enrol["key"] != "gh" || enrol["engine"] != "github" {
		t.Errorf("enrolment = %v, want key=gh engine=github", enrol)
	}
	settings, ok := enrol["settings"].(map[string]any)
	if !ok {
		t.Fatalf("enrolment.settings is %T, want map", enrol["settings"])
	}
	if settings["client_id"] != "abc123" {
		t.Errorf("settings.client_id = %v, want %q", settings["client_id"], "abc123")
	}
	if settings["oauth_token"] != "***" {
		t.Errorf("settings.oauth_token = %v, want redacted", settings["oauth_token"])
	}
	if strings.Contains(w.Body.String(), "ghp_should_not_appear") {
		t.Error("redacted token leaked into response body")
	}
}

func TestRedactEnrolmentSettings(t *testing.T) {
	in := map[string]any{
		"url":           "https://example.jfrog.io",
		"client_id":     "abc",
		"token_ttl":     "60d",
		"oauth_token":   "ghp_xxx",
		"api_key":       "k",
		"refresh_TOKEN": "r",
		"private_key":   "-----BEGIN-----",
	}
	out := redactEnrolmentSettings(in)
	for k, want := range map[string]any{
		"url":       "https://example.jfrog.io",
		"client_id": "abc",
		"token_ttl": "60d",
	} {
		if out[k] != want {
			t.Errorf("settings[%q] = %v, want %v", k, out[k], want)
		}
	}
	for _, k := range []string{"oauth_token", "api_key", "refresh_TOKEN", "private_key"} {
		if out[k] != "***" {
			t.Errorf("settings[%q] = %v, want redacted", k, out[k])
		}
	}
}

func TestFormatDuration(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{15 * time.Minute, "15m"},
		{time.Hour, "1h"},
		{time.Hour + 30*time.Minute, "1h30m"},
		{45 * time.Second, "45s"},
		{2*time.Hour + 5*time.Second, "2h0m5s"},
		{0, "0s"},
	} {
		if got := formatDuration(tc.in); got != tc.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsSensitiveSettingKey(t *testing.T) {
	for _, tc := range []struct {
		key       string
		sensitive bool
	}{
		// Configuration knobs that look credential-y but aren't.
		{"token_ttl", false},
		{"client_id", false},
		{"client_code", false},
		{"client_name", false},
		{"url", false},
		{"scopes", false},
		{"host", false},
		// Real credential keys.
		{"password", true},
		{"passphrase", true},
		{"token", true},
		{"oauth_token", true},
		{"access_token", true},
		{"refresh_token", true},
		{"REFRESH_TOKEN", true},
		{"api_key", true},
		{"private_key", true},
		{"some_password", true},
		{"vault_secret", true},
		// camelCase / kebab-case variants must also match.
		{"clientSecret", true},
		{"refreshToken", true},
		{"OAuthToken", true},
		{"privateKey", true},
		{"access-token", true},
		{"oauth-token", true},
		// Acronym-style keys: must still be caught.
		{"JWTToken", true},
		{"XMLToken", true},
		{"APIKey", true},
	} {
		if got := isSensitiveSettingKey(tc.key); got != tc.sensitive {
			t.Errorf("isSensitiveSettingKey(%q) = %v, want %v", tc.key, got, tc.sensitive)
		}
	}
}

func TestRedactEnrolmentSettings_Nested(t *testing.T) {
	in := map[string]any{
		"oauth": map[string]any{
			"client_id":   "public",
			"oauth_token": "ghp_should_not_appear",
			"deep": map[string]any{
				"password": "p",
				"label":    "fine",
			},
		},
		"hosts": []any{
			map[string]any{"url": "https://a", "secret": "leak"},
			map[string]any{"url": "https://b"},
		},
	}
	out := redactEnrolmentSettings(in)

	oauth := out["oauth"].(map[string]any)
	if oauth["client_id"] != "public" {
		t.Errorf("nested non-sensitive key altered: %v", oauth["client_id"])
	}
	if oauth["oauth_token"] != "***" {
		t.Errorf("nested oauth_token = %v, want redacted", oauth["oauth_token"])
	}
	deep := oauth["deep"].(map[string]any)
	if deep["password"] != "***" {
		t.Errorf("doubly-nested password = %v, want redacted", deep["password"])
	}
	if deep["label"] != "fine" {
		t.Errorf("doubly-nested label altered: %v", deep["label"])
	}

	hosts := out["hosts"].([]any)
	first := hosts[0].(map[string]any)
	if first["url"] != "https://a" {
		t.Errorf("slice element url altered: %v", first["url"])
	}
	if first["secret"] != "***" {
		t.Errorf("slice element secret = %v, want redacted", first["secret"])
	}
}

func TestHandleEnrolPrompt_NoPending(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	req := httptest.NewRequest("GET", "/api/v1/enrol/prompt", nil)
	w := httptest.NewRecorder()

	s.handleEnrolPrompt(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["pending"] != false {
		t.Errorf("pending = %v, want false", resp["pending"])
	}
}

func TestHandleEnrolPrompt_Pending(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.enrolPromptMu.Lock()
	s.enrolPromptCh = make(chan string, 1)
	s.enrolPromptLabel = "Enter passphrase:"
	s.enrolPromptMu.Unlock()

	req := httptest.NewRequest("GET", "/api/v1/enrol/prompt", nil)
	w := httptest.NewRecorder()

	s.handleEnrolPrompt(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["pending"] != true {
		t.Errorf("pending = %v, want true", resp["pending"])
	}
	if resp["label"] != "Enter passphrase:" {
		t.Errorf("label = %v, want %q", resp["label"], "Enter passphrase:")
	}
}

func TestHandleEnrolSecret_NoPending(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	body := strings.NewReader(`{"value":"secret"}`)
	req := httptest.NewRequest("POST", "/api/v1/enrol/secret", body)
	w := httptest.NewRecorder()

	s.handleEnrolSecret(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestHandleEnrolSecret_Accepted(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	ch := make(chan string, 1)
	s.enrolPromptMu.Lock()
	s.enrolPromptCh = ch
	s.enrolPromptLabel = "Enter passphrase:"
	s.enrolPromptMu.Unlock()

	body := strings.NewReader(`{"value":"hunter2"}`)
	req := httptest.NewRequest("POST", "/api/v1/enrol/secret", body)
	w := httptest.NewRecorder()

	s.handleEnrolSecret(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Verify value was sent through the channel
	val := <-ch
	if val != "hunter2" {
		t.Errorf("channel value = %q, want %q", val, "hunter2")
	}
	// Verify state was cleared atomically
	s.enrolPromptMu.RLock()
	promptCh := s.enrolPromptCh
	promptLabel := s.enrolPromptLabel
	s.enrolPromptMu.RUnlock()
	if promptCh != nil {
		t.Error("enrolPromptCh should be nil after accepted submission")
	}
	if promptLabel != "" {
		t.Errorf("enrolPromptLabel = %q, want empty", promptLabel)
	}
}

func TestHandleEnrolSecretRequiresCSRF(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"value":"secret"}`)
	req := httptest.NewRequest("POST", "/api/v1/enrol/secret", body)
	w := httptest.NewRecorder()

	s.requireCSRF(s.handleEnrolSecret)(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for missing CSRF", w.Code)
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Server{
		csrf:  NewCSRFStore(),
		oauth: NewOAuthManager(),
		mux:   http.NewServeMux(),
		rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:   "~/.config/gh/hosts.yml",
					Format: "yaml",
					Merge:  "deep",
				},
			},
		},
		kvMount:        "secret",
		userPrefix:     "users/",
		username:       "testuser",
		authMethod:     "oidc",
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
}

func testServerWithVault(t *testing.T, handler http.Handler) *Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	vc, err := vault.NewClient(vault.Config{
		Address: ts.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	s := testServer(t)
	s.vault = vc
	return s
}

func TestHandleSecrets_ListKeys(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			t.Errorf("expected list=true query param, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"gh", "ssh"},
			},
		})
	})

	s := testServerWithVault(t, handler)
	req := httptest.NewRequest("GET", "/api/v1/secrets/", nil)
	w := httptest.NewRecorder()

	s.handleSecrets(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	keys, ok := resp["keys"].([]any)
	if !ok {
		t.Fatalf("keys is %T, want []any", resp["keys"])
	}
	if len(keys) != 2 {
		t.Errorf("len(keys) = %d, want 2", len(keys))
	}
}

func TestHandleSecrets_ReadSecret(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"token": "ghp_secret",
					"user":  "testuser",
				},
				"metadata": map[string]any{
					"version": 3,
				},
			},
		})
	})

	s := testServerWithVault(t, handler)
	req := httptest.NewRequest("GET", "/api/v1/secrets/gh", nil)
	w := httptest.NewRecorder()

	s.handleSecrets(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if resp["path"] != "gh" {
		t.Errorf("path = %v, want %q", resp["path"], "gh")
	}
	// Without reveal=true, fields should be a list of names
	fields, ok := resp["fields"].([]any)
	if !ok {
		t.Fatalf("fields is %T, want []any", resp["fields"])
	}
	if len(fields) != 2 {
		t.Errorf("len(fields) = %d, want 2", len(fields))
	}
}

func TestHandleSecrets_SlowVaultReturnsWithinTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow Vault server that still responds within the 30s timeout.
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": []string{"gh"},
			},
		})
	})

	s := testServerWithVault(t, handler)
	req := httptest.NewRequest("GET", "/api/v1/secrets/", nil)
	w := httptest.NewRecorder()

	s.handleSecrets(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
}
