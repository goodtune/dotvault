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

func TestHandleConfig_Authenticated(t *testing.T) {
	s := testServerWithVault(t, http.HandlerFunc(fakeVaultHandler))
	s.vaultCfg = config.VaultConfig{
		Address:       "http://127.0.0.1:8200",
		CACert:        "-----BEGIN CERTIFICATE-----\nsecret\n-----END CERTIFICATE-----",
		TLSSkipVerify: true,
	}
	s.syncCfg = config.SyncConfig{RawInterval: "15m"}
	s.cfg = config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"}
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
		"oauth_token":   "ghp_xxx",
		"api_key":       "k",
		"refresh_TOKEN": "r",
		"private_key":   "-----BEGIN-----",
	}
	out := redactEnrolmentSettings(in)
	if out["url"] != "https://example.jfrog.io" || out["client_id"] != "abc" {
		t.Errorf("non-sensitive keys altered: %v", out)
	}
	for _, k := range []string{"oauth_token", "api_key", "refresh_TOKEN", "private_key"} {
		if out[k] != "***" {
			t.Errorf("settings[%q] = %v, want redacted", k, out[k])
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
