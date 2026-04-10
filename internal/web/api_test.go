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
