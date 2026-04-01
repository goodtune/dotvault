package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
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

func testServer(t *testing.T) *Server {
	t.Helper()
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
		kvMount:    "secret",
		userPrefix: "users/",
		username:   "testuser",
		authMethod: "oidc",
	}
}
