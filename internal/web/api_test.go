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
	}
}
