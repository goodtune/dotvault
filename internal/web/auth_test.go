package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// newFakeVaultServer creates a test Vault HTTP server with the given handler
// and returns a vault.Client pointing to it.
func newFakeVaultServer(t *testing.T, handler http.HandlerFunc) *vault.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	vc, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("create test vault client: %v", err)
	}
	return vc
}

// authTestServer creates a Server wired up with the given vault client and
// the fields needed by the auth handlers.
func authTestServer(t *testing.T, vc *vault.Client) *Server {
	t.Helper()
	return &Server{
		cfg:        config.WebConfig{Listen: "127.0.0.1:0"},
		vault:      vc,
		csrf:       NewCSRFStore(),
		login:      auth.NewLoginTracker(vc),
		authDone:   make(chan struct{}, 1),
		authMethod: "oidc",
		authMount:  "oidc",
		listenAddr: "127.0.0.1:8250",
	}
}

// --- handleAuthStart ---

func TestHandleAuthStart_VaultError(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"vault unavailable"}})
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/start", nil)
	w := httptest.NewRecorder()
	s.handleAuthStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for vault error", w.Code)
	}
}

func TestHandleAuthStart_NilSecret(t *testing.T) {
	// 204 No Content causes the Vault API client to return (nil, nil).
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/start", nil)
	w := httptest.NewRecorder()
	s.handleAuthStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for nil secret", w.Code)
	}
}

func TestHandleAuthStart_NilSecretData(t *testing.T) {
	// A response with no data field results in a non-nil secret with nil Data.
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"request_id": "test"})
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/start", nil)
	w := httptest.NewRecorder()
	s.handleAuthStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for nil secret data", w.Code)
	}
}

func TestHandleAuthStart_MissingAuthURL(t *testing.T) {
	// Secret data present but no auth_url key.
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "test",
			"data":       map[string]any{},
		})
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/start", nil)
	w := httptest.NewRecorder()
	s.handleAuthStart(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for missing auth_url", w.Code)
	}
}

func TestHandleAuthStart_Success(t *testing.T) {
	const oidcURL = "https://provider.example.com/auth?state=abc&nonce=xyz"
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "test",
			"data":       map[string]any{"auth_url": oidcURL},
		})
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/start", nil)
	w := httptest.NewRecorder()
	s.handleAuthStart(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != oidcURL {
		t.Errorf("Location = %q, want %q", loc, oidcURL)
	}
}

// --- handleAuthCallback ---

func TestHandleAuthCallback_MissingCode(t *testing.T) {
	s := authTestServer(t, nil) // vault not called when code is missing
	req := httptest.NewRequest("GET", "/auth/oidc/callback", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing code", w.Code)
	}
}

func TestHandleAuthCallback_VaultError(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid state"}})
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=test-code&state=test-state", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for vault error", w.Code)
	}
}

func TestHandleAuthCallback_NilAuth(t *testing.T) {
	// Vault returns a secret with no auth block.
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"request_id": "test"})
	})

	s := authTestServer(t, vc)
	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=test-code&state=test-state", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for nil auth block", w.Code)
	}
}

func TestHandleAuthCallback_Success(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "test",
			"auth": map[string]any{
				"client_token":   "hvs.test-token",
				"lease_duration": 3600,
				"renewable":      true,
				"policies":       []string{"default"},
				"metadata":       map[string]any{},
			},
		})
	})

	s := authTestServer(t, vc)
	s.tokenFilePath = filepath.Join(t.TempDir(), "vault-token")

	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=test-code&state=test-state", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	// authDone must be signaled.
	select {
	case <-s.authDone:
		// success
	default:
		t.Error("authDone was not signaled after successful callback")
	}
}

// --- WaitForAuth ---

func TestWaitForAuth_SignalReceived(t *testing.T) {
	s := &Server{authDone: make(chan struct{}, 1)}
	s.authDone <- struct{}{}

	if err := s.WaitForAuth(context.Background()); err != nil {
		t.Errorf("WaitForAuth() = %v, want nil", err)
	}
}

func TestWaitForAuth_ContextCancelled(t *testing.T) {
	s := &Server{authDone: make(chan struct{}, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.WaitForAuth(ctx); err == nil {
		t.Error("WaitForAuth() = nil, want error for cancelled context")
	}
}

// --- handleLDAPLogin ---

func TestHandleLDAPLogin_Success(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "req-1",
			"auth": map[string]any{
				"client_token":   "hvs.ldap-token",
				"lease_duration": 3600,
				"renewable":      true,
			},
		})
	})

	s := authTestServer(t, vc)
	s.authMethod = "ldap"
	s.authMount = "ldap"

	body := strings.NewReader(`{"username":"testuser","password":"secret"}`)
	req := httptest.NewRequest("POST", "/auth/ldap/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleLDAPLogin(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", w.Code)
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	sessionID, ok := resp["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatal("response missing session_id")
	}
}

// --- handleLDAPStatus ---

func TestHandleLDAPStatus_MissingSession(t *testing.T) {
	s := authTestServer(t, nil)

	req := httptest.NewRequest("GET", "/auth/ldap/status", nil)
	w := httptest.NewRecorder()
	s.handleLDAPStatus(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleLDAPStatus_NotFound(t *testing.T) {
	s := authTestServer(t, nil)

	req := httptest.NewRequest("GET", "/auth/ldap/status?session=nonexistent", nil)
	w := httptest.NewRecorder()
	s.handleLDAPStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// --- handleTokenLogin ---

func TestHandleTokenLogin_Success(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"request_id": "req-1",
			"data": map[string]any{
				"ttl":       3600,
				"renewable": true,
			},
		})
	})

	s := authTestServer(t, vc)
	s.tokenFilePath = filepath.Join(t.TempDir(), "vault-token")

	body := strings.NewReader(`{"token":"hvs.test-token"}`)
	req := httptest.NewRequest("POST", "/auth/token/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleTokenLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	select {
	case <-s.authDone:
		// success
	default:
		t.Error("authDone was not signaled")
	}
}

func TestHandleTokenLogin_InvalidToken(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
	})

	s := authTestServer(t, vc)

	body := strings.NewReader(`{"token":"invalid-token"}`)
	req := httptest.NewRequest("POST", "/auth/token/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleTokenLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
