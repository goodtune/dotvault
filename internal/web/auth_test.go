package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
		cfg:       config.WebConfig{Listen: "127.0.0.1:0"},
		vault:     vc,
		authDone:  make(chan struct{}, 1),
		authMount: "oidc",
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
	req := httptest.NewRequest("GET", "/auth/start", nil)
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
	req := httptest.NewRequest("GET", "/auth/start", nil)
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
	req := httptest.NewRequest("GET", "/auth/start", nil)
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
	req := httptest.NewRequest("GET", "/auth/start", nil)
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
	req := httptest.NewRequest("GET", "/auth/start", nil)
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
	req := httptest.NewRequest("GET", "/auth/callback", nil)
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
	req := httptest.NewRequest("GET", "/auth/callback?code=test-code&state=test-state", nil)
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
	req := httptest.NewRequest("GET", "/auth/callback?code=test-code&state=test-state", nil)
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

	req := httptest.NewRequest("GET", "/auth/callback?code=test-code&state=test-state", nil)
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
