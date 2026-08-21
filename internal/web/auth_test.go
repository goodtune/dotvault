package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	lt := auth.NewLoginTracker(vc)
	t.Cleanup(lt.Close)
	return &Server{
		cfg:        config.WebConfig{Listen: "127.0.0.1:0"},
		vault:      vc,
		csrf:       NewCSRFStore(),
		login:      lt,
		authDone:   make(chan struct{}, 1),
		authMethod: "oidc",
		authMount:  "oidc",
		listenAddr: "127.0.0.1:8250",
		// The login handlers are browser-facing: originAllowed refuses every
		// Origin on a daemon with no TCP listener, so model one here.
		webEnabled: true,
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

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want %q", loc, "/")
	}

	// authDone must be signaled.
	select {
	case <-s.authDone:
		// success
	default:
		t.Error("authDone was not signaled after successful callback")
	}
}

// TestHandleAuthCallback_Downscopes proves the web OIDC path narrows the
// broad login token to a least-privilege child when vault.policies is set:
// the broad token from the callback becomes the parent of an auth/token/create
// call, and the child token is what the server adopts. Without the production
// wiring this test fails because s.vault.Token() would still be the broad one.
func TestHandleAuthCallback_Downscopes(t *testing.T) {
	var createBody map[string]any
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/oidc/oidc/callback":
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "broad-token", "policies": []string{"default", "admin"}},
			})
		case "/v1/auth/token/create":
			if got := r.Header.Get("X-Vault-Token"); got != "broad-token" {
				t.Errorf("child created off token %q, want broad-token", got)
			}
			_ = json.NewDecoder(r.Body).Decode(&createBody)
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "child-token"},
			})
		default:
			t.Errorf("unexpected vault path: %s", r.URL.Path)
		}
	})

	s := authTestServer(t, vc)
	s.vaultCfg = config.VaultConfig{Policies: []string{"dotvault"}, NoDefaultPolicy: true}
	s.tokenFilePath = filepath.Join(t.TempDir(), "vault-token")

	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=c&state=s", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := s.vault.Token(); got != "child-token" {
		t.Errorf("adopted token = %q, want child-token (the downscoped child)", got)
	}
	if createBody == nil {
		t.Fatal("auth/token/create was never called — downscoping did not happen")
	}
	if ndp, _ := createBody["no_default_policy"].(bool); !ndp {
		t.Errorf("child create no_default_policy = %v, want true", createBody["no_default_policy"])
	}
}

// TestHandleAuthCallback_DownscopeFailureDoesNotLeakBroadToken is the web-layer
// regression for the leak where a failed downscope left the broad login token
// installed on the shared client — which the auth gate treats as authenticated
// and /api/v1/token would hand out. On a downscope failure the handler must
// 500 AND leave s.vault holding no token.
func TestHandleAuthCallback_DownscopeFailureDoesNotLeakBroadToken(t *testing.T) {
	vc := newFakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/oidc/oidc/callback":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "broad-token", "policies": []string{"admin"}},
			})
		case "/v1/auth/token/create":
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		default:
			t.Errorf("unexpected vault path: %s", r.URL.Path)
		}
	})

	s := authTestServer(t, vc)
	s.vaultCfg = config.VaultConfig{Policies: []string{"dotvault"}}
	s.tokenFilePath = filepath.Join(t.TempDir(), "vault-token")

	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=c&state=s", nil)
	w := httptest.NewRecorder()
	s.handleAuthCallback(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 on downscope failure", w.Code)
	}
	if got := s.vault.Token(); got != "" {
		t.Errorf("shared client token = %q, want empty — a failed downscope must not leave the broad token retrievable via /api/v1/token", got)
	}
	// authDone must NOT be signalled — auth did not complete.
	select {
	case <-s.authDone:
		t.Error("authDone signalled despite downscope failure")
	default:
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
