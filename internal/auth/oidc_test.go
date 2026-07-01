package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// newFakeOIDCVaultServer creates a test Vault HTTP server with the given
// handler and returns a vault.Client pointing to it.
func newFakeOIDCVaultServer(t *testing.T, handler http.HandlerFunc) *vault.Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	vc, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("create test vault client: %v", err)
	}
	return vc
}

func TestListenForOIDCCallback_ConfiguredPort(t *testing.T) {
	// Find a free port to use as the "configured" port.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	listener, got, err := listenForOIDCCallback(port)
	if err != nil {
		t.Fatalf("listenForOIDCCallback: %v", err)
	}
	defer listener.Close()
	if got != port {
		t.Errorf("bound port = %d, want configured port %d", got, port)
	}
}

func TestListenForOIDCCallback_FallsBackWhenConfiguredPortBusy(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	listener, got, err := listenForOIDCCallback(port)
	if err != nil {
		t.Fatalf("listenForOIDCCallback should fall back to a random port, got error: %v", err)
	}
	defer listener.Close()
	if got == port {
		t.Errorf("bound port = %d, want a fallback port different from the busy configured port", got)
	}
}

// TestListenForOIDCCallback_NonConflictErrorIsNotSwallowed pins that a bind
// failure other than "address already in use" (e.g. permission denied on a
// privileged port, or here an out-of-range port) is returned as a hard
// error rather than silently converted into a random-port fallback — that
// kind of failure won't clear itself on the next login the way a transient
// port conflict does, so it must surface instead of masking a
// misconfiguration as a benign, self-resolving one.
func TestListenForOIDCCallback_NonConflictErrorIsNotSwallowed(t *testing.T) {
	_, _, err := listenForOIDCCallback(99999)
	if err == nil {
		t.Fatal("expected error for an out-of-range port")
	}
}

func TestListenForOIDCCallback_UnsetDefaultsTo8250(t *testing.T) {
	// Occupy the built-in default so the fallback is observable
	// deterministically, without depending on 8250 being free in this
	// environment.
	occupied, err := net.Listen("tcp", "127.0.0.1:8250")
	if err != nil {
		t.Skipf("port 8250 not available in this environment: %v", err)
	}
	defer occupied.Close()

	listener, got, err := listenForOIDCCallback(0)
	if err != nil {
		t.Fatalf("listenForOIDCCallback: %v", err)
	}
	defer listener.Close()
	if got == defaultOIDCCallbackPort {
		t.Fatalf("expected fallback away from the occupied default port %d, got %d", defaultOIDCCallbackPort, got)
	}
}

// TestAuthenticateOIDC_EmptyAuthURLIsActionable pins the diagnostic added for
// the "no auth_url in OIDC response" failure mode: Vault returns 200 with no
// auth_url when it rejects the requested redirect_uri (e.g. not present in
// the role's allowed_redirect_uris). The error must name the exact
// redirect_uri dotvault sent plus the auth mount/role, so an operator can act
// on it instead of guessing.
func TestAuthenticateOIDC_EmptyAuthURLIsActionable(t *testing.T) {
	vc := newFakeOIDCVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	})

	m := &Manager{
		VaultClient:      vc,
		AuthMount:        "oidc",
		AuthRole:         "default",
		OIDCCallbackPort: 0,
	}

	err := m.authenticateOIDC(context.Background())
	if err == nil {
		t.Fatal("expected error for empty auth_url")
	}
	msg := err.Error()
	for _, want := range []string{"oidc/callback", "mount", "role", "oidc", "default"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}
}

// TestAuthenticateOIDC_SuccessWithFixedPort exercises the full happy path
// end-to-end against a fake Vault server: the redirect_uri dotvault sends
// must be the fixed 127.0.0.1:<port>/oidc/callback URI, and a "browser"
// (simulated by hitting that redirect_uri directly, standing in for the IdP
// redirect Vault would normally trigger) must be able to complete the login
// and land a Vault token on the Manager.
func TestAuthenticateOIDC_SuccessWithFixedPort(t *testing.T) {
	// Stub the browser opener: authenticateOIDC otherwise pops a real browser
	// tab to authURL on every test run.
	orig := openBrowser
	openBrowser = func(string) error { return nil }
	t.Cleanup(func() { openBrowser = orig })

	var mu sync.Mutex
	var capturedRedirectURI string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/oidc/oidc/auth_url", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RedirectURI string `json:"redirect_uri"`
			Role        string `json:"role"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		capturedRedirectURI = body.RedirectURI
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"auth_url": "http://idp.example.invalid/authorize"},
		})

		// Stand in for the browser completing the IdP login and being
		// redirected back to dotvault's local listener with a code.
		go func() {
			http.Get(body.RedirectURI + "?code=test-code&state=test-state")
		}()
	})
	mux.HandleFunc("/v1/auth/oidc/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code") != "test-code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "test-vault-token"},
		})
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	vc, err := vault.NewClient(vault.Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("create test vault client: %v", err)
	}

	// Pin a free port so the assertion on the captured redirect_uri is exact.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	dir := t.TempDir()
	m := &Manager{
		VaultClient:      vc,
		TokenFilePath:    filepath.Join(dir, "token"),
		AuthMethod:       "oidc",
		AuthMount:        "oidc",
		AuthRole:         "default",
		OIDCCallbackPort: port,
	}

	// Bound the wait: if the "browser" GET above never reaches the callback
	// listener, authenticateOIDC blocks on <-resultCh indefinitely. A short
	// deadline turns that into a fast, diagnosable failure instead of
	// relying on go test's package-level timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.authenticateOIDC(ctx); err != nil {
		t.Fatalf("authenticateOIDC: %v", err)
	}
	if m.VaultClient.Token() != "test-vault-token" {
		t.Errorf("token = %q, want test-vault-token", m.VaultClient.Token())
	}

	mu.Lock()
	redirect := capturedRedirectURI
	mu.Unlock()
	want := fmt.Sprintf("http://127.0.0.1:%d/oidc/callback", port)
	if redirect != want {
		t.Errorf("captured redirect_uri = %q, want %q", redirect, want)
	}
}
