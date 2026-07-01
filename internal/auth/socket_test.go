package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
)

// newUnixTokenServer starts an httptest server bound to a Unix socket at
// sockPath, serving GET /api/v1/token with the given handler. It returns the
// server so the caller can Close it. If the platform cannot bind a Unix-domain
// socket (some Windows configurations lack AF_UNIX server support) the test is
// skipped rather than failed — the borrow feature's listener side is Linux/macOS
// in the documented topology, and the pure-logic cases run regardless.
func newUnixTokenServer(t *testing.T, sockPath string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/token", handler)
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchTokenFromSocket_Success(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"hvs.peer-token"}`))
	})

	got, err := FetchTokenFromSocket(context.Background(), sock)
	if err != nil {
		t.Fatalf("FetchTokenFromSocket: %v", err)
	}
	if got != "hvs.peer-token" {
		t.Errorf("token = %q, want %q", got, "hvs.peer-token")
	}
}

func TestFetchTokenFromSocket_EmptyPath(t *testing.T) {
	got, err := FetchTokenFromSocket(context.Background(), "")
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchTokenFromSocket_MissingSocket(t *testing.T) {
	// A path that does not exist must resolve to ("", nil) — the peer simply
	// isn't connected, and the caller carries on with its normal auth flow.
	sock := filepath.Join(t.TempDir(), "absent.sock")
	got, err := FetchTokenFromSocket(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchTokenFromSocket_StaleSocket(t *testing.T) {
	// A regular file at the socket path (no listener) stands in for a stale
	// socket left behind by a dead SSH session: the dial fails and we carry on.
	sock := filepath.Join(t.TempDir(), "stale.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := FetchTokenFromSocket(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchTokenFromSocket_PeerUnauthenticated(t *testing.T) {
	// The peer is reachable but holds no token (mirrors handleToken's 401):
	// best-effort, so we return ("", nil) rather than an error.
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not authenticated"}`, http.StatusUnauthorized)
	})

	got, err := FetchTokenFromSocket(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchTokenFromSocket_MalformedBody(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dotvault.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`this is not json`))
	})

	got, err := FetchTokenFromSocket(context.Background(), sock)
	if err != nil || got != "" {
		t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestFetchTokenFromSocket_ExpandsHome(t *testing.T) {
	// A leading ~ must be expanded against the user's home directory so the
	// documented "~/.ssh/dotvault.sock" form works.
	home := t.TempDir()
	t.Setenv("HOME", home)        // Linux/macOS
	t.Setenv("USERPROFILE", home) // Windows
	// Keep the socket path short: Unix socket paths have a ~104-byte limit, so
	// place it directly under the (temp) home.
	sock := filepath.Join(home, "d.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"hvs.home-token"}`))
	})

	got, err := FetchTokenFromSocket(context.Background(), "~/d.sock")
	if err != nil {
		t.Fatalf("FetchTokenFromSocket: %v", err)
	}
	if got != "hvs.home-token" {
		t.Errorf("token = %q, want %q", got, "hvs.home-token")
	}
}

// mockVaultAccepting starts an httptest server standing in for Vault that
// accepts only the given token on lookup-self (any other token gets 403). It
// returns the server URL.
func mockVaultAccepting(t *testing.T, accepted string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if accepted != "" && r.Header.Get("X-Vault-Token") == accepted {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"ttl": json.Number("3600")},
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestManagerLogin_BorrowsFromSocket covers the headline production path: a
// Login with no usable local credential borrows the peer's token over the
// socket, validates it via LookupSelf, and returns without running the
// configured auth flow (here "token", which would otherwise error).
func TestManagerLogin_BorrowsFromSocket(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "") // hermetic: the socket is the only source

	vaultURL := mockVaultAccepting(t, "peer-token")

	sock := filepath.Join(t.TempDir(), "peer.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"peer-token"}`))
	})

	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	m := &Manager{
		VaultClient: vc,
		AuthMethod:  "token", // a bare token method would error without a token
		TokenSocket: sock,
		Username:    "testuser",
	}
	if err := m.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if got := vc.Token(); got != "peer-token" {
		t.Errorf("client token = %q after borrow, want %q", got, "peer-token")
	}
}

// TestManagerLogin_SocketTokenRejectedFallsThrough verifies that when the
// borrowed token fails LookupSelf, Login clears the in-memory token and falls
// through to the configured auth method (which here, "token", reports the
// usual no-token error).
func TestManagerLogin_SocketTokenRejectedFallsThrough(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	// The mock Vault accepts no token, so the borrowed one is rejected.
	vaultURL := mockVaultAccepting(t, "")

	sock := filepath.Join(t.TempDir(), "peer.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"rejected-token"}`))
	})

	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	m := &Manager{
		VaultClient: vc,
		AuthMethod:  "token",
		TokenSocket: sock,
		Username:    "testuser",
	}
	if err := m.Login(context.Background()); err == nil {
		t.Fatal("expected Login to fall through and error after the borrowed token was rejected")
	}
	if got := vc.Token(); got != "" {
		t.Errorf("in-memory token = %q after rejected borrow, want cleared", got)
	}
}
