package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// mockVaultAccepting starts an httptest server standing in for Vault that
// accepts only the given token on lookup-self (any other token gets 403).
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

// serveUnixToken binds a Unix socket at sockPath serving GET /api/v1/token. If
// the platform cannot bind a Unix socket the test is skipped.
func serveUnixToken(t *testing.T, sockPath, token string) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable on this platform: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

// TestWaitForHeadlessToken_BorrowsFromSocket covers the bug a headless daemon
// hit: with no token file it must still dial the peer socket and borrow a token
// rather than idling forever. The socket is present before the call, so the
// first tryAcquire pass borrows deterministically (no reliance on inotify).
func TestWaitForHeadlessToken_BorrowsFromSocket(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "") // hermetic: the socket is the only source

	vaultURL := mockVaultAccepting(t, "peer-token")
	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	sock := filepath.Join(t.TempDir(), "peer.sock")
	serveUnixToken(t, sock, "peer-token")

	// A token-file path that does not exist — the borrow is the only way in.
	tokenPath := filepath.Join(t.TempDir(), ".dotvault-token")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !waitForHeadlessToken(ctx, vc, tokenPath, sock) {
		t.Fatal("waitForHeadlessToken returned false; expected a borrowed token")
	}
	if got := vc.Token(); got != "peer-token" {
		t.Errorf("client token = %q after borrow, want %q", got, "peer-token")
	}
}

// TestWaitForHeadlessToken_SocketMaterialisesLater exercises the inotify path:
// the socket does not exist when the wait begins, then an SSH RemoteForward
// (modelled here by a goroutine) creates it. The directory watch must fire and
// trigger an immediate borrow rather than waiting out the 10s poll. Linux-only
// — on other platforms the tokenwatch is a no-op and the poll covers it (which
// would make this test take up to 10s, so it is skipped there).
func TestWaitForHeadlessToken_SocketMaterialisesLater(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inotify socket watch is Linux-only; other platforms rely on the 10s poll")
	}
	t.Setenv("DOTVAULT_TOKEN", "")

	vaultURL := mockVaultAccepting(t, "late-token")
	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "peer.sock")
	tokenPath := filepath.Join(t.TempDir(), ".dotvault-token")

	// Create the socket ~150ms after the wait starts. inotify on the socket's
	// parent directory should deliver IN_CREATE and wake tryAcquire well before
	// the 10s poll tick. The deferred receive both closes the server and joins
	// the goroutine. net.Listen("unix", …) does not fail on Linux.
	srvCh := make(chan *httptest.Server, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		ln, lerr := net.Listen("unix", sock)
		if lerr != nil {
			srvCh <- nil
			return
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "late-token"})
		})
		srv := httptest.NewUnstartedServer(mux)
		srv.Listener = ln
		srv.Start()
		srvCh <- srv
	}()
	defer func() {
		if srv := <-srvCh; srv != nil {
			srv.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	if !waitForHeadlessToken(ctx, vc, tokenPath, sock) {
		t.Fatal("waitForHeadlessToken returned false; expected a borrow once the socket materialised")
	}
	if got := vc.Token(); got != "late-token" {
		t.Errorf("client token = %q, want late-token", got)
	}
}

// TestWaitForHeadlessToken_CancelWithoutToken preserves the existing contract:
// when no token ever becomes available, a cancelled context makes the function
// return false rather than blocking forever.
func TestWaitForHeadlessToken_CancelWithoutToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	vaultURL := mockVaultAccepting(t, "never-offered")
	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), ".dotvault-token")
	// No socket configured: nothing to borrow, nothing to promote.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if waitForHeadlessToken(ctx, vc, tokenPath, "") {
		t.Fatal("waitForHeadlessToken returned true with no token source")
	}
}
