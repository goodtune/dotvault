package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
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

	if !waitForHeadlessToken(ctx, vc, tokenPath, []string{sock}, auth.NewTokenDenylist()) {
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

	if !waitForHeadlessToken(ctx, vc, tokenPath, []string{sock}, auth.NewTokenDenylist()) {
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

	if waitForHeadlessToken(ctx, vc, tokenPath, nil, auth.NewTokenDenylist()) {
		t.Fatal("waitForHeadlessToken returned true with no token source")
	}
}

// TestHeadlessTokenPathGatedByPersistence pins the runtime half of the
// no-token-at-rest guarantee, which pre-push security review found missing.
//
// certLogin removing the token file only holds if nothing puts one back. The
// headless idle watched and adopted the token file unconditionally, so a file
// appearing afterwards — restored from a backup, written by an older build, or
// dropped by anything running as this user — would be promoted to the daemon's
// working credential, and ahead of the certificate that is the correct source
// of a replacement under this method.
func TestHeadlessTokenPathGatedByPersistence(t *testing.T) {
	const path = "/home/alice/.dotvault-token"
	for _, tt := range []struct {
		method string
		want   string
	}{
		{method: "mtls+os", want: ""},
		{method: "mtls", want: path},
		{method: "mtls+tpm", want: path},
		{method: "oidc", want: path},
		{method: "oidc+os", want: path}, // no-persist is implemented only off mtls
	} {
		t.Run(tt.method, func(t *testing.T) {
			if got := headlessTokenPath(tt.method, path); got != tt.want {
				t.Errorf("headlessTokenPath(%q, path) = %q, want %q", tt.method, got, tt.want)
			}
		})
	}
}

// TestWaitForHeadlessTokenIgnoresFileWhenPathEmpty is the behavioural half:
// an empty token path must make the idle ignore the file entirely rather than
// fall back to some default. A token file sits on disk and a live Vault would
// accept it, so adopting it is observable — the call must instead block until
// ctx expires.
func TestWaitForHeadlessTokenIgnoresFileWhenPathEmpty(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"s.dropped-in","ttl":3600}}`))
	}))
	t.Cleanup(srv.Close)

	vc, err := vault.NewClient(vault.Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), ".dotvault-token")
	if err := os.WriteFile(tokenPath, []byte("s.dropped-in"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if waitForHeadlessToken(ctx, vc, "", nil, nil) {
		t.Fatal("waitForHeadlessToken adopted a token despite an empty token path — a file dropped on a no-persist host would become the daemon's credential")
	}
	if got := vc.Token(); got != "" {
		t.Errorf("client is holding %q", got)
	}
}

// countingMockVault is mockVaultAccepting plus a request counter, for asserting
// what the idle loop does NOT send.
func countingMockVault(t *testing.T, accepted string, calls *atomic.Int64) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
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

// TestWaitForHeadlessToken_RecordsRejectedToken pins the first half of the
// denied-token contract on the startup idle: a token file Vault refuses costs
// exactly one lookup, and the refusal is recorded in the shared cache so the
// lifecycle manager that takes over later does not ask again.
func TestWaitForHeadlessToken_RecordsRejectedToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	var calls atomic.Int64
	vaultURL := countingMockVault(t, "", &calls) // accepts nothing
	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), ".dotvault-token")
	if err := os.WriteFile(tokenPath, []byte("stale-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	denyList := auth.NewTokenDenylist()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if waitForHeadlessToken(ctx, vc, tokenPath, nil, denyList) {
		t.Fatal("waitForHeadlessToken returned true for a token Vault refuses")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("lookup-self called %d times, want 1", got)
	}
	if !denyList.Denied(ctx, "stale-token") {
		t.Error("rejected token was not recorded in the shared denylist; the lifecycle manager would re-present it")
	}
}

// TestWaitForHeadlessToken_SkipsAlreadyDeniedToken is the second half: a token
// an earlier startup step already watched Vault refuse must not be re-presented
// here. Without the shared cache, the reuse check and this loop each asked
// about the same expired ~/.dotvault-token, and the loop then kept asking for
// as long as the daemon idled.
func TestWaitForHeadlessToken_SkipsAlreadyDeniedToken(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	var calls atomic.Int64
	vaultURL := countingMockVault(t, "", &calls)
	vc, err := vault.NewClient(vault.Config{Address: vaultURL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), ".dotvault-token")
	if err := os.WriteFile(tokenPath, []byte("stale-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	denyList := auth.NewTokenDenylist()
	denyList.Deny("stale-token") // as an earlier startup step would have

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if waitForHeadlessToken(ctx, vc, tokenPath, nil, denyList) {
		t.Fatal("waitForHeadlessToken returned true for a suppressed token")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("lookup-self called %d times for a token already known to be refused, want 0", got)
	}
}
