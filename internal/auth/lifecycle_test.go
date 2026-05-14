package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

func TestLifecycleManager_Start(t *testing.T) {
	skipIfNoVault(t)

	vc := mustVaultClient(t)
	vc.SetToken("dev-root-token")

	lm := NewLifecycleManager(vc, 1*time.Second, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start should not block
	errCh := lm.Start(ctx)

	// Should get at least one check cycle without error
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("lifecycle error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Good — no error within timeout
	}
}

func TestLifecycleManager_NeedsReauth(t *testing.T) {
	skipIfNoVault(t)

	vc := mustVaultClient(t)
	vc.SetToken("dev-root-token")

	lm := NewLifecycleManager(vc, 1*time.Second, false)

	// With a valid root token, should not need reauth
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true for valid root token")
	}
}

func TestLifecycleManager_403TriggersReauth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" || r.Method != http.MethodGet {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{
			"errors": {"permission denied"},
		})
	}))
	defer ts.Close()

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "bad-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected non-nil error on errCh for 403")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for error on errCh after 403 response")
	}

	if !lm.NeedsReauth() {
		t.Error("NeedsReauth() = false, want true after 403")
	}
}

func TestLifecycleManager_DisableRenewalSkipsRenewCall(t *testing.T) {
	renewCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":       json.Number("30"), // well within renewal threshold
					"renewable": true,
					"expire_time": "2099-01-01T00:00:00Z",
				},
			})
		case r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut:
			renewCalled = true
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok"}})
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "some-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, true)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	<-lm.Start(ctx)

	if renewCalled {
		t.Error("RenewSelf was called despite disable_token_renewal=true")
	}
}

// TestLifecycleManager_ReloadFromTokenFile exercises the recovery path
// where a token has expired/been revoked but a fresh value has been
// written to the token file by an external process (e.g. an interactive
// `dotvault login` running in another session). The manager must pick
// up the new token on its next check and continue running instead of
// permanently latching the needs-reauth state.
func TestLifecycleManager_ReloadFromTokenFile(t *testing.T) {
	var currentValid atomic.Value // string — the token Vault will currently accept
	currentValid.Store("good-token")

	var lookups atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		lookups.Add(1)
		expected := currentValid.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Vault-Token") == expected {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":          json.Number("3600"),
					"creation_ttl": json.Number("3600"),
					"renewable":    true,
				},
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
	}))
	defer ts.Close()

	// Start with the old (now-revoked) token loaded on the client and
	// the new valid token already written to disk — emulating the
	// "user already ran `dotvault login` in another session" timing.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("new-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	currentValid.Store("new-token") // server will only accept the new token now

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	lm.SetTokenFilePath(tokenPath)

	var onReauthFired atomic.Bool
	lm.SetOnReauth(func() { onReauthFired.Store(true) })

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)

	// Drain errCh in the background — we don't assert on it here because
	// the reload path may suppress the re-auth signal entirely.
	go func() {
		for range errCh {
		}
	}()

	// Wait until the manager has had a chance to run a check and reload.
	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		if vc.Token() == "new-token" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := vc.Token(); got != "new-token" {
		t.Fatalf("client token = %q after reload, want %q", got, "new-token")
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after successful reload")
	}
	if onReauthFired.Load() {
		t.Error("OnReauth callback fired despite successful token-file reload")
	}
}

// TestLifecycleManager_ReloadPrefersFileOverStaleEnv guards against a
// regression where ResolveToken's env-first policy would re-select the
// stale VAULT_TOKEN value the daemon was originally started with and
// never observe a fresh token written to disk by an external
// `dotvault login`. The recovery path must read the file first.
func TestLifecycleManager_ReloadPrefersFileOverStaleEnv(t *testing.T) {
	var currentValid atomic.Value
	currentValid.Store("file-token")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		expected := currentValid.Load().(string)
		if r.Header.Get("X-Vault-Token") == expected {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":          json.Number("3600"),
					"creation_ttl": json.Number("3600"),
					"renewable":    true,
				},
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
	}))
	defer ts.Close()

	// VAULT_TOKEN is the same stale value the daemon is currently
	// holding — the process environment can't be updated from another
	// shell, so the file must take precedence during recovery.
	t.Setenv("VAULT_TOKEN", "stale-token")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("file-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	lm.SetTokenFilePath(tokenPath)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		if vc.Token() == "file-token" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := vc.Token(); got != "file-token" {
		t.Fatalf("client token = %q after reload, want %q (file content); env-first ResolveToken regressed", got, "file-token")
	}
}

// TestLifecycleManager_OnReauthFires verifies that when the token is
// invalid AND no fresh value is available on disk, the OnReauth callback
// fires exactly once (so web mode can clear the in-memory token and
// force the SPA back to its login screen).
func TestLifecycleManager_OnReauthFires(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
	}))
	defer ts.Close()

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "bad-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Empty token file: tryReload should return false and the manager
	// should signal re-auth.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	lm.SetTokenFilePath(tokenPath)

	var fired atomic.Int64
	lm.SetOnReauth(func() { fired.Add(1) })

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)

	select {
	case <-errCh:
		// good — re-auth signalled
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected re-auth signal on errCh within 500ms")
	}

	if got := fired.Load(); got != 1 {
		t.Errorf("OnReauth fired %d times, want exactly 1", got)
	}
	if !lm.NeedsReauth() {
		t.Error("NeedsReauth() = false, want true after re-auth signal")
	}

	// Give it another tick or two to confirm the callback isn't re-fired
	// on subsequent failures.
	time.Sleep(300 * time.Millisecond)
	if got := fired.Load(); got != 1 {
		t.Errorf("OnReauth fired %d times after additional ticks, want exactly 1", got)
	}
}

func TestLifecycleManager_TransientErrorNoReauth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" || r.Method != http.MethodGet {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string][]string{
			"errors": {"internal server error"},
		})
	}))
	defer ts.Close()

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "some-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)

	// Allow time for at least one check cycle; transient errors must not send to errCh
	select {
	case err := <-errCh:
		t.Fatalf("unexpected error on errCh for transient (non-403) error: %v", err)
	case <-time.After(300 * time.Millisecond):
		// Good — no error on errCh for transient errors
	}

	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true, want false for transient (non-403) error")
	}
}
