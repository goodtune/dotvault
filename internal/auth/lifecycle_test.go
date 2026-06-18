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
	var renewCalled atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
			// creation_ttl=120 → renew threshold = 30s.
			// ttl=20 is below the threshold, so renewal WOULD
			// fire if disableRenewal weren't set. The earlier
			// shape (ttl=30, no creation_ttl) made the baseline
			// cache anchor at 30s and the threshold at 7.5s,
			// which meant the assertion passed vacuously: no
			// renewal would have happened regardless of the
			// flag.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":          json.Number("20"),
					"creation_ttl": json.Number("120"),
					"renewable":    true,
					"expire_time":  "2099-01-01T00:00:00Z",
				},
			})
		case r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut:
			renewCalled.Store(true)
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

	if renewCalled.Load() {
		t.Error("RenewSelf was called despite disable_token_renewal=true")
	}
}

// TestLifecycleManager_RenewWhenInsideThreshold confirms RenewSelf is
// actually called once the remaining TTL crosses below 25% of
// creation_ttl. Earlier the threshold was computed as `ttl / 4` and
// then compared `ttl <= ttl/4`, which can never hold for any positive
// ttl — renewal silently never fired and tokens were left to expire
// into a forced re-auth.
func TestLifecycleManager_RenewWhenInsideThreshold(t *testing.T) {
	var renewCalled atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					// creation_ttl=3600 → renew threshold = 900s.
					// ttl=120s is well below it.
					"ttl":          json.Number("120"),
					"creation_ttl": json.Number("3600"),
					"renewable":    true,
					"expire_time":  "2099-01-01T00:00:00Z",
				},
			})
		case r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut:
			renewCalled.Store(true)
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

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	<-lm.Start(ctx)

	if !renewCalled.Load() {
		t.Error("RenewSelf was not called despite ttl being well below the renew threshold")
	}
}

// TestLifecycleManager_SkipRenewWhenFresh confirms RenewSelf is NOT
// called when the remaining TTL is still above the threshold. Pairs
// with the previous test to pin the policy on both sides.
func TestLifecycleManager_SkipRenewWhenFresh(t *testing.T) {
	var renewCalled atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					// creation_ttl=3600 → renew threshold = 900s.
					// ttl=3000s is well above it; nothing to do.
					"ttl":          json.Number("3000"),
					"creation_ttl": json.Number("3600"),
					"renewable":    true,
					"expire_time":  "2099-01-01T00:00:00Z",
				},
			})
		case r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut:
			renewCalled.Store(true)
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

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	<-lm.Start(ctx)

	if renewCalled.Load() {
		t.Error("RenewSelf was called despite ttl being above the renew threshold")
	}
}

// TestLifecycleManager_ShortTokenWithoutCreationTTL exercises the
// baseline-caching path. A 5-minute token with no creation_ttl would
// previously satisfy the 15-minute fallback threshold on every check
// and the daemon would call RenewSelf at every poll interval; the
// baseline cache locks the threshold to creation_ttl/4 (or the
// largest observed ttl, whichever is greater) so a short-lived token
// is only renewed when its remaining TTL crosses below 25% of its
// observed lifetime.
func TestLifecycleManager_ShortTokenWithoutCreationTTL(t *testing.T) {
	var lookups, renews atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
			lookups.Add(1)
			// 5-minute (300s) token, no creation_ttl. Baseline cache
			// kicks in: baseline becomes 300s after the first check,
			// renew threshold becomes 75s. 300s is above 75s, so we
			// shouldn't renew.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":         json.Number("300"),
					"renewable":   true,
					"expire_time": "2099-01-01T00:00:00Z",
				},
			})
		case r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut:
			renews.Add(1)
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

	// Tight loop interval so we get many checks within the test
	// window. The lookups bound is deliberately loose (≥2 — enough
	// to prove the loop ticked at all) so a heavily-loaded CI
	// runner with HTTP/scheduling jitter doesn't fail this test
	// for the wrong reason; the load-bearing assertion is
	// renews == 0, which is unaffected by scheduling latency.
	lm := NewLifecycleManager(vc, 20*time.Millisecond, false)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	<-lm.Start(ctx)

	if lookups.Load() < 2 {
		t.Fatalf("expected the loop to tick at least twice (got %d) — test conditions not satisfied", lookups.Load())
	}
	if renews.Load() != 0 {
		t.Errorf("RenewSelf was called %d times for a 5min token whose remaining ttl is well above the cached-baseline threshold", renews.Load())
	}
}

// TestLifecycleManager_BaselineResetsOnTokenSwap covers the case where
// the in-memory token changes mid-lifecycle: a new shorter-TTL token
// must not inherit the oversized baseline cached from its
// predecessor. Without the reset, `ttl <= baseline/4` would fire
// immediately on the new token and the daemon would call RenewSelf
// every poll interval.
func TestLifecycleManager_BaselineResetsOnTokenSwap(t *testing.T) {
	var renews atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
			// Vault would never report different TTLs for the same
			// token across calls; we vary it by the inbound header
			// so the test simulates a token swap.
			tok := r.Header.Get("X-Vault-Token")
			ttl := "3600"
			if tok == "short-token" {
				ttl = "300"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":         json.Number(ttl),
					"renewable":   true,
					"expire_time": "2099-01-01T00:00:00Z",
				},
			})
		case r.URL.Path == "/v1/auth/token/renew-self" && r.Method == http.MethodPut:
			renews.Add(1)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok"}})
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "long-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)

	// readBaseline acquires baselineMu before snapshotting the
	// field. The test calls checkAndRenew synchronously so there
	// isn't an actual race today, but the field is documented as
	// mutex-guarded and bare reads here would diverge from that
	// contract — making the test the first thing to break if the
	// guarded-access invariant slips elsewhere.
	readBaseline := func() time.Duration {
		lm.baselineMu.Lock()
		defer lm.baselineMu.Unlock()
		return lm.baselineTTL
	}

	// First, drive a check with the long token so the baseline anchors at 3600s.
	if err := lm.checkAndRenew(context.Background()); err != nil {
		t.Fatalf("checkAndRenew (long): %v", err)
	}
	if got := readBaseline(); got != time.Hour {
		t.Fatalf("baselineTTL = %v, want 1h after long-token observation", got)
	}

	// Now swap the in-memory token to a shorter-TTL one. The
	// baseline must reset, otherwise `300 <= 3600/4` would be true
	// and the renew check would fire spuriously.
	vc.SetToken("short-token")
	if err := lm.checkAndRenew(context.Background()); err != nil {
		t.Fatalf("checkAndRenew (short): %v", err)
	}
	if got := readBaseline(); got != 300*time.Second {
		t.Errorf("baselineTTL after swap = %v, want 5m (baseline should have reset and rebound to the new token's TTL)", got)
	}
	if renews.Load() != 0 {
		t.Errorf("RenewSelf fired %d time(s) after token swap; oversized baseline leaked through", renews.Load())
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
// stale DOTVAULT_TOKEN value the daemon was originally started with and
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

	// DOTVAULT_TOKEN is the same stale value the daemon is currently
	// holding — the process environment can't be updated from another
	// shell, so the file must take precedence during recovery.
	t.Setenv("DOTVAULT_TOKEN", "stale-token")

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

// TestLifecycleManager_ReloadFromSocket verifies that when the in-memory token
// goes invalid and no fresh token is on disk or in the environment, the
// recovery path borrows a live token from a peer dotvault over the configured
// Unix socket (dotvault-to-dotvault sharing) instead of forcing a re-auth.
func TestLifecycleManager_ReloadFromSocket(t *testing.T) {
	// Hermetic: with no token file and no env token, the socket must be the
	// sole reload candidate. Clear any ambient DOTVAULT_TOKEN so a developer's
	// or CI's exported value can't sneak in as a candidate.
	t.Setenv("DOTVAULT_TOKEN", "")

	var currentValid atomic.Value
	currentValid.Store("peer-token") // server only accepts the peer's token now

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

	// The peer daemon serves its live token over the socket.
	sock := filepath.Join(t.TempDir(), "peer.sock")
	newUnixTokenServer(t, sock, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"peer-token"}`))
	})

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)
	// No token file and no DOTVAULT_TOKEN: the socket is the only candidate.
	lm.SetTokenSocket(sock)

	var onReauthFired atomic.Bool
	lm.SetOnReauth(func() { onReauthFired.Store(true) })

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		if vc.Token() == "peer-token" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := vc.Token(); got != "peer-token" {
		t.Fatalf("client token = %q after reload, want %q (borrowed from peer socket)", got, "peer-token")
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after successful socket reload")
	}
}

// TestLifecycleManager_ReloadPicksUpFreshToken verifies that Reload()
// triggers an immediate tryReload pass on the lifecycle goroutine —
// the SIGHUP / tokenwatch entry point. The test uses a
// long checkInterval so the timer-based reload path cannot satisfy the
// assertion: only Reload() can make the swap happen in time. The
// ctx/poll deadlines are generous (5s/3s) because on a CI runner under
// `-race` the goroutine scheduler can lag a few hundred ms between
// Reload() and the select arm firing.
func TestLifecycleManager_ReloadPicksUpFreshToken(t *testing.T) {
	var currentValid atomic.Value
	currentValid.Store("fresh-token")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Vault-Token") == currentValid.Load().(string) {
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

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("fresh-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// 1h check interval: the timer-based path will not fire during the
	// 5s test deadline, so the assertion can only be satisfied by Reload().
	lm := NewLifecycleManager(vc, 1*time.Hour, false)
	lm.SetTokenFilePath(tokenPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	lm.Reload()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if vc.Token() == "fresh-token" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := vc.Token(); got != "fresh-token" {
		t.Fatalf("client token = %q after Reload(), want %q", got, "fresh-token")
	}
}

// TestLifecycleManager_ReloadCoalesces verifies that back-to-back
// Reload() calls collapse into at most one queued reload pass on the
// lifecycle goroutine. The handler returns 403 for every request so
// tryReload's candidate is rejected and the in-memory token is never
// updated to match the file — every tryReload entry therefore makes
// exactly one LookupSelf call we can count. The first call parks
// inside the handler so we can fire 50 Reload()s while the goroutine
// is mid-tryReload; if the size-1 reloadCh buffer regressed (became
// unbuffered with a backlog, or larger), the handler would be hit 51
// times after release instead of the expected 2.
func TestLifecycleManager_ReloadCoalesces(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			<-release // park only the first request so the goroutine is mid-tryReload
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
	}))
	defer ts.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("fresh-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLifecycleManager(vc, 1*time.Hour, false)
	lm.SetTokenFilePath(tokenPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	// First Reload: parks the goroutine inside the handler.
	lm.Reload()
	for hits.Load() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("handler not entered within deadline")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// 50 more Reload()s while the goroutine is parked. The buffered
	// reloadCh (size 1) holds one queued nudge and the other 49 hit
	// Reload's default-branch drop.
	for i := 0; i < 50; i++ {
		lm.Reload()
	}

	// Release. The parked tryReload finishes (candidate rejected, no
	// token swap), goroutine consumes the one queued nudge and runs a
	// second tryReload — handler hits=2. No further nudges remain.
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("LookupSelf called %d times after 51 Reload() calls, want exactly 2 (1 parked + 1 coalesced); >2 means buffered-1 reloadCh coalescing regressed", got)
	}
}

// TestLifecycleManager_ReloadNoOpWhenFileUnchanged pins that Reload()
// does NOT disturb the schedule when tryReload returns false (the
// common case: the file token equals the in-memory token, so no swap
// candidate is produced). A regression that mistakenly reset the
// timer on every reload would let a flapping editor save starve the
// normal 5-minute lookup cycle.
func TestLifecycleManager_ReloadNoOpWhenFileUnchanged(t *testing.T) {
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"ttl":          json.Number("3600"),
				"creation_ttl": json.Number("3600"),
				"renewable":    true,
			},
		})
	}))
	defer ts.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	// File token == in-memory token, so tryReload short-circuits.
	if err := os.WriteFile(tokenPath, []byte("same-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "same-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLifecycleManager(vc, 1*time.Hour, false)
	lm.SetTokenFilePath(tokenPath)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	for i := 0; i < 20; i++ {
		lm.Reload()
	}
	// Let the goroutine drain any queued nudges.
	time.Sleep(300 * time.Millisecond)

	if got := hits.Load(); got != 0 {
		t.Fatalf("LookupSelf called %d times after no-op Reload bursts, want 0 (a no-op reload must not trigger a Vault round-trip)", got)
	}
}

// TestLifecycleManager_RecoversAfterTokenCleared simulates the
// post-OnReauth state: the daemon's web-mode OnReauth callback has
// cleared the in-memory Vault token, so the next lookup-self call
// goes out with no `X-Vault-Token` header and Vault returns a
// "missing client token" 400. Without the empty-token branch on the
// recoverable-failure check this would slip into the transient-error
// path, back off, and never observe a fresh token written to disk.
// The test pins the recovery path: a new token is written to the
// file after the clear, and the manager picks it up on its 10s
// recovery poll.
func TestLifecycleManager_RecoversAfterTokenCleared(t *testing.T) {
	var validToken atomic.Value
	validToken.Store("new-token")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tok := r.Header.Get("X-Vault-Token")
		switch {
		case tok == "":
			// Vault returns 400 for a request with no token header.
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"missing client token"}})
		case tok == validToken.Load().(string):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ttl":          json.Number("3600"),
					"creation_ttl": json.Number("3600"),
					"renewable":    true,
				},
			})
		default:
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"permission denied"}})
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: ""}) // already cleared
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

	// Let the manager run a tick or two with the empty token — it should
	// surface "missing client token" responses but stay on the recovery
	// path (10s recovery interval, not the transient backoff).
	time.Sleep(150 * time.Millisecond)
	if !lm.NeedsReauth() {
		t.Error("NeedsReauth() = false after empty-token checks; recovery path was not taken")
	}

	// Drop the new token on disk — the manager should pick it up.
	if err := os.WriteFile(tokenPath, []byte("new-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	deadline := time.Now().Add(800 * time.Millisecond)
	for time.Now().Before(deadline) {
		if vc.Token() == "new-token" && !lm.NeedsReauth() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := vc.Token(); got != "new-token" {
		t.Fatalf("client token = %q after token-file write, want %q (recovery never fired)", got, "new-token")
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after recovery picked up a working token")
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
