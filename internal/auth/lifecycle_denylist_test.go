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

// countingVault stands in for Vault, counting every lookup-self it is asked and
// accepting only whatever token is currently stored in accepted (empty = accept
// nothing, i.e. every token is 403 "permission denied").
type countingVault struct {
	*httptest.Server
	lookups  atomic.Int64
	accepted atomic.Value // string
}

func newCountingVault(t *testing.T) *countingVault {
	t.Helper()
	cv := &countingVault{}
	cv.accepted.Store("")
	cv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		cv.lookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if want, _ := cv.accepted.Load().(string); want != "" && r.Header.Get("X-Vault-Token") == want {
			// ttl == creation_ttl keeps the renew threshold (baseline/4) well
			// below the remaining TTL, so an accepted token never triggers a
			// renew-self this handler does not serve.
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
	t.Cleanup(cv.Close)
	return cv
}

func (cv *countingVault) accept(token string) { cv.accepted.Store(token) }

// waitForLookupsToSettle returns the lookup count once it has stopped growing
// across a window of polls, or fails if it never settles.
func waitForLookupsToSettle(t *testing.T, cv *countingVault, window time.Duration) int64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		before := cv.lookups.Load()
		time.Sleep(window)
		if cv.lookups.Load() == before {
			return before
		}
	}
	t.Fatalf("lookup-self count never settled: still climbing at %d", cv.lookups.Load())
	return 0
}

// TestLifecycleManager_DeniedTokenStopsLookupSpam is the regression test for the
// bug this cache exists to fix: with an expired token on the client and another
// unusable one in the token file, the recovery poll re-presented both to
// lookup-self on every tick, forever. Each token must now be asked about once,
// after which the poll continues (it still has to watch for a new token
// arriving) but sends nothing to Vault.
func TestLifecycleManager_DeniedTokenStopsLookupSpam(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "") // hermetic: the file is the only other source

	cv := newCountingVault(t)

	tokenFile := filepath.Join(t.TempDir(), ".dotvault-token")
	if err := os.WriteFile(tokenFile, []byte("stale-file-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{Address: cv.URL, Token: "expired-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// A 20ms check interval makes the recovery poll 20ms too (it is capped at
	// the check interval), so the settle window below covers many ticks.
	lm := NewLifecycleManager(vc, 20*time.Millisecond, false)
	lm.SetTokenFilePath(tokenFile)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a non-nil re-auth error for a wholly invalid token set")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the re-auth signal")
	}

	settled := waitForLookupsToSettle(t, cv, 300*time.Millisecond)

	// Two tokens exist and each is worth exactly one question: the client's own
	// and the file's. Allow a little slack for a tick that was already in
	// flight, but nothing like the ~15 per 300ms the old code produced.
	if settled > 4 {
		t.Errorf("lookup-self called %d times before settling, want <= 4 (one per distinct token)", settled)
	}
	if !lm.NeedsReauth() {
		t.Error("NeedsReauth() = false; suppression must not hide the fact that re-auth is needed")
	}

	// Suppression must not outlive the token: a genuinely fresh token written
	// to the file is picked up on the next reload nudge (the inotify watcher's
	// job in the daemon) even though the manager has given up on two others.
	cv.accept("fresh-token")
	if err := os.WriteFile(tokenFile, []byte("fresh-token"), 0600); err != nil {
		t.Fatalf("rewrite token file: %v", err)
	}
	lm.Reload()

	deadline := time.Now().Add(2 * time.Second)
	for vc.Token() != "fresh-token" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := vc.Token(); got != "fresh-token" {
		t.Fatalf("client token = %q after a fresh token was written, want %q", got, "fresh-token")
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after adopting a valid token")
	}
}

// TestLifecycleManager_ReloadRetriesThenReSuppresses covers the other half of
// the contract: a reload nudge (inotify saw the token file rewritten, a peer
// socket reconnected, or an operator sent SIGHUP) clears the suppression and
// tries again — because Vault's reason for refusing may have been server-side —
// and a token refused a second time is suppressed again rather than reopening
// the loop.
func TestLifecycleManager_ReloadRetriesThenReSuppresses(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	cv := newCountingVault(t)

	tokenFile := filepath.Join(t.TempDir(), ".dotvault-token")
	if err := os.WriteFile(tokenFile, []byte("stale-file-token"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	vc, err := vault.NewClient(vault.Config{Address: cv.URL, Token: "expired-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 20*time.Millisecond, false)
	lm.SetTokenFilePath(tokenFile)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lm.Start(ctx)

	settled := waitForLookupsToSettle(t, cv, 300*time.Millisecond)

	lm.Reload()

	resettled := waitForLookupsToSettle(t, cv, 300*time.Millisecond)
	if resettled <= settled {
		t.Errorf("lookup-self count %d unchanged after Reload(); a rewritten token file must get a fresh attempt", resettled)
	}
	if grew := resettled - settled; grew > 4 {
		t.Errorf("Reload() cost %d lookups, want <= 4 (one per token, then re-suppressed)", grew)
	}
}
