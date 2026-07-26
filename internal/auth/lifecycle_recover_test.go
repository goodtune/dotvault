package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// newRecoveryVaultServer stands up a fake Vault whose lookup-self accepts
// exactly one token value (read live from valid, so a test can move the
// goalposts mid-run). An empty token header gets Vault's real "missing client
// token" 400; anything else gets a 403. This is the same shape the existing
// reload tests use, factored out because every recovery case needs it.
func newRecoveryVaultServer(t *testing.T, valid *atomic.Value) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tok := r.Header.Get("X-Vault-Token")
		switch {
		case tok == "":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string][]string{"errors": {"missing client token"}})
		case tok == valid.Load().(string):
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
	t.Cleanup(ts.Close)
	return ts
}

// waitFor polls cond until it holds or the deadline passes. Returns whether it
// held. Polling (rather than sleeping a fixed amount) keeps the timer-driven
// lifecycle tests fast in the common case and tolerant of scheduler lag under
// -race.
func waitFor(cond func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestLifecycleManager_RecoverWiring pins how the unattended-recovery hook
// (LifecycleManager.SetRecover, satisfied in production by
// Manager.CertLoginFromStore) participates in the recovery branch of the Start
// loop. The headline case is recoverSucceeds: a certificate-auth daemon whose
// Vault token expired mints a fresh one from the credential already on disk,
// and — crucially — must NOT fire OnReauth, which in web mode would clear
// in-memory auth state and bounce the SPA to a login screen for an outage the
// daemon just healed by itself.
func TestLifecycleManager_RecoverWiring(t *testing.T) {
	const recoveredToken = "recovered-token"

	tests := []struct {
		name string
		// makeRecover returns the hook to register, or nil to register none
		// (the oidc/ldap shape, where the credential is a human).
		makeRecover func(vc *vault.Client, calls *atomic.Int64) func(context.Context) error
		// tokenFileContent, when non-empty, is written to a token file wired
		// via SetTokenFilePath — used to prove tryReload precedence.
		tokenFileContent string
		// settled is the condition the test waits on before asserting.
		settled func(lm *LifecycleManager, vc *vault.Client, calls *atomic.Int64, reauths *atomic.Int64) bool

		wantToken       string
		wantNeedsReauth bool
		wantReauths     int64
		wantMinCalls    int64
	}{
		{
			// 1. Recovery succeeds: token swapped, no re-auth signal at all.
			name: "recoverSucceeds",
			makeRecover: func(vc *vault.Client, calls *atomic.Int64) func(context.Context) error {
				return func(context.Context) error {
					calls.Add(1)
					vc.SetToken(recoveredToken)
					return nil
				}
			},
			settled: func(_ *LifecycleManager, vc *vault.Client, _, _ *atomic.Int64) bool {
				return vc.Token() == recoveredToken
			},
			wantToken:       recoveredToken,
			wantNeedsReauth: false,
			wantReauths:     0,
			wantMinCalls:    1,
		},
		{
			// 2. Recovery fails: fall through to the pre-existing behaviour.
			name: "recoverFails",
			makeRecover: func(_ *vault.Client, calls *atomic.Int64) func(context.Context) error {
				return func(context.Context) error {
					calls.Add(1)
					return errors.New("certificate credential is unusable")
				}
			},
			settled: func(lm *LifecycleManager, _ *vault.Client, _, reauths *atomic.Int64) bool {
				return lm.NeedsReauth() && reauths.Load() > 0
			},
			wantToken:       "stale-token",
			wantNeedsReauth: true,
			wantReauths:     1,
			wantMinCalls:    1,
		},
		{
			// 3. No hook registered (oidc/ldap): unchanged behaviour.
			name: "recoverNil",
			settled: func(lm *LifecycleManager, _ *vault.Client, _, reauths *atomic.Int64) bool {
				return lm.NeedsReauth() && reauths.Load() > 0
			},
			wantToken:       "stale-token",
			wantNeedsReauth: true,
			wantReauths:     1,
			wantMinCalls:    0,
		},
		{
			// 4. A hook that lies — reports success but leaves the client with
			// no token — must not be believed. Treated exactly like a failure.
			name: "recoverLeavesTokenEmpty",
			makeRecover: func(vc *vault.Client, calls *atomic.Int64) func(context.Context) error {
				return func(context.Context) error {
					calls.Add(1)
					vc.SetToken("")
					return nil
				}
			},
			settled: func(lm *LifecycleManager, _ *vault.Client, _, reauths *atomic.Int64) bool {
				return lm.NeedsReauth() && reauths.Load() > 0
			},
			wantToken:       "",
			wantNeedsReauth: true,
			wantReauths:     1,
			wantMinCalls:    1,
		},
		{
			// 5. Retried on every recovery poll: a hook that fails once then
			// succeeds recovers the daemon without a restart. (OnReauth has
			// already fired by then — the point is the daemon heals anyway.)
			name: "recoverRetriedUntilSuccess",
			makeRecover: func(vc *vault.Client, calls *atomic.Int64) func(context.Context) error {
				return func(context.Context) error {
					if calls.Add(1) == 1 {
						return errors.New("transient vault outage")
					}
					vc.SetToken(recoveredToken)
					return nil
				}
			},
			settled: func(lm *LifecycleManager, vc *vault.Client, _, _ *atomic.Int64) bool {
				return vc.Token() == recoveredToken && !lm.NeedsReauth()
			},
			wantToken:       recoveredToken,
			wantNeedsReauth: false,
			wantReauths:     1,
			wantMinCalls:    2,
		},
		{
			// 6. tryReload wins: a valid token on disk is adopted and the
			// recovery hook is never consulted. Minting a brand-new token when
			// a perfectly good one is sitting in the file would be wasteful and
			// would fight a parallel `dotvault login`.
			name: "tokenFileTakesPrecedence",
			makeRecover: func(vc *vault.Client, calls *atomic.Int64) func(context.Context) error {
				return func(context.Context) error {
					calls.Add(1)
					vc.SetToken(recoveredToken)
					return nil
				}
			},
			tokenFileContent: "file-token",
			settled: func(lm *LifecycleManager, vc *vault.Client, _, _ *atomic.Int64) bool {
				return vc.Token() == "file-token" && !lm.NeedsReauth()
			},
			wantToken:       "file-token",
			wantNeedsReauth: false,
			wantReauths:     0,
			wantMinCalls:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Hermetic: DOTVAULT_TOKEN must not become a surprise reload
			// candidate on a developer machine that exports one.
			t.Setenv("DOTVAULT_TOKEN", "")

			var valid atomic.Value
			// Both the recovered token and a token written to the file are
			// accepted by the fake Vault; only one is reachable per case.
			if tt.tokenFileContent != "" {
				valid.Store(tt.tokenFileContent)
			} else {
				valid.Store(recoveredToken)
			}
			ts := newRecoveryVaultServer(t, &valid)

			vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			lm := NewLifecycleManager(vc, 50*time.Millisecond, false)

			if tt.tokenFileContent != "" {
				tokenPath := filepath.Join(t.TempDir(), ".vault-token")
				if err := os.WriteFile(tokenPath, []byte(tt.tokenFileContent), 0600); err != nil {
					t.Fatalf("write token file: %v", err)
				}
				lm.SetTokenFilePath(tokenPath)
			}

			var calls, reauths atomic.Int64
			if tt.makeRecover != nil {
				lm.SetRecover(tt.makeRecover(vc, &calls))
			}
			lm.SetOnReauth(func() { reauths.Add(1) })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			errCh := lm.Start(ctx)
			go func() {
				for range errCh {
				}
			}()

			if !waitFor(func() bool { return tt.settled(lm, vc, &calls, &reauths) }, 3*time.Second) {
				t.Fatalf("condition never settled: token=%q needsReauth=%v recoverCalls=%d onReauth=%d",
					vc.Token(), lm.NeedsReauth(), calls.Load(), reauths.Load())
			}

			// Let a couple more poll cycles run so a callback that fires
			// repeatedly (rather than once per transition) is caught, and so a
			// state that only transiently looked right is caught too.
			time.Sleep(200 * time.Millisecond)

			if got := vc.Token(); got != tt.wantToken {
				t.Errorf("client token = %q, want %q", got, tt.wantToken)
			}
			if got := lm.NeedsReauth(); got != tt.wantNeedsReauth {
				t.Errorf("NeedsReauth() = %v, want %v", got, tt.wantNeedsReauth)
			}
			if got := reauths.Load(); got != tt.wantReauths {
				t.Errorf("OnReauth fired %d times, want exactly %d", got, tt.wantReauths)
			}
			if got := calls.Load(); got < tt.wantMinCalls {
				t.Errorf("recover hook called %d times, want at least %d", got, tt.wantMinCalls)
			}
			if tt.wantMinCalls == 0 && tt.makeRecover != nil {
				if got := calls.Load(); got != 0 {
					t.Errorf("recover hook called %d times, want 0 (tryReload should have satisfied the recovery)", got)
				}
			}
		})
	}
}

// TestLifecycleManager_tryRecover exercises tryRecover directly — the same
// four outcomes the wiring test observes indirectly, but pinned at the unit
// level so a regression names the guard that broke. In particular the
// "reports success but leaves no token" case: a hook whose word is taken at
// face value would have the loop clear needs-reauth on a client that cannot
// talk to Vault at all.
func TestLifecycleManager_tryRecover(t *testing.T) {
	tests := []struct {
		name    string
		hook    func(vc *vault.Client) func(context.Context) error
		want    bool
		wantTok string
	}{
		{
			name:    "nilHook",
			want:    false,
			wantTok: "stale-token",
		},
		{
			name: "hookErrors",
			hook: func(*vault.Client) func(context.Context) error {
				return func(context.Context) error { return errors.New("boom") }
			},
			want:    false,
			wantTok: "stale-token",
		},
		{
			name: "hookSucceedsButLeavesNoToken",
			hook: func(vc *vault.Client) func(context.Context) error {
				return func(context.Context) error {
					vc.SetToken("")
					return nil
				}
			},
			want:    false,
			wantTok: "",
		},
		{
			name: "hookSucceeds",
			hook: func(vc *vault.Client) func(context.Context) error {
				return func(context.Context) error {
					vc.SetToken("minted")
					return nil
				}
			},
			want:    true,
			wantTok: "minted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No Vault round-trip happens in tryRecover — the address is
			// never dialled, so an unreachable one is fine and keeps the
			// test hermetic.
			vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:1", Token: "stale-token"})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			lm := NewLifecycleManager(vc, time.Hour, false)
			if tt.hook != nil {
				lm.SetRecover(tt.hook(vc))
			}
			if got := lm.tryRecover(context.Background()); got != tt.want {
				t.Errorf("tryRecover() = %v, want %v", got, tt.want)
			}
			if got := vc.Token(); got != tt.wantTok {
				t.Errorf("client token = %q, want %q", got, tt.wantTok)
			}
		})
	}
}

// TestLifecycleManager_RecoverIsBounded pins the timeout on an unattended
// recovery attempt.
//
// The hook runs synchronously on the lifecycle goroutine and, for certificate
// auth, opens a secure store and performs a TLS handshake plus a Vault login.
// Unbounded, an unreachable Vault would stall token management for every other
// token the manager looks after — the Vault SDK's own default is ~60s. The
// hook must therefore receive a context carrying a deadline.
//
// Asserting the deadline exists (rather than timing a slow hook) keeps this
// fast and non-flaky. Removing the context.WithTimeout in tryRecover must fail
// this test.
func TestLifecycleManager_RecoverIsBounded(t *testing.T) {
	lm := &LifecycleManager{client: &vault.Client{}}

	var (
		gotDeadline bool
		remaining   time.Duration
	)
	lm.SetRecover(func(ctx context.Context) error {
		dl, ok := ctx.Deadline()
		gotDeadline = ok
		if ok {
			remaining = time.Until(dl)
		}
		return context.DeadlineExceeded // force the failure path
	})

	if lm.tryRecover(context.Background()) {
		t.Fatal("tryRecover() = true, want false when the hook errors")
	}
	if !gotDeadline {
		t.Fatal("recovery hook received a context with no deadline; an unreachable Vault would stall the lifecycle goroutine")
	}
	if remaining <= 0 || remaining > recoverTimeout {
		t.Errorf("deadline %v out of range (0, %v]", remaining, recoverTimeout)
	}
}
