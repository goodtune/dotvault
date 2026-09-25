package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// TestLifecycleManager_NotifyRejectedTriggersImmediateRecovery pins the whole
// point of NotifyRejected: a subsystem outside this manager (the SSH agent's
// vault-ca source, a managed SSH forward) that independently observes Vault
// reject the shared token can make the manager recover NOW instead of waiting
// out checkInterval.
//
// The test uses a 1-hour checkInterval so the timer-based path cannot satisfy
// the assertion within the test's deadline — only NotifyRejected can. No
// token file or peer socket is wired (mirroring mtls+os, which keeps neither),
// so tryReload has no candidate and the recover hook is what must fire.
func TestLifecycleManager_NotifyRejectedTriggersImmediateRecovery(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	const recoveredToken = "recovered-token"
	var valid atomic.Value
	valid.Store(recoveredToken)
	ts := newRecoveryVaultServer(t, &valid)

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, time.Hour, false)
	var recoverCalls atomic.Int64
	lm.SetRecover(func(context.Context) error {
		recoverCalls.Add(1)
		vc.SetToken(recoveredToken)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	lm.NotifyRejected(forbiddenErr())

	if !waitFor(func() bool { return vc.Token() == recoveredToken }, 3*time.Second) {
		t.Fatalf("client token = %q after NotifyRejected, want %q", vc.Token(), recoveredToken)
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after a successful notify-triggered recovery")
	}
	if got := recoverCalls.Load(); got == 0 {
		t.Error("recover hook was never called; NotifyRejected did not trigger the recovery branch")
	}
}

// TestLifecycleManager_NotifyRejectedIgnoresTransientErrors pins that
// NotifyRejected only acts on a Vault-confirmed rejection (IsTokenRejected),
// not on a transient fault a caller might report — an unreachable Vault, a
// connection reset, a context deadline from an unrelated operation. Treating
// those as a verdict on the token would run a recovery pass, and possibly an
// unattended-recovery attempt, over nothing.
func TestLifecycleManager_NotifyRejectedIgnoresTransientErrors(t *testing.T) {
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

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "some-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLifecycleManager(vc, time.Hour, false)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	lm.NotifyRejected(errors.New("connection reset by peer"))
	lm.NotifyRejected(context.DeadlineExceeded)

	// Let the goroutine drain anything queued.
	time.Sleep(300 * time.Millisecond)

	if got := hits.Load(); got != 0 {
		t.Fatalf("LookupSelf called %d times after non-rejection NotifyRejected calls, want 0", got)
	}
}

// TestLifecycleManager_NotifyRejectedCoalesces mirrors
// TestLifecycleManager_ReloadCoalesces: several independent sources hitting
// the same dead token in quick succession (multiple managed SSH forwards
// resolving identity against the same expired token, say) must collapse to a
// single extra recovery pass, not one per report.
//
// With the rate limiter (see TestLifecycleManager_NotifyRejectedRateLimited)
// this is stricter than plain channel-buffer coalescing: none of the 50
// follow-up calls even reach the point of attempting a send, since they all
// land inside the same recoveryInterval window as the first. The test still
// exists under this name because the observable guarantee — a burst produces
// exactly one recovery cycle, not 51 — is unchanged; only the mechanism
// providing it has strengthened.
//
// The server distinguishes the stale token (always 403, and parks on its
// first hit so the goroutine can be caught mid-cycle) from the token the
// recover hook installs (always 200) — routing the assertion through hits on
// LookupSelf rather than through the token denylist, which would otherwise
// suppress the second LookupSelf for the *same* stale token and make the
// count depend on denylist internals this test isn't about.
func TestLifecycleManager_NotifyRejectedCoalesces(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	const recoveredToken = "recovered-token"
	release := make(chan struct{})
	var hits atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			<-release // park only the first request so the goroutine is mid-cycle
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Vault-Token") == recoveredToken {
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

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLifecycleManager(vc, time.Hour, false)
	lm.SetRecover(func(context.Context) error {
		vc.SetToken(recoveredToken)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	// First report: passes the rate limiter (nothing notified yet), parks the
	// goroutine inside checkAndRenew's LookupSelf call against the stale token.
	lm.NotifyRejected(forbiddenErr())
	for hits.Load() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("handler not entered within deadline")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	// 50 more reports while parked. Every one lands inside the same
	// recoveryInterval window as the first and is dropped by the rate
	// limiter before it ever reaches rejectCh.
	for i := 0; i < 50; i++ {
		lm.NotifyRejected(forbiddenErr())
	}

	// Release. The parked LookupSelf returns 403, the recovery branch's
	// tryRecover installs recoveredToken, and runCheckCycle finishes — for
	// hits=1. No queued nudge remains to trigger a second cycle.
	close(release)

	if !waitFor(func() bool { return hits.Load() >= 1 }, 2*time.Second) {
		t.Fatalf("hits never reached 1 (got %d)", hits.Load())
	}
	// Give any spurious extra cycle a moment to show up before the final
	// assertion, mirroring ReloadCoalesces's settle window.
	time.Sleep(100 * time.Millisecond)

	if got := hits.Load(); got != 1 {
		t.Fatalf("LookupSelf called %d times after 51 NotifyRejected calls, want exactly 1; >1 means the rate limiter let a burst through", got)
	}
}

// TestLifecycleManager_NotifyRejectedRateLimited pins the sliding-window rate
// limiter directly, independent of the full Start() goroutine: a report that
// passes is followed by an immediate second report that must be dropped
// (still inside the window), and a third report after the window elapses
// must pass again. This is the mechanism that keeps a misbehaving or
// misconfigured Vault path (e.g. a vault-ca role denied on ssh/sign/<role>
// while the shared token is otherwise fine) from turning into a lookup-self
// storm every time an SSH client retries — see NotifyRejected's doc comment.
func TestLifecycleManager_NotifyRejectedRateLimited(t *testing.T) {
	lm := &LifecycleManager{
		rejectCh:         make(chan struct{}, 1),
		recoveryInterval: 30 * time.Millisecond,
	}

	lm.NotifyRejected(forbiddenErr())
	select {
	case <-lm.rejectCh:
	default:
		t.Fatal("first NotifyRejected did not queue a nudge")
	}

	// Immediately after, still inside the window: must be dropped.
	lm.NotifyRejected(forbiddenErr())
	select {
	case <-lm.rejectCh:
		t.Fatal("second NotifyRejected inside the rate-limit window queued a nudge")
	default:
	}

	// After the window elapses, a fresh report queues again — this is not a
	// permanent lockout, just a sliding window.
	time.Sleep(40 * time.Millisecond)
	lm.NotifyRejected(forbiddenErr())
	select {
	case <-lm.rejectCh:
	default:
		t.Fatal("NotifyRejected after the rate-limit window elapsed did not queue a nudge")
	}
}

// TestLifecycleManager_NotifyRejectedBeforeStartIsBuffered pins that a report
// arriving before Start is not dropped — mirroring Reload's documented
// contract — so a race between wiring the reporter and starting the goroutine
// cannot silently lose the first rejection.
func TestLifecycleManager_NotifyRejectedBeforeStartIsBuffered(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	const recoveredToken = "recovered-token"
	var valid atomic.Value
	valid.Store(recoveredToken)
	ts := newRecoveryVaultServer(t, &valid)

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "stale-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLifecycleManager(vc, time.Hour, false)
	lm.SetRecover(func(context.Context) error {
		vc.SetToken(recoveredToken)
		return nil
	})

	// Notify before Start.
	lm.NotifyRejected(forbiddenErr())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	if !waitFor(func() bool { return vc.Token() == recoveredToken }, 3*time.Second) {
		t.Fatalf("client token = %q after a pre-Start NotifyRejected, want %q", vc.Token(), recoveredToken)
	}
}
