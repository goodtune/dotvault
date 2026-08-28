package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// TestLifecycleManager_ReauthGateHeldDuringSuccessfulRecovery pins the gate
// over the window a *successful* unattended recovery occupies.
//
// The gate used to be engaged only by signalReauth, which the Start loop
// reaches solely after recovery has already failed — so the common case, where
// recovery works, ran with the gate down from start to finish. That window is
// not instantaneous: the hook mints a certificate and exchanges it for a token
// over the network, and until its last step installs the result the shared
// client still carries the token Vault just rejected. A consumer checking the
// gate (the SSH agent before signing or listing, the web UI before handing out
// the token) saw nothing to wait for and used the dead token instead.
//
// The two halves are equally load-bearing, so both are asserted: the gate is
// up for the whole hook, and OnReauth never fires. Engaging the gate by
// signalling re-auth would satisfy the first and break the second — in web
// mode it clears in-memory auth state and bounces the browser to a login
// screen, for an outage the daemon is in the middle of healing by itself.
func TestLifecycleManager_ReauthGateHeldDuringSuccessfulRecovery(t *testing.T) {
	// Hermetic: DOTVAULT_TOKEN must not become a surprise reload candidate on
	// a developer machine that exports one.
	t.Setenv("DOTVAULT_TOKEN", "")

	const (
		staleToken     = "stale-token"
		recoveredToken = "recovered-token"
	)

	var valid atomic.Value
	valid.Store(recoveredToken)
	ts := newRecoveryVaultServer(t, &valid)

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: staleToken})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	lm := NewLifecycleManager(vc, 50*time.Millisecond, false)

	var reauths atomic.Int64
	lm.SetOnReauth(func() { reauths.Add(1) })

	// The hook stands in for a certificate login: it blocks partway through,
	// which is where a real one sits waiting on a PKI sign and a cert login,
	// and only then installs the new token. Blocking exactly once keeps the
	// test deterministic if the loop ever calls it again.
	var once sync.Once
	entered := make(chan struct{})
	release := make(chan struct{})
	lm.SetRecover(func(ctx context.Context) error {
		once.Do(func() {
			close(entered)
			<-release
		})
		vc.SetToken(recoveredToken)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery hook was never called")
	}

	// Mid-recovery: this is the concurrent consumer's view of the world.
	if got := vc.Token(); got != staleToken {
		t.Fatalf("client token mid-recovery = %q, want the stale one (%q) — "+
			"the test no longer covers the window it was written for", got, staleToken)
	}
	if !lm.NeedsReauth() {
		t.Error("NeedsReauth() is false while the token is being replaced; a " +
			"concurrent Sign would present the token Vault already rejected")
	}
	if n := reauths.Load(); n != 0 {
		t.Errorf("OnReauth fired %d times during a recovery that is about to "+
			"succeed; the gate must be held without raising the signal", n)
	}

	close(release)

	if !waitFor(func() bool { return vc.Token() == recoveredToken && !lm.NeedsReauth() }, 5*time.Second) {
		t.Fatalf("after recovery: token=%q NeedsReauth=%v, want %q/false",
			vc.Token(), lm.NeedsReauth(), recoveredToken)
	}
	if n := reauths.Load(); n != 0 {
		t.Errorf("OnReauth fired %d times across a successful recovery, want 0", n)
	}
}

// TestLifecycleManager_ReauthGateIsBounded pins that the gate cannot be held
// open-endedly by a slow replacement.
//
// An unbounded gate is worse than none: a consumer waits on it, exhausts its
// own budget (the SSH agent allows 30s) and fails anyway, having spent the time
// as well. The window that made this reachable is tryReload's, whose LookupSelf
// calls otherwise inherit the Vault SDK's own ~60s default with retries — and
// it is held even in the renewal-failure branch, where the token being replaced
// still works, so a slow Vault could gate a healthy daemon against itself.
func TestLifecycleManager_ReauthGateIsBounded(t *testing.T) {
	lm := &LifecycleManager{}

	start := time.Now()
	got := lm.withTokenInFlux(context.Background(), 50*time.Millisecond, func(ctx context.Context) bool {
		// Stand in for a Vault call that never answers: honour the context, as
		// every real step must, and report failure when it expires.
		<-ctx.Done()
		return false
	})
	elapsed := time.Since(start)

	if got {
		t.Error("withTokenInFlux reported success for a step that timed out")
	}
	if elapsed > 5*time.Second {
		t.Errorf("step ran for %s past its 50ms budget; the gate is unbounded", elapsed)
	}
	if lm.NeedsReauth() {
		t.Error("the gate is still held after the step returned")
	}
}

// TestLifecycleManager_SignalIsNarrowerThanGate pins the distinction the two
// flags exist to draw, because collapsing them is the easy mistake in both
// directions.
//
// A caller asking "does this daemon need someone to find it a token" must not
// see a reload that is already under way — cmd/dotvault's peer-socket watcher
// reads it exactly that way, and answering yes there queues a second reload
// that would demote a healthy token to a borrowed one. A caller asking "is it
// safe to use the client" must see it.
func TestLifecycleManager_SignalIsNarrowerThanGate(t *testing.T) {
	lm := &LifecycleManager{}

	var gateDuringStep, signalDuringStep bool
	lm.withTokenInFlux(context.Background(), time.Second, func(context.Context) bool {
		gateDuringStep, signalDuringStep = lm.NeedsReauth(), lm.ReauthSignalled()
		return true
	})

	if !gateDuringStep {
		t.Error("NeedsReauth() was false mid-replacement; the gate must be held")
	}
	if signalDuringStep {
		t.Error("ReauthSignalled() was true mid-replacement; a replacement " +
			"already under way is not a daemon awaiting rescue")
	}
}
