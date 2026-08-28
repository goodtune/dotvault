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
