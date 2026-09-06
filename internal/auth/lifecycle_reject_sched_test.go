package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// TestLifecycleManager_OutOfCycleRunDoesNotAdvanceBackoff pins that only a
// scheduled tick advances the exponential backoff.
//
// The two are counted against different clocks. The doubling is designed to
// happen once per elapsed currentDelay; a rejection report can arrive once per
// rate-limit window. Letting the out-of-cycle path double meant that during an
// outage — a subsystem reporting a 403 while checkAndRenew fails transiently —
// the delay ran from checkInterval to the cap in well under a minute, so the
// fast path made recovery slower than the poll it exists to pre-empt.
func TestLifecycleManager_OutOfCycleRunDoesNotAdvanceBackoff(t *testing.T) {
	lm := &LifecycleManager{maxDelay: 5 * time.Minute}

	if got := lm.backoffFrom(30*time.Second, true); got != time.Minute {
		t.Errorf("scheduled tick: backoffFrom(30s) = %s, want 1m — the backoff must still advance", got)
	}
	if got := lm.backoffFrom(30*time.Second, false); got != 30*time.Second {
		t.Errorf("out-of-cycle run: backoffFrom(30s) = %s, want it left at 30s", got)
	}
	if got := lm.backoffFrom(4*time.Minute, true); got != 5*time.Minute {
		t.Errorf("scheduled tick: backoffFrom(4m) = %s, want the 5m cap", got)
	}
}

// TestLifecycleManager_OutOfCycleRunDoesNotDeferScheduledTick pins the other
// half: a run that pre-empted a tick and did not restore health must not push
// that tick further out. Re-arming a full delay from now would let a steady
// trickle of reports starve the scheduled check indefinitely.
func TestLifecycleManager_OutOfCycleRunDoesNotDeferScheduledTick(t *testing.T) {
	lm := &LifecycleManager{currentDelay: 5 * time.Minute}

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	// The pre-empted tick was due in 50ms; the cycle failed to fix anything.
	deadline := time.Now().Add(50 * time.Millisecond)
	start := time.Now()
	lm.armAfterCycle(timer, false, false, deadline)

	select {
	case <-timer.C:
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("timer fired after %s; the scheduled tick was deferred", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timer did not fire: an out-of-cycle run pushed the scheduled tick out by its own full delay")
	}
}

// TestLifecycleManager_OutOfCycleRunKeepsLongerDelayOnceHealthy is the
// exemption. A run that restored health has nothing left to be urgent about,
// so returning to checkInterval is right even though it is longer than what
// remained of the tick it pre-empted.
func TestLifecycleManager_OutOfCycleRunKeepsLongerDelayOnceHealthy(t *testing.T) {
	lm := &LifecycleManager{currentDelay: 5 * time.Minute}

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	lm.armAfterCycle(timer, false, true, time.Now().Add(50*time.Millisecond))

	select {
	case <-timer.C:
		t.Fatal("timer fired on the short remaining deadline; a healthy cycle should have armed its full delay")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestLifecycleManager_ArmAfterCycleReportsWhatItArmed pins that the arming
// helpers return the delay they actually used, which is what lets the Start
// loop track the next tick instead of guessing.
//
// The clamp means the armed delay is not always currentDelay, so a caller that
// re-derived it from currentDelay drifted: after a healthy out-of-cycle run it
// would leave the tracked deadline earlier than the timer, and the next report
// would then clamp to an already-past deadline and fire a spurious immediate
// check.
func TestLifecycleManager_ArmAfterCycleReportsWhatItArmed(t *testing.T) {
	lm := &LifecycleManager{currentDelay: 5 * time.Minute}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}

	// Unhealthy out-of-cycle run: armed the short remainder, not currentDelay.
	remaining := 50 * time.Millisecond
	got := lm.armAfterCycle(timer, false, false, time.Now().Add(remaining))
	if got >= lm.currentDelay {
		t.Errorf("armAfterCycle returned %s; want the clamped remainder, well under currentDelay (%s)", got, lm.currentDelay)
	}

	// Healthy out-of-cycle run: armed the full delay.
	if got := lm.armAfterCycle(timer, false, true, time.Now().Add(remaining)); got != lm.currentDelay {
		t.Errorf("armAfterCycle(healthy) returned %s, want currentDelay %s", got, lm.currentDelay)
	}
}

// TestLifecycleManager_DroppedReportReleasesRateLimitWindow pins that only a
// report which actually queues a nudge spends the window. A report dropped
// because one is already queued has done no work, so burning the full interval
// on it would let a redundant report suppress the next genuine one.
func TestLifecycleManager_DroppedReportReleasesRateLimitWindow(t *testing.T) {
	lm := &LifecycleManager{
		rejectCh:         make(chan struct{}, 1),
		recoveryInterval: time.Minute, // long enough that only a release can explain a second nudge
	}

	// Occupy the buffer so the next report has nowhere to go.
	lm.rejectCh <- struct{}{}
	lm.NotifyRejected(forbiddenErr())

	// The lifecycle goroutine consumes the queued nudge.
	<-lm.rejectCh

	// A fresh report must still be accepted: the dropped one released the
	// window rather than holding it for the full minute.
	lm.NotifyRejected(forbiddenErr())
	select {
	case <-lm.rejectCh:
	default:
		t.Fatal("a report dropped on a full channel consumed the rate-limit window")
	}
}

// TestLifecycleManager_SuccessfulCycleDrainsQueuedReport pins that a report
// queued while a cycle was running is discarded when that cycle ends with a
// working token. The reporting subsystem keeps failing for as long as the gate
// is held, so without this every successful recovery was followed by an
// immediate out-of-cycle re-check of the token it had just fixed.
func TestLifecycleManager_SuccessfulCycleDrainsQueuedReport(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	const good = "good-token"
	var valid atomic.Value
	valid.Store(good)
	ts := newRecoveryVaultServer(t, &valid)

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: good})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	lm := NewLifecycleManager(vc, time.Minute, true)

	// A report lands while the cycle is in flight.
	lm.rejectCh <- struct{}{}

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		<-timer.C
	}
	errCh := make(chan error, 1)
	lm.runCheckCycle(context.Background(), errCh, timer, true, time.Time{})

	select {
	case <-lm.rejectCh:
		t.Error("a report queued during a cycle that ended healthy was left to trigger a redundant re-check")
	default:
	}
}

// TestLifecycleManager_OutOfCycleRecoveryDoesNotReCheck drives the whole path
// through Start — NotifyRejected, the rejectCh branch, an out-of-cycle
// runCheckCycle that recovers, and the nextTickAt threading behind it — rather
// than the helpers in isolation.
//
// It covers the drain on an early-return success path, which the scheduled
// case cannot reach, and pins the behaviour that motivated it: the reporting
// subsystem keeps failing for as long as the gate is held, so a report lands
// during the very cycle that fixes the token. Without the drain, every
// successful recovery was followed by an immediate redundant re-check.
func TestLifecycleManager_OutOfCycleRecoveryDoesNotReCheck(t *testing.T) {
	t.Setenv("DOTVAULT_TOKEN", "")

	const recovered = "recovered-token"
	var valid atomic.Value
	valid.Store(recovered)

	var lookups atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-Vault-Token") == valid.Load().(string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"ttl": json.Number("3600"), "creation_ttl": json.Number("3600"), "renewable": true,
			}})
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

	// A long checkInterval keeps the scheduled tick out of the measurement:
	// anything that runs here was driven by the report, not the clock.
	lm := NewLifecycleManager(vc, time.Hour, false)
	// A short rate-limit window models the case that actually produces the
	// queued report: a real recovery (a PKI sign plus a Vault login, bounded
	// at 20s) outlasts the reporter's window, so its next failure does queue.
	// Left at the 10s default the in-cycle report below is simply rate-limited
	// away and the test proves nothing.
	lm.recoveryInterval = time.Millisecond
	lm.SetRecover(func(context.Context) error {
		// Stand in for the reporting subsystem still failing while the gate is
		// held — this is the report the drain exists to discard.
		time.Sleep(5 * time.Millisecond) // outlast the window, as a real recovery does
		lm.NotifyRejected(forbiddenErr())
		vc.SetToken(recovered)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errCh := lm.Start(ctx)
	go func() {
		for range errCh {
		}
	}()

	lm.NotifyRejected(forbiddenErr())
	if !waitFor(func() bool { return vc.Token() == recovered }, 5*time.Second) {
		t.Fatalf("token = %q, want %q — the reported rejection did not drive a recovery", vc.Token(), recovered)
	}

	// Let any queued nudge that survived the drain be acted on.
	// Assert on the total rather than sampling after the token flips: the
	// redundant cycle races that flip, so a delta measured from there passes
	// whenever it happens to run first. One lookup-self is the whole story —
	// the cycle the report drove. A second means the report queued during it
	// survived and drove another against the token that cycle had just fixed.
	time.Sleep(500 * time.Millisecond)
	if got := lookups.Load(); got != 1 {
		t.Errorf("%d lookup-self calls, want 1; a report queued during the recovery was left to trigger a redundant re-check", got)
	}
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true after a successful notify-driven recovery")
	}
}
