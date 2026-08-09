package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestBackoffDelayAppliesAuthFailureFloor and its host-key sibling pin the
// backoff-floor rule that fail() relies on: an authentication or host-key
// failure never retries faster than AuthFailureFloor, even fresh off
// NewBackoff's 500ms base delay.
func TestBackoffDelayAppliesAuthFailureFloor(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.backoff.rnd = func() float64 { return 0.5 } // midpoint: no jitter jitter

	if d := mr.backoffDelay(ClassAuth); d < AuthFailureFloor {
		t.Errorf("backoffDelay(ClassAuth) = %s, want >= %s", d, AuthFailureFloor)
	}
}

func TestBackoffDelayAppliesHostKeyFloor(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.backoff.rnd = func() float64 { return 0.5 }

	if d := mr.backoffDelay(ClassHostKey); d < AuthFailureFloor {
		t.Errorf("backoffDelay(ClassHostKey) = %s, want >= %s", d, AuthFailureFloor)
	}
}

// TestBackoffDelayNoFloorForOtherClasses guards the negative case: an
// ordinary transport failure must not be dragged up to the multi-minute auth
// floor, or a flaky-but-otherwise-healthy remote would reconnect far slower
// than it needs to.
func TestBackoffDelayNoFloorForOtherClasses(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.backoff.rnd = func() float64 { return 0.5 }

	if d := mr.backoffDelay(ClassRefused); d >= AuthFailureFloor {
		t.Errorf("backoffDelay(ClassRefused) = %s, want well under the %s auth floor", d, AuthFailureFloor)
	}
}

// TestFailSetsStateForClass drives fail() directly (not just backoffDelay)
// to pin the class→state mapping it applies before sleeping. The context
// passed in is pre-cancelled so fail's call to sleep() returns immediately
// regardless of the computed delay — otherwise an auth-class case would
// block for the real 5-minute AuthFailureFloor.
func TestFailSetsStateForClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want State
	}{
		{"auth", fmt.Errorf("rejected: %w", ErrAuth), StateAuthError},
		{"host key unknown", fmt.Errorf("unknown: %w", ErrHostKeyUnknown), StateHostKeyError},
		{"other", errors.New("connection reset"), StateOffline},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mr := newManagedRemote(remote("foo.example.com"), Deps{})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			mr.fail(ctx, c.err)

			got := mr.status("")
			if got.State != string(c.want) {
				t.Errorf("state = %q, want %q", got.State, c.want)
			}
			if got.LastError == "" {
				t.Error("LastError not recorded")
			}
		})
	}
}

// TestArmStableResetResetsBackoffAfterThreshold and its early-stop sibling
// cover the stable-connection-resets-backoff behaviour that serveConnected
// relies on armStableReset for, using a short injected threshold instead of
// the real 60s StableConnectionThreshold.
func TestArmStableResetResetsBackoffAfterThreshold(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.backoff.rnd = func() float64 { return 0.5 }
	for i := 0; i < 5; i++ {
		mr.backoff.Next()
	}

	stop := mr.armStableReset(context.Background(), 20*time.Millisecond)
	// Poll for the reset rather than sleeping a fixed multiple of the
	// threshold: a loaded CI box can delay a 20ms timer well past any margin
	// worth hard-coding, and the poll is both faster in the ordinary case and
	// unflakeable in the slow one.
	waitForBackoffReset(t, mr.backoff)
	stop()

	if d := mr.backoff.Next(); d != 500*time.Millisecond {
		t.Errorf("backoff not reset after the stable threshold elapsed: Next() = %s, want 500ms", d)
	}
}

func TestArmStableResetDoesNothingWhenStoppedFirst(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})
	mr.backoff.rnd = func() float64 { return 0.5 }
	for i := 0; i < 5; i++ {
		mr.backoff.Next()
	}

	stop := mr.armStableReset(context.Background(), 1*time.Hour)
	stop()
	time.Sleep(20 * time.Millisecond) // let a wrongly-firing goroutine have a chance to misbehave

	if d := mr.backoff.Next(); d == 500*time.Millisecond {
		t.Error("backoff was reset despite armStableReset being stopped well before its threshold")
	}
}

// TestRunFailsClosedOnIncompleteDeps guards the nil-Deps-func defence in
// run(): a Manager is always constructed with a fully-populated Deps in
// production, but several tests in this package (and a plausible future
// wiring mistake) construct one with Deps{}. run must report a failed
// connection attempt rather than let a nil func call panic the goroutine.
func TestRunFailsClosedOnIncompleteDeps(t *testing.T) {
	mr := newManagedRemote(remote("foo.example.com"), Deps{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mr.run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mr.status("").LastError != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	got := mr.status("")
	if got.LastError == "" {
		t.Fatal("run() with an incomplete Deps never recorded a failure; want it to fail the attempt instead of panicking")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not exit after ctx cancellation")
	}
}

// waitForBackoffReset blocks until b's schedule has been returned to its base
// delay, or the deadline passes. It reads the attempt counter directly (under
// b's own mutex) because the public observation — Next() — advances the
// schedule, so polling through it would destroy the very state the caller is
// about to assert on.
func waitForBackoffReset(t *testing.T, b *Backoff) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		n := b.n
		b.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("backoff was not reset after the stable-connection threshold elapsed")
}
