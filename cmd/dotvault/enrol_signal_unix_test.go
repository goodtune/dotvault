//go:build unix

package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestReadSingleKey_SurvivesSignalDuringEscapeTail pins the EINTR retry in
// waitForMoreInput. It is a regression test for a real terminal bug, not just
// a CI flake: poll(2) returns EINTR whenever a signal lands mid-wait, and the
// Go runtime delivers SIGURG constantly to preempt goroutines, so on a busy
// process the interruption is routine rather than exotic. Treating it as "no
// input" made drainEscapeTail abandon a half-arrived arrow sequence, so the
// keystroke either vanished (a two-byte prefix classifies as keyNone) or quit
// the picker (a lone ESC classifies as keyQuit).
//
// The signal storm here reproduces deterministically what a loaded machine
// produces by chance. Without the retry this fails on the first iteration.
//
// It lives in a unix-tagged file rather than carrying a runtime GOOS skip
// because syscall.Kill does not exist on Windows at all, so a skip would still
// fail to compile there — invisible to a Linux-only CI, exactly the class of
// breakage that has bitten this package before.
func TestReadSingleKey_SurvivesSignalDuringEscapeTail(t *testing.T) {
	for i := 0; i < 40; i++ {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}

		done := make(chan struct{})
		go func() {
			// SIGURG is what the runtime itself uses for preemption, so it is
			// both realistic and harmless to raise here.
			for {
				select {
				case <-done:
					return
				default:
					_ = syscall.Kill(syscall.Getpid(), syscall.SIGURG)
					time.Sleep(200 * time.Microsecond)
				}
			}
		}()

		go func() {
			defer w.Close()
			for _, b := range []byte{0x1b, '[', 'B'} {
				_, _ = w.Write([]byte{b})
				time.Sleep(2 * time.Millisecond)
			}
		}()

		got, err := readSingleKey(context.Background(), r)
		close(done)
		_ = r.Close()
		if err != nil {
			t.Fatalf("readSingleKey: %v", err)
		}
		if got != keyDown {
			t.Fatalf("iteration %d: arrow interrupted by a signal = %v, want keyDown "+
				"(a signal during the escape tail must not drop the keystroke)", i, got)
		}
	}
}

// TestPollTimeoutMillisNeverTruncatesToZero pins the conversion that keeps a
// positive budget from becoming a non-blocking poll, and the clamp that keeps
// a negative one from becoming an infinite wait.
//
// It is a pure function precisely so both can be asserted without racing a
// clock. Observing the truncation through waitForMoreInput would mean
// arranging a sub-millisecond remainder and a byte arriving inside it, which
// is the probabilistic shape that produced the flake this file exists to fix.
func TestPollTimeoutMillisNeverTruncatesToZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want int
	}{
		// The case review caught. drainEscapeTail's remainder decrements
		// across its loop, so a tail byte landing late in the 50ms budget
		// leaves under a millisecond; truncation would pass 0, which poll
		// treats as "check and return".
		{"sub-millisecond floors up", 500 * time.Microsecond, 1},
		{"one nanosecond floors up", time.Nanosecond, 1},
		// Non-positive is unreachable while both callers guard, but the clamp
		// is what makes it safe if one ever stops. A negative timeout tells
		// poll to block forever, so == 0 would be the more dangerous spelling
		// and these two cases are what distinguish it from < 1.
		{"zero clamps", 0, 1},
		{"negative clamps rather than blocking forever", -5 * time.Millisecond, 1},
		// Above a millisecond it floors, and must not ceil: a truncated wait
		// still blocks, and the caller's loop comes round again.
		{"floors within a millisecond", 7500 * time.Microsecond, 7},
		{"whole milliseconds pass through", 50 * time.Millisecond, 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pollTimeoutMillis(tc.in); got != tc.want {
				t.Errorf("pollTimeoutMillis(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
