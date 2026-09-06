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
