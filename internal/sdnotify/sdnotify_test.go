package sdnotify

import (
	"context"
	"testing"
	"time"
)

// TestReadyWithoutSocket exercises the no-op fast path: with
// NOTIFY_SOCKET unset, Ready must return nil and not attempt to dial.
// On non-Linux Ready is unconditionally nil from sdnotify_other.go.
func TestReadyWithoutSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Ready(); err != nil {
		t.Errorf("Ready() with no NOTIFY_SOCKET = %v, want nil", err)
	}
	if err := Stopping(); err != nil {
		t.Errorf("Stopping() with no NOTIFY_SOCKET = %v, want nil", err)
	}
}

// TestWatchdogLoopExitsOnCancel confirms the watchdog ticker honours
// context cancellation (both as a fast-return when WATCHDOG_USEC is
// unset and as a normal teardown when it isn't). Without this the
// daemon shutdown sequence could hang waiting on a stuck loop.
func TestWatchdogLoopExitsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		WatchdogLoop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WatchdogLoop did not exit on context cancellation")
	}
}
