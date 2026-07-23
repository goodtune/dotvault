package web

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestGuardedLaunch_Success(t *testing.T) {
	var mu sync.Mutex
	timedOut, err := guardedLaunch(&mu, time.Second, func() error { return nil })
	if timedOut || err != nil {
		t.Fatalf("got (timedOut=%v, err=%v), want (false, nil)", timedOut, err)
	}
	// Gate must be released for the next launch.
	if !mu.TryLock() {
		t.Error("gate still held after a successful launch")
	}
}

func TestGuardedLaunch_Error(t *testing.T) {
	var mu sync.Mutex
	want := errors.New("boom")
	timedOut, err := guardedLaunch(&mu, time.Second, func() error { return want })
	if timedOut || !errors.Is(err, want) {
		t.Fatalf("got (timedOut=%v, err=%v), want (false, %v)", timedOut, err, want)
	}
}

func TestGuardedLaunch_PanicRecovered(t *testing.T) {
	var mu sync.Mutex
	timedOut, err := guardedLaunch(&mu, time.Second, func() error { panic("kaboom") })
	if timedOut || err == nil {
		t.Fatalf("got (timedOut=%v, err=%v), want (false, non-nil)", timedOut, err)
	}
	if !mu.TryLock() {
		t.Error("gate still held after a panicking launch")
	}
}

func TestGuardedLaunch_Busy(t *testing.T) {
	var mu sync.Mutex
	mu.Lock() // simulate an in-flight launch holding the gate
	timedOut, err := guardedLaunch(&mu, time.Second, func() error { return nil })
	if timedOut || !errors.Is(err, errLauncherBusy) {
		t.Fatalf("got (timedOut=%v, err=%v), want (false, errLauncherBusy)", timedOut, err)
	}
}

func TestGuardedLaunch_Timeout(t *testing.T) {
	var mu sync.Mutex
	release := make(chan struct{})
	timedOut, err := guardedLaunch(&mu, 20*time.Millisecond, func() error {
		<-release
		return nil
	})
	if !timedOut || err != nil {
		t.Fatalf("got (timedOut=%v, err=%v), want (true, nil)", timedOut, err)
	}
	// The gate is still held by the abandoned launch until it returns.
	if mu.TryLock() {
		t.Error("gate should stay held while the abandoned launch runs")
	}
	// Once the launch finishes, the gate frees up.
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mu.TryLock() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("gate not released after the abandoned launch returned")
}
