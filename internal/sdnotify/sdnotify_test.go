package sdnotify

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
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

// TestNotifyDeliversToFilesystemSocket spins up a unixgram listener at
// a real path, points NOTIFY_SOCKET at it, and verifies Ready() writes
// the expected payload. Linux-only — the Linux build of notify is the
// one being exercised, and the unixgram + abstract-socket plumbing
// only exists there.
func TestNotifyDeliversToFilesystemSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sd_notify is Linux-only")
	}
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	ln, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	defer ln.Close()

	t.Setenv("NOTIFY_SOCKET", socketPath)
	if err := Ready(); err != nil {
		t.Fatalf("Ready(): %v", err)
	}

	buf := make([]byte, 64)
	if err := ln.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := ln.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("payload = %q, want READY=1", got)
	}
}

// TestNotifyDeliversToAbstractSocket verifies the '@'→NUL translation
// that sd_notify requires for abstract sockets — a footgun under some
// container runtimes if the leading '@' is passed through verbatim,
// because the kernel would then look for a filesystem path starting
// with '@' rather than the abstract namespace.
func TestNotifyDeliversToAbstractSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sd_notify is Linux-only")
	}
	// Abstract namespace is "\x00" + name; we advertise the same with
	// "@" + name and expect notify() to translate.
	name := "dotvault-test-" + t.Name()
	addr := &net.UnixAddr{Name: "\x00" + name, Net: "unixgram"}
	ln, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen abstract unixgram: %v", err)
	}
	defer ln.Close()

	t.Setenv("NOTIFY_SOCKET", "@"+name)
	if err := Ready(); err != nil {
		t.Fatalf("Ready(): %v", err)
	}

	buf := make([]byte, 64)
	if err := ln.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := ln.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("payload = %q, want READY=1", got)
	}
}

// TestWatchdogLoopHonoursWATCHDOG_PID verifies that the loop exits
// immediately when WATCHDOG_PID is set to a PID that isn't ours.
// This protects against a forked child process (or a misconfigured
// supervisor) kicking the watchdog on behalf of someone else.
func TestWatchdogLoopHonoursWATCHDOG_PID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sd_notify is Linux-only")
	}
	t.Setenv("NOTIFY_SOCKET", "/tmp/fake-socket")
	t.Setenv("WATCHDOG_USEC", "1000000")
	// PID 1 is almost certainly not us.
	t.Setenv("WATCHDOG_PID", "1")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		WatchdogLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good — returned without waiting for the ticker
	case <-time.After(100 * time.Millisecond):
		t.Fatal("WatchdogLoop did not exit when WATCHDOG_PID mismatched current PID")
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
