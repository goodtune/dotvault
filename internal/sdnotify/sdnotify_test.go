package sdnotify

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	// os.Getpid()+1 is provably not us. Hard-coding "1" would
	// false-pass in containers (Docker default PID namespace,
	// many CI runners) where the test process *is* PID 1.
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()+1))

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

// TestWatchdogLoopExitsOnCancel covers two paths: the fast no-op
// return when systemd env vars are unset, and the actual ticker
// teardown when they are. The second case is the one the daemon
// shutdown sequence actually hits — without an exit on ctx
// cancellation the sync loop's defer chain would hang waiting on
// a stuck goroutine.
func TestWatchdogLoopExitsOnCancel(t *testing.T) {
	t.Run("FastReturnWithoutSystemd", func(t *testing.T) {
		// NOTIFY_SOCKET unset → WatchdogLoop returns immediately.
		t.Setenv("NOTIFY_SOCKET", "")
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
			t.Fatal("WatchdogLoop did not exit on context cancellation (fast-return path)")
		}
	})

	t.Run("TickerExitsOnCancel", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("sd_notify is Linux-only")
		}
		// Real unixgram socket so notify() succeeds; tiny
		// WATCHDOG_USEC so the ticker is genuinely running by the
		// time cancel fires.
		dir := t.TempDir()
		socketPath := filepath.Join(dir, "notify.sock")
		addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
		ln, err := net.ListenUnixgram("unixgram", addr)
		if err != nil {
			t.Fatalf("listen unixgram: %v", err)
		}
		defer ln.Close()
		t.Setenv("NOTIFY_SOCKET", socketPath)
		t.Setenv("WATCHDOG_USEC", "200000") // 200ms → tick every 100ms

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			WatchdogLoop(ctx)
			close(done)
		}()
		// Wait for the actual ticker to fire by reading the first
		// WATCHDOG=1 datagram. A bare time.Sleep here was a flake
		// risk on loaded CI runners: if the goroutine hadn't been
		// scheduled within the sleep window, cancel() would fire
		// while WatchdogLoop was still in its pre-ticker setup,
		// which has its own early-return path — the test would
		// then pass vacuously without exercising the active-
		// ticker cancellation. A successful read proves the
		// ticker fired and the goroutine is parked in its
		// select.
		buf := make([]byte, 32)
		if err := ln.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, _, err := ln.ReadFrom(buf); err != nil {
			t.Fatalf("waiting for first watchdog kick: %v", err)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("WatchdogLoop did not exit on context cancellation (active-ticker path)")
		}
	})
}
