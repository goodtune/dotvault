package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// sdNotifyTimeout bounds the READY/STOPPING notifications. The library's
// SdNotify has no write deadline, and while a dead or absent notify socket
// fails fast at dial, a live-but-unread unixgram peer with a full receive
// buffer (a misconfigured container runtime advertising a wedged notify
// socket — the case the previous hand-rolled implementation defended
// against with a 1s SetWriteDeadline) blocks the write indefinitely. READY
// and STOPPING sit on the synchronous startup/shutdown path, so they get a
// bounded wait here; the abandoned goroutine on timeout is acceptable for
// two calls per process lifetime.
const sdNotifyTimeout = 2 * time.Second

// sdNotify sends one sd_notify state with a bounded wait. Returns nil when
// notification is unsupported (not under systemd), mirroring SdNotify's
// (false, nil) so callers wire it unconditionally.
func sdNotify(state string) error {
	done := make(chan error, 1)
	go func() {
		_, err := daemon.SdNotify(false, state)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(sdNotifyTimeout):
		return fmt.Errorf("sd_notify %s timed out after %v (notify socket wedged?)", state, sdNotifyTimeout)
	}
}

// watchdogLoop kicks the systemd watchdog at half the interval declared by
// WATCHDOG_USEC, returning when ctx is cancelled or the watchdog is not
// enabled for this process. go-systemd's SdWatchdogEnabled owns the
// protocol reading (including the WATCHDOG_PID scoping, so a child that
// inherited the variables never kicks on behalf of a stalled parent); the
// loop itself is ours because the library deliberately ships none — the
// half-interval pacing follows the sd_watchdog_enabled(3) recommendation.
//
// Environment variables are left in place (unsetEnvironment=false):
// NOTIFY_SOCKET must survive for the later READY/STOPPING notifications,
// and the WATCHDOG_* pair is scoped by PID rather than scrubbed. All of it
// is a no-op outside systemd, so the daemon wires this unconditionally.
func watchdogLoop(ctx context.Context) {
	// Without a notify socket every kick would no-op; don't keep a ticker
	// spinning for a WATCHDOG_USEC that has nowhere to report.
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return
	}
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Deliberately unbounded, unlike sdNotify above: if the notify
			// socket wedges, kicks stop, the watchdog window lapses, and
			// systemd restarts the service — which is the watchdog doing
			// its job. A timeout here would let a wedged process keep
			// looking healthy.
			_, _ = daemon.SdNotify(false, daemon.SdNotifyWatchdog)
		}
	}
}
