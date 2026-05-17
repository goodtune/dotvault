//go:build !linux

package sdnotify

import "context"

// Ready signals systemd that the daemon is fully initialised and
// ready to handle work. Equivalent to sd_notify(0, "READY=1") on
// Linux; a no-op on non-Linux platforms so the daemon's startup path
// can call it unconditionally.
func Ready() error { return nil }

// Stopping signals systemd that the daemon is shutting down. The
// systemd manual recommends sending this before starting teardown so
// the unit state reflects the shutdown sequence rather than appearing
// to crash. A no-op on non-Linux platforms.
func Stopping() error { return nil }

// WatchdogLoop kicks the systemd watchdog at half the interval
// declared by WATCHDOG_USEC, returning when ctx is cancelled. A
// no-op on non-Linux platforms so the daemon can wire it
// unconditionally.
func WatchdogLoop(ctx context.Context) {}
