// Package sdnotify implements the small subset of the systemd
// sd_notify(3) protocol the daemon needs (READY=1, STOPPING=1,
// WATCHDOG=1) without pulling in a dependency on go-systemd.
//
// On non-Linux platforms every function is a no-op (see
// sdnotify_other.go). On Linux the functions look at $NOTIFY_SOCKET;
// when it's empty (i.e. we're not under systemd) every call is also a
// no-op. This means callers can wire the hooks unconditionally — no
// branching on OS or service-manager presence required.
package sdnotify

// Ready signals systemd that the daemon is fully initialised and ready
// to handle work. Equivalent to sd_notify(0, "READY=1"). Safe to call
// outside systemd / on non-Linux — returns nil silently.
//
// The implementation lives in sdnotify_linux.go.

// Stopping signals systemd that the daemon is shutting down. The
// systemd manual recommends sending this before starting teardown so
// the unit state reflects the shutdown sequence rather than appearing
// to crash.

// WatchdogLoop kicks the systemd watchdog at half the interval
// declared by WATCHDOG_USEC, returning when ctx is cancelled. It is a
// no-op when WATCHDOG_USEC is unset or zero, and outside systemd /
// on non-Linux.
