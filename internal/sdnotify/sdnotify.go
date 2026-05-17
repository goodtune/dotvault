// Package sdnotify implements the small subset of the systemd
// sd_notify(3) protocol the daemon needs (READY=1, STOPPING=1,
// WATCHDOG=1) without pulling in a dependency on go-systemd.
//
// On non-Linux platforms every function is a no-op (see
// sdnotify_other.go). On Linux the functions look at $NOTIFY_SOCKET;
// when it's empty (i.e. we're not under systemd) every call is also a
// no-op. This means callers can wire the hooks unconditionally — no
// branching on OS or service-manager presence required.
//
// Function-level docs live with the build-tag-specific declarations
// in sdnotify_linux.go and sdnotify_other.go so `go doc` picks them
// up on the matching platform.
package sdnotify
