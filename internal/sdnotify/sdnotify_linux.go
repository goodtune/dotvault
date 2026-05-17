//go:build linux

package sdnotify

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// notify writes a single sd_notify message to $NOTIFY_SOCKET. Returns
// nil when the env var is unset so the daemon doesn't error on a
// non-systemd boot.
//
// systemd advertises two socket forms: a filesystem path (the
// common case under user / system services) and an abstract socket
// when NOTIFY_SOCKET starts with '@'. The abstract form needs the
// leading '@' translated to a leading NUL byte before it can be
// passed to the kernel — without this rewrite, READY=1 is silently
// dropped under setups (including some container runtimes) that
// expose the notify socket abstractly.
func notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{
		Name: socket,
		Net:  "unixgram",
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// Ready signals READY=1 to systemd.
func Ready() error {
	return notify("READY=1")
}

// Stopping signals STOPPING=1 to systemd.
func Stopping() error {
	return notify("STOPPING=1")
}

// WatchdogLoop kicks WATCHDOG=1 at half the interval declared by
// WATCHDOG_USEC. Returns when ctx is cancelled, when WATCHDOG_USEC is
// unset/unparseable, when NOTIFY_SOCKET is unset (in which case every
// kick would no-op anyway and the spinning goroutine has no purpose),
// or when WATCHDOG_PID is set and doesn't match the current PID.
//
// systemd uses WATCHDOG_PID to scope the watchdog to a specific
// process in a multi-process service (e.g. a supervisor that forks
// workers). Without the PID check, a child process that inherits
// the env vars would also try to kick the watchdog, which is at
// best wasted IPC and at worst masks a stalled main process.
//
// The half-interval pacing matches the systemd manual recommendation.
func WatchdogLoop(ctx context.Context) {
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return
	}
	if pidStr := os.Getenv("WATCHDOG_PID"); pidStr != "" {
		wantPID, err := strconv.Atoi(pidStr)
		if err != nil || wantPID != os.Getpid() {
			return
		}
	}
	raw := os.Getenv("WATCHDOG_USEC")
	if raw == "" {
		return
	}
	usec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || usec <= 0 {
		return
	}
	// systemd hands out the full window — kick at half to stay well
	// inside it under load.
	interval := time.Duration(usec) * time.Microsecond / 2
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = notify("WATCHDOG=1")
		}
	}
}
