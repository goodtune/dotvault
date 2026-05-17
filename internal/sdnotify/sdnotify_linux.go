//go:build linux

package sdnotify

import (
	"context"
	"net"
	"os"
	"strconv"
	"time"
)

// notify writes a single sd_notify message to $NOTIFY_SOCKET. Returns
// nil when the env var is unset so the daemon doesn't error on a
// non-systemd boot.
func notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
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
// WATCHDOG_USEC. Returns when ctx is cancelled or when the env var is
// unset / unparseable. The half-interval pacing matches the systemd
// manual recommendation.
func WatchdogLoop(ctx context.Context) {
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
