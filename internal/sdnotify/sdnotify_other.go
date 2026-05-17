//go:build !linux

package sdnotify

import "context"

// Ready is a no-op on non-Linux platforms.
func Ready() error { return nil }

// Stopping is a no-op on non-Linux platforms.
func Stopping() error { return nil }

// WatchdogLoop is a no-op on non-Linux platforms.
func WatchdogLoop(ctx context.Context) {}
