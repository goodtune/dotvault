//go:build !(windows || darwin)

package daemon

import "log/slog"

// StartTray is a no-op on platforms without system tray support.
func StartTray(cfg TrayConfig) {
	slog.Debug("system tray not available on this platform")
}

// StopTray is a no-op on platforms without system tray support.
func StopTray() {}
