//go:build darwin

package daemon

import "log/slog"

// StartTray logs a notice on macOS. Native menu bar integration requires a
// CGo-enabled build with Cocoa bindings, which is not included in the default
// CGO_ENABLED=0 cross-compilation. The daemon still runs correctly without it.
func StartTray(cfg TrayConfig) {
	slog.Info("daemon running — menu bar icon not available in this build; open the web UI manually", "url", cfg.URL)
}

// StopTray is a no-op on macOS builds without native tray support.
func StopTray() {}
