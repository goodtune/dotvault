// Package tray provides an optional Windows system-tray icon for the
// daemon. On non-Windows platforms Run is a no-op that simply blocks
// until ctx is cancelled, so callers can wire it unconditionally.
package tray

// Config bundles the tray menu configuration.
//
// WebURL is the URL the "View" menu entry should open. If empty, the
// View entry is omitted entirely. OnExit is invoked when the user picks
// the Exit menu entry; it should signal the daemon to shut down (e.g.
// by cancelling the daemon's context). OnReload is invoked when the user
// picks the "Reload config" menu entry; if nil, the entry is omitted.
// Windows never delivers SIGHUP, so this is the reload affordance for
// dotvaultw (and the console daemon) — the daemon wires it to the same
// token re-read + config-refresh pass its SIGHUP handler runs elsewhere.
type Config struct {
	Tooltip  string
	WebURL   string
	OnExit   func()
	OnReload func()
}
