// Package tray provides an optional Windows system-tray icon for the
// daemon. On non-Windows platforms Run is a no-op that simply blocks
// until ctx is cancelled, so callers can wire it unconditionally.
package tray

// Config bundles the tray menu configuration.
//
// WebURL is the URL the "View" menu entry should open. If empty, the
// View entry is omitted entirely. OnExit is invoked when the user picks
// the Exit menu entry; it should signal the daemon to shut down (e.g.
// by cancelling the daemon's context).
type Config struct {
	Tooltip string
	WebURL  string
	OnExit  func()
}
