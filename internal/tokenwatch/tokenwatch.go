// Package tokenwatch watches the Vault token file for replacement and
// invokes a callback when it is created or updated, so a running daemon
// picks up a token freshly written by `dotvault login` (or any other
// external writer) without waiting for the lifecycle manager's periodic
// re-read.
//
// On Linux it uses inotify on the token file's parent directory. The
// directory — not the file — is the robust target: atomic writers
// (`vault login`, dotvault's own temp-file+rename) replace the inode
// rather than writing in place, so an inode-level watch would go deaf
// after the first rotation. It subscribes to creation and
// write-completion events and deliberately ignores deletes — a removed
// token file leaves the daemon operating on its current in-memory token
// until a replacement appears.
//
// This replaces the previously shipped systemd `.path` unit, which
// achieved the same nudge out-of-process by SIGHUP-ing the daemon on
// every change to the token file. Doing it in-process drops two unit
// files and works regardless of the service manager.
//
// On every other platform Watch is a no-op that blocks until ctx is
// cancelled, so the daemon can wire it unconditionally. Non-Linux
// platforms had no path-unit equivalent to replace; the manual nudge
// remains available as SIGHUP (where delivered — macOS and the BSDs)
// and as the tray's "Reload config" entry on Windows. Function-level
// docs live with the build-tag-specific declarations so `go doc`
// picks up the right one per platform.
package tokenwatch
