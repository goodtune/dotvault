//go:build !linux

package tokenwatch

import "context"

// Watcher is the no-op counterpart to the Linux inotify Watcher on
// platforms without inotify. It exists so the daemon can wire
// New/Run/Close unconditionally; there is nothing to register, so New
// never fails and Run simply blocks until ctx is cancelled. onChange is
// never invoked.
type Watcher struct {
	onChange func()
}

// New returns a no-op Watcher. It never fails — there is no inotify
// machinery to set up — and accepts path for signature parity with the
// Linux build.
func New(path string, onChange func()) (*Watcher, error) {
	return &Watcher{onChange: onChange}, nil
}

// Run blocks until ctx is cancelled and returns ctx.Err(). onChange is
// never invoked: macOS and Windows had no systemd path-unit equivalent
// to replace, and the manual re-read nudge remains available (SIGHUP on
// macOS, the tray's "Reload config" entry on Windows).
func (w *Watcher) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// Close is a no-op; there is no fd to release.
func (w *Watcher) Close() error {
	return nil
}

// Watch is the no-op one-shot wrapper retained for signature parity with
// the Linux build. It blocks until ctx is cancelled and returns
// ctx.Err(); onChange is never invoked.
func Watch(ctx context.Context, path string, onChange func()) error {
	<-ctx.Done()
	return ctx.Err()
}
