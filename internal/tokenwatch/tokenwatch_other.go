//go:build !linux

package tokenwatch

import "context"

// Watch is a no-op on platforms without inotify: it blocks until ctx is
// cancelled and returns ctx.Err(). The daemon wires it unconditionally;
// macOS and Windows had no systemd path-unit equivalent to replace, and
// SIGHUP (where delivered) remains the manual re-read nudge. onChange is
// never invoked. The path argument is accepted for signature parity with
// the Linux build.
func Watch(ctx context.Context, path string, onChange func()) error {
	<-ctx.Done()
	return ctx.Err()
}
