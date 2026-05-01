//go:build !windows

package tray

import "context"

// Run blocks until ctx is cancelled. The system-tray UI is Windows-only;
// on other platforms there is nothing to display, so Run simply waits.
func Run(ctx context.Context, _ Config) error {
	<-ctx.Done()
	return nil
}
