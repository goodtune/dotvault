package daemon

import (
	"path/filepath"

	"github.com/goodtune/dotvault/internal/paths"
)

// Result is returned by Daemonize to describe which side of the fork we are on.
type Result struct {
	// PID is the child process ID (only meaningful in the parent).
	PID int
	// IsChild is true when we are the daemonized child process.
	IsChild bool
	// Release must be deferred by the child to clean up the PID file on exit.
	// It is nil in the parent.
	Release func()
}

// PIDFilePath returns the path to the daemon PID file.
func PIDFilePath() string {
	return filepath.Join(paths.CacheDir(), "daemon.pid")
}
