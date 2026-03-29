package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	godaemon "github.com/sevlyar/go-daemon"

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

// Daemonize forks the current process into the background using go-daemon.
//
// In the parent, Result.IsChild is false and the caller should print the PID
// and exit. In the child, Result.IsChild is true and the caller should defer
// Result.Release() then continue normal execution.
func Daemonize() (*Result, error) {
	logDir := paths.LogDir()
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	pidDir := paths.CacheDir()
	if err := os.MkdirAll(pidDir, 0700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	ctx := &godaemon.Context{
		PidFileName: PIDFilePath(),
		PidFilePerm: 0600,
		LogFileName: filepath.Join(logDir, "daemon.log"),
		LogFilePerm: 0600,
		WorkDir:     "/",
		Umask:       0o27,
	}

	child, err := ctx.Reborn()
	if err != nil {
		return nil, fmt.Errorf("daemonize: %w", err)
	}

	if child != nil {
		// Parent process: child is running in the background.
		return &Result{PID: child.Pid}, nil
	}

	// Child process: hand back a release function for PID file cleanup.
	return &Result{
		IsChild: true,
		Release: func() { ctx.Release() },
	}, nil
}

// WasReborn returns true if the current process is the daemonized child.
func WasReborn() bool {
	return godaemon.WasReborn()
}

// PIDFilePath returns the path to the daemon PID file.
func PIDFilePath() string {
	return filepath.Join(paths.CacheDir(), "daemon.pid")
}
