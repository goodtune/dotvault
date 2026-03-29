package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/goodtune/dotvault/internal/paths"
)

const envDaemonized = "_DOTVAULT_DAEMON"

// IsDaemonized returns true if the current process was spawned by Daemonize.
func IsDaemonized() bool {
	return os.Getenv(envDaemonized) == "1"
}

// Daemonize re-executes the current binary as a detached background process.
// It strips the --daemon flag from the arguments to prevent infinite recursion,
// redirects output to a log file, writes a PID file, and returns the child PID.
// The caller should exit after a successful call.
func Daemonize() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable: %w", err)
	}

	args := filterFlag(os.Args[1:], "--daemon")

	logDir := paths.LogDir()
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return 0, fmt.Errorf("create log directory: %w", err)
	}

	logFile, err := os.OpenFile(
		filepath.Join(logDir, "daemon.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0600,
	)
	if err != nil {
		return 0, fmt.Errorf("open log file: %w", err)
	}

	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), envDaemonized+"=1")

	detach(cmd)

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("start daemon: %w", err)
	}

	pid := cmd.Process.Pid

	// Write PID file for later management.
	pidDir := paths.CacheDir()
	if err := os.MkdirAll(pidDir, 0700); err == nil {
		_ = os.WriteFile(filepath.Join(pidDir, "daemon.pid"), []byte(fmt.Sprintf("%d\n", pid)), 0600)
	}

	// Release the child so it survives our exit.
	_ = cmd.Process.Release()
	logFile.Close()

	return pid, nil
}

// PIDFilePath returns the path to the daemon PID file.
func PIDFilePath() string {
	return filepath.Join(paths.CacheDir(), "daemon.pid")
}

// filterFlag removes exact matches of flag from args.
func filterFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}
