// Package loginsuppress implements the marker-file suppression that
// coordinates `dotvault login-check` invocations across rapidly-launched
// shells. The shell wrapper (.bashrc/.zshrc/profile.d) is authoritative
// for environment gating — TTY, interactivity, daemon state — and this
// package never repeats those checks. It only answers: "given the
// resolved marker path and window, should this invocation prompt?"
package loginsuppress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	// DefaultHours is the suppression window when DOTVAULT_SUPPRESS_HOURS
	// is unset. Six hours matches the shell-wrapper era and keeps shell
	// startup quiet across a normal working day.
	DefaultHours = 6

	envMarker = "DOTVAULT_SUPPRESS_MARKER"
	envHours  = "DOTVAULT_SUPPRESS_HOURS"
	fileName  = "login-check-suppress"
	dirName   = "dotvault"
)

// Path returns the suppression marker file path.
//
// Resolution order:
//  1. DOTVAULT_SUPPRESS_MARKER (used primarily by tests)
//  2. ${XDG_STATE_HOME}/dotvault/login-check-suppress
//  3. $HOME/.local/state/dotvault/login-check-suppress
//
// This matches the path the previous shell-side suppression script used,
// so existing users retain their suppression state without migration.
func Path() string {
	if p := os.Getenv(envMarker); p != "" {
		return p
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, dirName, fileName)
}

// Window returns the suppression window duration parsed from
// DOTVAULT_SUPPRESS_HOURS, defaulting to DefaultHours when unset. The
// value must be a positive integer number of hours; zero, negative, and
// non-integer values are rejected so misconfiguration surfaces loudly
// rather than silently disabling suppression.
func Window() (time.Duration, error) {
	raw := os.Getenv(envHours)
	if raw == "" {
		return DefaultHours * time.Hour, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid %s: must be a positive integer", envHours)
	}
	return time.Duration(n) * time.Hour, nil
}

// IsFresh reports whether the marker at path is recent enough to
// suppress an invocation. A missing marker, a marker older than the
// window, or a marker with an mtime in the future (clock skew, restored
// backup, VM snapshot rollback) are all treated as stale so suppression
// cannot lock itself on indefinitely.
func IsFresh(path string, window time.Duration, now time.Time) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	mtime := info.ModTime()
	if mtime.After(now) {
		return false
	}
	return now.Sub(mtime) < window
}

// Refresh ensures the marker file exists and bumps its mtime to now.
// Parent directories are created on demand. Concurrent callers racing
// to refresh the same marker are safe: the worst case is interleaved
// mtime updates, which is the intended behaviour for the "multiple
// shells start at once" case.
func Refresh(path string) error {
	if path == "" {
		return errors.New("empty marker path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(path, now, now)
}
