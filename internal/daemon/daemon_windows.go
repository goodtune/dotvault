//go:build windows

package daemon

import "fmt"

// Daemonize is not supported on Windows.
func Daemonize() (*Result, error) {
	return nil, fmt.Errorf("--daemon is not supported on Windows; run dotvault in the foreground or use a Windows service manager")
}

// WasReborn always returns false on Windows.
func WasReborn() bool {
	return false
}
