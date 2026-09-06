//go:build windows

package uds

import "net"

// Listen is unavailable on Windows: dotvault's Windows surfaces use named
// pipes with an equivalent protected DACL instead (see
// internal/agent/listener_windows.go). The symbol exists so packages that
// reference it compile everywhere and can degrade cleanly at runtime.
func Listen(path string) (net.Listener, error) {
	return nil, ErrUnsupported
}

// Cleanup is a no-op on Windows, where Listen never creates anything.
func Cleanup(path string) {}
