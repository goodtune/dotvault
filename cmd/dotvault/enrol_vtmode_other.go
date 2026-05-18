//go:build !windows

package main

import "os"

// enableVTOutput is a no-op on non-Windows. POSIX terminals process
// ANSI escape sequences natively; the Windows variant exists only
// to flip ENABLE_VIRTUAL_TERMINAL_PROCESSING on the output handle.
func enableVTOutput(_ *os.File) func() {
	return func() {}
}
