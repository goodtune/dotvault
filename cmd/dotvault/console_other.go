//go:build !windows

package main

// attachParentConsole is a no-op on non-Windows platforms. The Windows
// build needs it because we link with -H=windowsgui, which detaches
// stdio when the binary is launched outside of a console.
func attachParentConsole() {}
