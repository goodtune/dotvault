//go:build !unix

package main

import "time"

// waitForMoreInput is a no-op on non-POSIX builds. On Windows
// term.MakeRaw enables ENABLE_VIRTUAL_TERMINAL_INPUT, which delivers
// each keystroke — including the multi-byte ANSI escape sequence an
// arrow key expands into — as one atomic ReadFile event. Splits don't
// occur there, so the peek is unnecessary.
func waitForMoreInput(_ uintptr, _ time.Duration) bool {
	return false
}
