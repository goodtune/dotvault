//go:build !unix

package main

import (
	"context"
	"time"
)

// waitForMoreInput is a no-op on non-POSIX builds. On Windows
// term.MakeRaw enables ENABLE_VIRTUAL_TERMINAL_INPUT, which delivers
// each keystroke — including the multi-byte ANSI escape sequence an
// arrow key expands into — as one atomic ReadFile event. Splits don't
// occur there, so the peek is unnecessary.
func waitForMoreInput(_ uintptr, _ time.Duration) bool {
	return false
}

// blockUntilInput on non-POSIX returns immediately so the caller
// proceeds straight to a blocking Read. There is no portable way to
// interrupt a Read on Windows mid-stream from another goroutine
// without closing the file descriptor (which breaks subsequent
// reads), so the picker on Windows observes ctx cancellation only
// after the user presses a key. Documented as a known limitation;
// the picker is a foreground interactive command, so the user is
// the natural unblocker.
func blockUntilInput(ctx context.Context, _ uintptr) error {
	return ctx.Err()
}
