//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVTOutput turns on ENABLE_VIRTUAL_TERMINAL_PROCESSING on the
// given handle so the ANSI escape sequences the TUI emits (cursor
// movement, screen clear, inverted highlight) render as escape
// codes rather than literal text.
//
// term.MakeRaw enables ENABLE_VIRTUAL_TERMINAL_INPUT on stdin so
// arrow-key sequences arrive in the usual `\x1b[A` shape, but it
// does not touch the output handle — without this helper the
// picker on bare cmd.exe / older conhost shows `←[H←[2J ▶...` as
// literal characters instead of clearing the screen.
//
// Supported since Windows 10 1809. On hosts that don't support VT
// processing SetConsoleMode returns an error, which we swallow:
// the picker degrades to garbled glyphs but the daemon and the
// rest of dotvault continue to work, and the user has a clear
// signal that they should fall back to `dotvault enrol <name>`.
//
// Returns a cleanup func that restores the previous console mode;
// callers should defer it alongside term.Restore on the input
// handle.
func enableVTOutput(f *os.File) func() {
	handle := windows.Handle(f.Fd())
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		return func() {}
	}
	if original&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return func() {}
	}
	if err := windows.SetConsoleMode(handle, original|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return func() {}
	}
	return func() {
		_ = windows.SetConsoleMode(handle, original)
	}
}
