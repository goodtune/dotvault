//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

var (
	modkernel32         = windows.NewLazySystemDLL("kernel32.dll")
	procAttachConsole   = modkernel32.NewProc("AttachConsole")
	procGetConsoleWindow = modkernel32.NewProc("GetConsoleWindow")
)

const attachParentProcess = ^uintptr(0) // (DWORD)-1

// attachParentConsole tries to inherit the parent process's console so
// CLI subcommands like `dotvault status` produce visible output even
// though the binary is linked with -H=windowsgui (no console of its
// own). If there is no parent console — the user double-clicked the
// .exe — the call is harmless and stdout/stderr remain detached.
func attachParentConsole() {
	// Already have a console? Nothing to do.
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
		return
	}
	ret, _, _ := procAttachConsole.Call(attachParentProcess)
	if ret == 0 {
		return
	}
	// Re-bind the Go runtime's stdio to the now-attached console so
	// fmt.Println and slog land where the user expects.
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 {
		os.Stdout = os.NewFile(uintptr(h), "stdout")
	}
	if h, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE); err == nil && h != 0 {
		os.Stderr = os.NewFile(uintptr(h), "stderr")
	}
	if h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE); err == nil && h != 0 {
		os.Stdin = os.NewFile(uintptr(h), "stdin")
	}
}
