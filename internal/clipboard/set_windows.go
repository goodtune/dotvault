package clipboard

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows writer talks to the Win32 clipboard API directly
// (CF_UNICODETEXT) rather than shelling out to clip.exe: clip.exe interprets
// stdin in the console code page, which mangles non-ASCII text, while
// CF_UNICODETEXT is the canonical Unicode format every application reads.
// Like the go-toast clickable-notification path and the TPM backend, this
// Windows-only code is not exercised in the (Linux) CI; the shared candidate
// logic it does not use (execSet) and the validation it sits behind are
// unit-tested everywhere.
var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalFree       = kernel32.NewProc("GlobalFree")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13     // CF_UNICODETEXT
	gmemMoveable  = 0x0002 // GMEM_MOVEABLE — clipboard handles must be moveable
)

// openClipboard retries briefly: the clipboard is a single shared resource
// and OpenClipboard fails while any other process holds it — clipboard
// managers open it on every change — so a single attempt would flake.
func openClipboard() error {
	const (
		attempts = 25
		backoff  = 10 * time.Millisecond
	)
	var lastErr error
	for i := 0; i < attempts; i++ {
		r, _, err := procOpenClipboard.Call(0)
		if r != 0 {
			return nil
		}
		lastErr = err
		time.Sleep(backoff)
	}
	return fmt.Errorf("open clipboard: %w", lastErr)
}

func platformSet(text string) error {
	// UTF16FromString appends the terminating NUL CF_UNICODETEXT requires and
	// rejects interior NULs (already excluded by ValidateText).
	u16, err := windows.UTF16FromString(text)
	if err != nil {
		return fmt.Errorf("encode clipboard text: %w", err)
	}

	if err := openClipboard(); err != nil {
		return err
	}
	defer procCloseClipboard.Call() //nolint:errcheck

	if r, _, err := procEmptyClipboard.Call(); r == 0 {
		return fmt.Errorf("empty clipboard: %w", err)
	}
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(u16))*2)
	if h == 0 {
		return fmt.Errorf("allocate clipboard buffer: %w", err)
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h) //nolint:errcheck
		return fmt.Errorf("lock clipboard buffer: %w", err)
	}
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(p)), len(u16)), u16)
	procGlobalUnlock.Call(h) //nolint:errcheck
	if r, _, err := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		// On failure the buffer is still ours to free; on success the system
		// owns it and freeing it would corrupt the clipboard.
		procGlobalFree.Call(h) //nolint:errcheck
		return fmt.Errorf("set clipboard data: %w", err)
	}
	return nil
}
