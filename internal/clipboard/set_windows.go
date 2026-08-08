package clipboard

import (
	"fmt"
	"runtime"
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
	user32                   = windows.NewLazySystemDLL("user32.dll")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard        = user32.NewProc("OpenClipboard")
	procCloseClipboard       = user32.NewProc("CloseClipboard")
	procEmptyClipboard       = user32.NewProc("EmptyClipboard")
	procSetClipboardData     = user32.NewProc("SetClipboardData")
	procRegisterClipboardFmt = user32.NewProc("RegisterClipboardFormatW")
	procGlobalAlloc          = kernel32.NewProc("GlobalAlloc")
	procGlobalFree           = kernel32.NewProc("GlobalFree")
	procGlobalLock           = kernel32.NewProc("GlobalLock")
	procGlobalUnlock         = kernel32.NewProc("GlobalUnlock")
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

	// The Win32 clipboard is thread-affine: an open clipboard belongs to the
	// calling THREAD, so the whole Open→Empty→Set→Close sequence must run on
	// one OS thread. Without the lock the Go scheduler may migrate the
	// goroutine mid-sequence, failing later calls with
	// ERROR_CLIPBOARD_NOT_OPEN and leaving the clipboard held open (blocking
	// every other application) until the original thread dies. LIFO defers:
	// CloseClipboard runs before the thread is unlocked.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
	setExclusionFormats()
	return nil
}

// exclusionFormats opt this clipboard update out of Windows' built-in
// credential-exfiltration paths: `CanIncludeInClipboardHistory` = 0 keeps it
// out of Clipboard History (Win+V), `CanUploadToCloudClipboard` = 0 keeps it
// off cross-device Cloud Clipboard sync (which would copy the credential to
// the user's Microsoft account and other devices), and
// `ExcludeClipboardContentFromMonitorProcessing` tells format-monitor-based
// clipboard managers to skip it entirely.
var exclusionFormats = []string{
	"CanIncludeInClipboardHistory",
	"CanUploadToCloudClipboard",
	"ExcludeClipboardContentFromMonitorProcessing",
}

// setExclusionFormats registers the exclusion formats alongside the text
// while the clipboard is still open. Best-effort by design: the text is
// already placed by the time this runs, so failing the user's copy over a
// missing defense-in-depth marker (the formats are advisory, and third-party
// managers may ignore them anyway) would be worse than proceeding — the docs
// carry the residual-risk note either way.
func setExclusionFormats() {
	for _, name := range exclusionFormats {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		fmtID, _, _ := procRegisterClipboardFmt.Call(uintptr(unsafe.Pointer(namePtr)))
		if fmtID == 0 {
			continue
		}
		h, _, _ := procGlobalAlloc.Call(gmemMoveable, 4)
		if h == 0 {
			continue
		}
		mem, _, _ := procGlobalLock.Call(h)
		if mem == 0 {
			procGlobalFree.Call(h) //nolint:errcheck
			continue
		}
		*(*uint32)(unsafe.Pointer(mem)) = 0 // DWORD 0 = "not allowed"
		procGlobalUnlock.Call(h)            //nolint:errcheck
		if r, _, _ := procSetClipboardData.Call(fmtID, h); r == 0 {
			procGlobalFree.Call(h) //nolint:errcheck
		}
	}
}
