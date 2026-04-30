//go:build windows

package tray

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/browser"
	"golang.org/x/sys/windows"
)

// Win32 message identifiers and constants used by the tray. Values come
// from the Windows SDK headers (winuser.h, shellapi.h).
const (
	wmDestroy     = 0x0002
	wmNull        = 0x0000
	wmCommand     = 0x0111
	wmRButtonUp   = 0x0205
	wmLButtonDbl  = 0x0203
	wmUser        = 0x0400
	wmTrayCB      = wmUser + 1 // notification callback from Shell_NotifyIcon
	wmTrayQuit    = wmUser + 2 // posted by Run when ctx is cancelled
	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nifMessage    = 0x00000001
	nifIcon       = 0x00000002
	nifTip        = 0x00000004
	idiApplication = 32512
	idcArrow       = 32512
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	mfString       = 0x00000000
	mfSeparator    = 0x00000800

	menuIDView = 1001
	menuIDExit = 1002
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	procLoadIconW          = user32.NewProc("LoadIconW")
	procLoadCursorW        = user32.NewProc("LoadCursorW")
	procRegisterClassExW   = user32.NewProc("RegisterClassExW")
	procCreateWindowExW    = user32.NewProc("CreateWindowExW")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procDefWindowProcW     = user32.NewProc("DefWindowProcW")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessageW   = user32.NewProc("DispatchMessageW")
	procPostMessageW       = user32.NewProc("PostMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procCreatePopupMenu    = user32.NewProc("CreatePopupMenu")
	procAppendMenuW        = user32.NewProc("AppendMenuW")
	procDestroyMenu        = user32.NewProc("DestroyMenu")
	procTrackPopupMenu     = user32.NewProc("TrackPopupMenu")
	procGetCursorPos       = user32.NewProc("GetCursorPos")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")

	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
)

// wndClassEx mirrors WNDCLASSEXW.
type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

// notifyIconData mirrors NOTIFYICONDATAW. The full V4 struct is large but
// laying it out lets us pass cbSize = unsafe.Sizeof(notifyIconData{}) and
// rely on the kernel to ignore unset fields.
type notifyIconData struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     windows.Handle
}

type point struct {
	x, y int32
}

type msg struct {
	hwnd     windows.Handle
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

// state holds everything the WindowProc needs to react to messages. There
// is exactly one tray per process, so a package-level singleton is fine.
type state struct {
	mu       sync.Mutex
	hwnd     windows.Handle
	nid      notifyIconData
	cfg      Config
	hasView  bool
}

var trayState state

// Run installs a tray icon, runs the Win32 message pump on a locked OS
// thread, and returns when ctx is cancelled or the user picks Exit.
//
// All Win32 GUI calls must originate from the thread that created the
// window, so Run pins itself with runtime.LockOSThread. Other goroutines
// communicate with the pump via PostMessageW (see ctx-cancel watcher).
func Run(ctx context.Context, cfg Config) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInstance, _, callErr := procGetModuleHandleW.Call(0)
	if hInstance == 0 {
		return fmt.Errorf("GetModuleHandle: %w", callErr)
	}

	hIcon, _, _ := procLoadIconW.Call(0, uintptr(idiApplication))
	hCursor, _, _ := procLoadCursorW.Call(0, uintptr(idcArrow))

	className, err := windows.UTF16PtrFromString("dotvaultTrayWnd")
	if err != nil {
		return fmt.Errorf("class name: %w", err)
	}
	windowName, err := windows.UTF16PtrFromString("dotvault")
	if err != nil {
		return fmt.Errorf("window name: %w", err)
	}

	wc := wndClassEx{
		lpfnWndProc:   windows.NewCallback(wndProc),
		hInstance:     windows.Handle(hInstance),
		hIcon:         windows.Handle(hIcon),
		hCursor:       windows.Handle(hCursor),
		lpszClassName: className,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))

	if ret, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); ret == 0 {
		return fmt.Errorf("RegisterClassEx: %w", callErr)
	}

	// Hidden top-level window — no WS_VISIBLE, no taskbar entry. We
	// deliberately do not pass HWND_MESSAGE: TrackPopupMenu requires a
	// foreground-able owner to dismiss on click-away (see showMenu's
	// SetForegroundWindow workaround), and message-only windows cannot
	// become foreground.
	hwnd, _, callErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 0, 0,
		0, 0,
		hInstance,
		0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %w", callErr)
	}

	trayState.mu.Lock()
	trayState.hwnd = windows.Handle(hwnd)
	trayState.cfg = cfg
	trayState.hasView = cfg.WebURL != ""
	trayState.nid = notifyIconData{
		hWnd:             windows.Handle(hwnd),
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: wmTrayCB,
		hIcon:            windows.Handle(hIcon),
	}
	trayState.nid.cbSize = uint32(unsafe.Sizeof(trayState.nid))
	tip := cfg.Tooltip
	if tip == "" {
		tip = "dotvault"
	}
	copyUTF16(trayState.nid.szTip[:], tip)
	trayState.mu.Unlock()

	if ret, _, callErr := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&trayState.nid))); ret == 0 {
		procDestroyWindow.Call(hwnd)
		return fmt.Errorf("Shell_NotifyIcon(NIM_ADD): %w", callErr)
	}

	// Watcher: when the daemon context is cancelled, tell the message
	// pump to break out by posting a custom message to our window.
	go func() {
		<-ctx.Done()
		procPostMessageW.Call(hwnd, wmTrayQuit, 0, 0)
	}()

	// Standard Win32 message pump. GetMessageW returns 0 on WM_QUIT
	// and -1 on error — the latter is a real failure (invalid hwnd or
	// bad message-queue state), surface it instead of treating it as a
	// clean shutdown.
	var loopErr error
	var m msg
	for {
		ret, _, callErr := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		switch int32(ret) {
		case -1:
			loopErr = fmt.Errorf("GetMessage: %w", callErr)
		case 0:
			// WM_QUIT — clean exit.
		default:
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
			continue
		}
		break
	}

	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&trayState.nid)))
	return loopErr
}

// wndProc handles messages for the tray's hidden window. It must not block
// or re-enter Win32 in ways that stall the pump, so user-supplied callbacks
// (browser open, daemon shutdown) are dispatched to goroutines and return
// control immediately.
func wndProc(hwnd windows.Handle, message uint32, wParam, lParam uintptr) uintptr {
	switch message {
	case wmTrayCB:
		// lParam carries the inner mouse event for the tray icon.
		switch uint32(lParam) {
		case wmLButtonDbl:
			go triggerView()
		case wmRButtonUp:
			showMenu(hwnd)
		}
		return 0
	case wmCommand:
		switch uint32(wParam & 0xFFFF) {
		case menuIDView:
			go triggerView()
		case menuIDExit:
			go triggerExit(hwnd)
		}
		return 0
	case wmTrayQuit:
		// Ctx-cancel watcher tapping us on the shoulder.
		procDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
	return ret
}

func showMenu(hwnd windows.Handle) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	trayState.mu.Lock()
	hasView := trayState.hasView
	trayState.mu.Unlock()

	if hasView {
		viewPtr, _ := windows.UTF16PtrFromString("&View web UI")
		procAppendMenuW.Call(hMenu, mfString, uintptr(menuIDView), uintptr(unsafe.Pointer(viewPtr)))
		procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	}
	exitPtr, _ := windows.UTF16PtrFromString("E&xit")
	procAppendMenuW.Call(hMenu, mfString, uintptr(menuIDExit), uintptr(unsafe.Pointer(exitPtr)))

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	// Required quirks (documented in the Shell_NotifyIcon MSDN reference):
	// 1. Bring our window to the foreground before TrackPopupMenu so the
	//    menu actually dismisses when the user clicks away.
	// 2. Post a no-op WM_NULL afterwards to flush the menu's input state;
	//    without this the menu can stay "stuck" on second invocation.
	procSetForegroundWindow.Call(uintptr(hwnd))
	procTrackPopupMenu.Call(
		hMenu,
		tpmRightButton,
		uintptr(pt.x), uintptr(pt.y),
		0,
		uintptr(hwnd),
		0,
	)
	procPostMessageW.Call(uintptr(hwnd), wmNull, 0, 0)
}

func triggerView() {
	trayState.mu.Lock()
	url := trayState.cfg.WebURL
	trayState.mu.Unlock()
	if url == "" {
		return
	}
	if err := browser.OpenURL(url); err != nil {
		slog.Warn("tray: failed to open browser", "url", url, "error", err)
	}
}

// triggerExit runs the user-supplied OnExit (typically a context cancel)
// off-thread so wndProc never blocks. We do not call DestroyWindow here:
// the ctx-cancel watcher inside Run will see the cancelled context and
// post wmTrayQuit, which wndProc handles on the correct thread.
func triggerExit(_ windows.Handle) {
	trayState.mu.Lock()
	onExit := trayState.cfg.OnExit
	trayState.mu.Unlock()
	if onExit != nil {
		onExit()
	}
}

// copyUTF16 fills a fixed-size UTF-16 buffer from s, leaving room for a
// trailing null terminator regardless of input length.
func copyUTF16(dst []uint16, s string) {
	enc, err := syscall.UTF16FromString(s)
	if err != nil {
		return
	}
	n := len(enc)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst[:n], enc[:n])
	if len(dst) > 0 {
		dst[len(dst)-1] = 0
	}
}
