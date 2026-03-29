//go:build windows

package daemon

import (
	"log/slog"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/pkg/browser"
	"golang.org/x/sys/windows"
)

// Win32 constants for the notification icon and window messages.
const (
	nimAdd    = 0x00000000
	nimDelete = 0x00000004
	nifIcon   = 0x00000002
	nifTip    = 0x00000004
	nifMsg    = 0x00000001

	wmApp        = 0x8000 // WM_APP
	wmTrayMsg    = wmApp + 1
	wmNull       = 0x0000
	wmCommand    = 0x0111
	wmLButtonUp  = 0x0202
	wmRButtonUp  = 0x0205
	wmDestroy    = 0x0002
	wmClose      = 0x0010

	tpmBottomAlign = 0x0020
	tpmLeftAlign   = 0x0000

	idOpen = 1
	idQuit = 2
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	shell32               = windows.NewLazySystemDLL("shell32.dll")
	user32                = windows.NewLazySystemDLL("user32.dll")
	procGetModuleHandle   = kernel32.NewProc("GetModuleHandleW")
	procShellNotifyIcon   = shell32.NewProc("Shell_NotifyIconW")
	procLoadIcon          = user32.NewProc("LoadIconW")
	procRegisterClassEx   = user32.NewProc("RegisterClassExW")
	procCreateWindowEx    = user32.NewProc("CreateWindowExW")
	procDefWindowProc     = user32.NewProc("DefWindowProcW")
	procGetMessage        = user32.NewProc("GetMessageW")
	procTranslateMessage  = user32.NewProc("TranslateMessage")
	procDispatchMessage   = user32.NewProc("DispatchMessageW")
	procPostQuitMessage   = user32.NewProc("PostQuitMessage")
	procCreatePopupMenu   = user32.NewProc("CreatePopupMenu")
	procAppendMenu        = user32.NewProc("AppendMenuW")
	procTrackPopupMenu    = user32.NewProc("TrackPopupMenu")
	procSetForegroundWnd  = user32.NewProc("SetForegroundWindow")
	procGetCursorPos      = user32.NewProc("GetCursorPos")
	procDestroyMenu       = user32.NewProc("DestroyMenu")
	procPostMessage       = user32.NewProc("PostMessageW")
)

type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
}

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  uintptr
	lpszClassName uintptr
	hIconSm       uintptr
}

type point struct {
	x, y int32
}

type msg struct {
	hWnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

// package-level state for the window procedure callback
var trayState struct {
	cfg  TrayConfig
	hwnd atomic.Uintptr
	nid  notifyIconData
}

// StartTray starts the Windows system tray (notification area) icon in a
// background goroutine. Left-clicking the icon opens the web UI. Right-click
// shows a context menu with "Open DotVault" and "Quit".
func StartTray(cfg TrayConfig) {
	trayState.cfg = cfg
	go runTrayLoop()
}

// StopTray requests that the tray window close and clean up the notification
// icon. It can be called from non-tray shutdown paths (e.g., signal handlers)
// to avoid leaving a stale notification icon in the system tray.
func StopTray() {
	hwnd := trayState.hwnd.Load()
	if hwnd == 0 {
		return
	}
	procPostMessage.Call(hwnd, uintptr(wmClose), 0, 0)
}

func runTrayLoop() {
	// Windows GUI calls must stay on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	className, _ := windows.UTF16PtrFromString("DotVaultTray")
	hInstance, _, _ := procGetModuleHandle.Call(0)

	wc := wndClassEx{
		lpfnWndProc:   windows.NewCallback(wndProc),
		lpszClassName: uintptr(unsafe.Pointer(className)),
		hInstance:     hInstance,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))

	ret, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc)))
	if ret == 0 {
		slog.Error("failed to register tray window class", "error", err)
		return
	}

	hwnd, _, err := procCreateWindowEx.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0, // no title
		0, // style
		0, 0, 0, 0,
		0, 0, hInstance, 0,
	)
	if hwnd == 0 {
		slog.Error("failed to create tray window", "error", err)
		return
	}
	trayState.hwnd.Store(hwnd)

	// Load default application icon.
	icon, _, _ := procLoadIcon.Call(0, uintptr(32512)) // IDI_APPLICATION

	nid := notifyIconData{
		hWnd:             hwnd,
		uID:              1,
		uFlags:           nifIcon | nifTip | nifMsg,
		uCallbackMessage: wmTrayMsg,
		hIcon:            icon,
	}
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	copy(nid.szTip[:], windows.StringToUTF16("DotVault — Secret Sync Daemon"))
	trayState.nid = nid

	ret, _, err = procShellNotifyIcon.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		slog.Error("failed to add system tray icon", "error", err)
		return
	}

	slog.Info("system tray icon added")

	// Standard Windows message loop.
	var m msg
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 { // WM_QUIT
			break
		}
		if ret == ^uintptr(0) { // -1: error
			slog.Error("GetMessageW returned error, exiting tray loop")
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}

	// Clean up tray icon on exit and reset handle so StopTray is safe to call after.
	procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&trayState.nid)))
	trayState.hwnd.Store(0)
}

func wndProc(hwnd, msgID, wParam, lParam uintptr) uintptr {
	switch msgID {
	case wmTrayMsg:
		switch lParam {
		case wmLButtonUp:
			// Left-click: open browser directly.
			if err := browser.OpenURL(trayState.cfg.URL); err != nil {
				slog.Warn("failed to open browser from tray", "error", err)
			}
		case wmRButtonUp:
			showContextMenu(hwnd)
		}
		return 0

	case wmCommand:
		id := wParam & 0xFFFF
		switch id {
		case idOpen:
			if err := browser.OpenURL(trayState.cfg.URL); err != nil {
				slog.Warn("failed to open browser from tray", "error", err)
			}
		case idQuit:
			if trayState.cfg.Cancel != nil {
				trayState.cfg.Cancel()
			}
			procPostMessage.Call(hwnd, wmClose, 0, 0)
		}
		return 0

	case wmClose, wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProc.Call(hwnd, msgID, wParam, lParam)
	return ret
}

func showContextMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()

	openLabel, _ := windows.UTF16PtrFromString("Open DotVault")
	quitLabel, _ := windows.UTF16PtrFromString("Quit")

	procAppendMenu.Call(menu, 0, idOpen, uintptr(unsafe.Pointer(openLabel)))
	procAppendMenu.Call(menu, 0, idQuit, uintptr(unsafe.Pointer(quitLabel)))

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	procSetForegroundWnd.Call(hwnd)
	procTrackPopupMenu.Call(menu, tpmLeftAlign|tpmBottomAlign, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
	procPostMessage.Call(hwnd, wmNull, 0, 0)
	procDestroyMenu.Call(menu)
}
