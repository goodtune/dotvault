package daemon

import "context"

// TrayConfig holds the parameters for the system tray / menu bar icon.
type TrayConfig struct {
	// URL is the web UI address to open when the user clicks the tray icon.
	URL string
	// Cancel is called when the user selects "Quit" from the tray menu.
	Cancel context.CancelFunc
}
