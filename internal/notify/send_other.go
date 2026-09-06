//go:build !windows

package notify

// platformDeliver is the non-Windows delivery path. beeep exposes no
// click-action API, and the one-shot delivery here cannot register a D-Bus
// action handler (Linux) or drive terminal-notifier's -open reliably (macOS
// falls back to osascript, which has no open support), so an ActionURL cannot
// be made clickable. It degrades gracefully: the URL is appended to the body
// (actionBody) so the user can still see and copy it. The level's urgency and
// stock icon are applied exactly as before.
func platformDeliver(msg Message) error {
	urgent := levelTable[msg.Level].urgent
	return beeepDeliver(urgent, msg.Title, actionBody(msg), iconArg(msg.Level))
}
