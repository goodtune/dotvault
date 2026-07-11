// Package notify delivers platform-native desktop notifications — Windows
// toast popups, macOS Notification Center panels, Linux D-Bus notifications —
// behind a small level vocabulary (info / warning / error / attention).
//
// It is the delivery half of the remote-notify feature: the web API's
// POST /api/v1/remote/notify handler and the `dotvault notify` CLI both build
// a Message and hand it to a Notifier, so a headless peer can surface a
// notification on the workstation over the same forwarded socket that carries
// the token borrow and remote browse.
//
// Delivery is via github.com/gen2brain/beeep, which is pure Go (no cgo) with
// build-tagged platform backends, preserving the repo's CGO_ENABLED=0
// invariant. The package exposes an injectable Notifier seam (Send is the
// default) so callers can fake delivery in tests without popping real
// notifications.
package notify

import (
	"fmt"
	"runtime"
	"strings"
	"unicode"

	"github.com/gen2brain/beeep"
)

// appName is the application name beeep attributes notifications to (the
// D-Bus app_name on Linux, the toast AppID hint on Windows). Set once at
// package init rather than per-call so every notification is consistently
// attributed to dotvault.
const appName = "dotvault"

func init() {
	beeep.AppName = appName
}

// Maximum accepted lengths for the title and body. Notification surfaces
// truncate long text anyway; capping here keeps a hostile or buggy peer from
// handing a megabyte of text to the OS notification daemon.
const (
	maxTitleLen = 200
	maxBodyLen  = 1000
)

// Level classifies a notification's severity. It drives two things: the
// urgency of delivery (error and attention are delivered as audible,
// higher-priority alerts) and, where the platform supports a named stock
// icon (Linux/BSD via D-Bus), the icon shown.
type Level string

const (
	LevelInfo      Level = "info"
	LevelWarning   Level = "warning"
	LevelError     Level = "error"
	LevelAttention Level = "attention"
)

// levelOrder is the canonical list, used for validation error messages and
// CLI help so the accepted set has one source of truth.
var levelOrder = []Level{LevelInfo, LevelWarning, LevelError, LevelAttention}

// levelInfo carries the per-level delivery attributes.
type levelAttrs struct {
	// urgent selects beeep.Alert (audible, critical urgency) over
	// beeep.Notify (normal). Error and attention warrant interrupting the
	// user; info and warning do not.
	urgent bool
	// stockIcon is the freedesktop icon name shown on Linux/BSD, where the
	// D-Bus app_icon field accepts stock names. It is deliberately not used
	// on macOS/Windows — see iconArg.
	stockIcon string
}

var levelTable = map[Level]levelAttrs{
	LevelInfo:      {urgent: false, stockIcon: "dialog-information"},
	LevelWarning:   {urgent: false, stockIcon: "dialog-warning"},
	LevelError:     {urgent: true, stockIcon: "dialog-error"},
	LevelAttention: {urgent: true, stockIcon: "dialog-question"},
}

// Levels returns the accepted level names in canonical order, for CLI help
// and error messages.
func Levels() []string {
	out := make([]string, len(levelOrder))
	for i, l := range levelOrder {
		out[i] = string(l)
	}
	return out
}

// ParseLevel validates a level name (case-insensitive) and returns the
// canonical Level. An unknown name is an error naming the accepted set.
func ParseLevel(s string) (Level, error) {
	l := Level(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := levelTable[l]; ok {
		return l, nil
	}
	return "", fmt.Errorf("unknown level %q (want one of: %s)", s, strings.Join(Levels(), ", "))
}

// Message is a validated notification ready for delivery.
type Message struct {
	Level Level
	Title string
	Body  string
}

// NewMessage validates and sanitizes the inputs into a Message. The level
// must be a known level; the title must be non-empty after sanitization; the
// body is optional. Title and body are stripped of control characters
// (notification text is single-line, and control bytes are an injection
// vector into the shell/AppleScript/XML backends beeep drives) and capped in
// length.
func NewMessage(level, title, body string) (Message, error) {
	l, err := ParseLevel(level)
	if err != nil {
		return Message{}, err
	}
	title = sanitize(title, maxTitleLen)
	if title == "" {
		return Message{}, fmt.Errorf("notification title must not be empty")
	}
	return Message{Level: l, Title: title, Body: sanitize(body, maxBodyLen)}, nil
}

// sanitize collapses control characters (including newlines and tabs) to
// spaces, trims surrounding whitespace, and truncates to max runes. Removing
// control bytes keeps title/body from breaking out of the single-line
// notification fields or injecting into the exec/XML/AppleScript delivery
// backends; the length cap bounds what reaches the OS daemon.
func sanitize(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == unicode.ReplacementChar {
			continue
		}
		if unicode.IsControl(r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len([]rune(out)) > max {
		out = string([]rune(out)[:max])
		out = strings.TrimSpace(out)
	}
	return out
}

// Notifier delivers a validated Message. Send is the real implementation;
// the web server and tests inject their own.
type Notifier func(Message) error

// Send delivers msg via the platform's native notification mechanism. It is
// the default Notifier. A level's urgency selects an audible alert (error /
// attention) or a normal notification (info / warning), and on platforms that
// accept a named stock icon the level's icon is shown.
func Send(msg Message) error {
	icon := iconArg(msg.Level)
	if levelTable[msg.Level].urgent {
		return beeep.Alert(msg.Title, msg.Body, icon)
	}
	return beeep.Notify(msg.Title, msg.Body, icon)
}

// iconArg returns the icon argument handed to beeep for a level. On Linux and
// the BSDs the D-Bus app_icon (and notify-send -i) accept a freedesktop stock
// icon name, so the level's named icon is shown. On macOS and Windows a
// string icon is interpreted as a file *path*; a stock name is not a real
// file there, so we pass an empty string (no custom icon) rather than a bogus
// path that a backend might choke on — the level is still conveyed by the
// urgency (audible alert vs quiet notification). beeep requires the icon be a
// string or []byte, so this is "" rather than nil.
func iconArg(level Level) string {
	switch runtime.GOOS {
	case "linux", "freebsd", "netbsd", "openbsd", "dragonfly", "illumos":
		return levelTable[level].stockIcon
	default:
		return ""
	}
}
