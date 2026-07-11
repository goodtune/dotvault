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
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"unicode"

	"github.com/gen2brain/beeep"
)

// appName is the application name beeep attributes notifications to (the
// D-Bus app_name on Linux, the toast AppID hint on Windows). Applied inside
// Send rather than an init() so importing this package has no invisible
// import-time side effect of rebranding beeep process-wide; the assignment is
// idempotent and cheap.
const appName = "dotvault"

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
	// ActionURL, when non-empty, is an http/https URL the notification should
	// take the user to when clicked. It is validated by NewMessage. Whether it
	// is actually *clickable* is platform-dependent: on Windows the toast is
	// activated to open the URL; on macOS/Linux, where a one-shot delivery
	// cannot register a click handler, the URL is appended to the body so it
	// stays visible and copyable (see actionBody / platformDeliver).
	ActionURL string
}

// NewMessage validates and sanitizes the inputs into a Message. The level
// must be a known level; the title must be non-empty after sanitization; the
// body is optional. Title and body are sanitized (control characters removed,
// delivery-backend metacharacters neutralized — see sanitize) and capped in
// length. actionURL is optional; when set it must be an http/https URL with a
// host and no embedded credentials.
func NewMessage(level, title, body, actionURL string) (Message, error) {
	l, err := ParseLevel(level)
	if err != nil {
		return Message{}, err
	}
	title = sanitize(title, maxTitleLen)
	if title == "" {
		return Message{}, fmt.Errorf("notification title must not be empty")
	}
	au, err := validateActionURL(actionURL)
	if err != nil {
		return Message{}, err
	}
	return Message{Level: l, Title: title, Body: sanitize(body, maxBodyLen), ActionURL: au}, nil
}

// validateActionURL enforces the same allowlist the browse endpoint applies to
// a URL handed to an OS opener: an absolute http/https URL with a host and no
// embedded user:pass@ credentials, free of control characters. It returns the
// canonical serialized URL, or "" for an empty (absent) input. It duplicates
// web.ValidateBrowseURL's rules deliberately — internal/web imports
// internal/notify, so importing back would cycle, and the action URL has its
// own delivery-sink concerns (see safeToastArgs).
func validateActionURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid action url: %v", err)
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("action url must be http or https (got %q)", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", errors.New("action url has no host")
	}
	if u.User != nil {
		return "", errors.New("action url must not contain embedded credentials")
	}
	s := u.String()
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errors.New("action url must not contain control characters")
		}
	}
	return s, nil
}

// sanitize prepares an untrusted title/body for delivery: it collapses control
// characters to spaces, neutralizes the metacharacters that would break out of
// beeep's Windows toast backends, trims, and truncates to max runes.
//
// The Windows neutralization is load-bearing, not cosmetic. beeep's toast path
// (git.sr.ht/~jackmordaunt/go-toast) interpolates the title/body into TWO
// unescaped sinks:
//
//   - an XML CDATA section (`<text><![CDATA[{{.Title}}]]></text>`), where the
//     literal `]]>` closes the CDATA and injects arbitrary toast XML into
//     doc.LoadXml; and
//   - a PowerShell **expandable** here-string (`$template = @"…"@`) on the
//     COM-unavailable fallback, where `$(…)` runs a subexpression (arbitrary
//     command execution), `$name` expands a variable, and a backtick is the
//     escape character.
//
// We cannot inject escaping into beeep's own pipeline, so we neutralize on the
// way in. This is a complete handling of both sink grammars — CDATA has exactly
// one terminator, and a PowerShell here-string has exactly two active
// metacharacters (`$` and backtick) — not a best-effort blocklist. macOS
// (osascript via fmt.Sprintf %q) and Linux (D-Bus method call / notify-send
// argv) do not interpolate into an evaluated context, so this transform is
// aimed at the Windows sinks; it is applied unconditionally because a message
// validated on one host may be delivered on another (a headless peer posts to
// a Windows workstation).
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
	out := neutralizeToastMetachars(b.String())
	out = strings.TrimSpace(out)
	if len([]rune(out)) > max {
		out = string([]rune(out)[:max])
		out = strings.TrimSpace(out)
	}
	return out
}

// neutralizeToastMetachars defuses the CDATA terminator and PowerShell
// here-string metacharacters described in sanitize's doc comment, keeping the
// text otherwise verbatim.
func neutralizeToastMetachars(s string) string {
	// CDATA: break the only sequence that can close a CDATA section.
	s = strings.ReplaceAll(s, "]]>", "]] >")
	// PowerShell here-string: the backtick is the escape/line-continuation
	// character; render it as an apostrophe.
	s = strings.ReplaceAll(s, "`", "'")
	// PowerShell here-string: a `$` immediately followed by any non-space
	// character can start an expansion — `$(cmd)` (subexpression → command
	// execution), `${name}`/`$name`/`$5`/`$$` (variable expansion). Inserting
	// a space after such a `$` makes it a literal dollar sign and leaves the
	// following text inert, while preserving a trailing/space-separated `$`
	// (e.g. "cost: $").
	var b strings.Builder
	b.Grow(len(s) + 8)
	runes := []rune(s)
	for i, r := range runes {
		b.WriteRune(r)
		if r == '$' && i+1 < len(runes) && runes[i+1] != ' ' {
			b.WriteRune(' ')
		}
	}
	return b.String()
}

// Notifier delivers a validated Message. Send is the real implementation;
// the web server and tests inject their own.
type Notifier func(Message) error

// Send delivers msg via the platform's native notification mechanism. It is
// the default Notifier. A level's urgency selects an audible alert (error /
// attention) or a normal notification (info / warning), and on platforms that
// accept a named stock icon the level's icon is shown. When msg carries an
// ActionURL, delivery is platform-specific (see platformDeliver): a clickable
// toast on Windows, the URL appended to the body elsewhere.
func Send(msg Message) error {
	beeep.AppName = appName
	return platformDeliver(msg)
}

// beeepDeliver is the shared beeep call: an audible Alert for urgent levels, a
// quiet Notify otherwise. Both platform deliverers route their non-clickable
// path through here so the urgency mapping lives in one place.
func beeepDeliver(urgent bool, title, body, icon string) error {
	if urgent {
		return beeep.Alert(title, body, icon)
	}
	return beeep.Notify(title, body, icon)
}

// actionBody returns the body to show when the platform cannot make the action
// URL clickable: the URL appended to the body (space-separated, single line —
// the sanitize contract keeps notifications single-line) so it stays visible
// and copyable. With no action URL, or no room, it degrades sensibly.
func actionBody(msg Message) string {
	if msg.ActionURL == "" {
		return msg.Body
	}
	if msg.Body == "" {
		return msg.ActionURL
	}
	return msg.Body + " " + msg.ActionURL
}

// safeToastArgs encodes an action URL for safe interpolation into go-toast's
// unescaped `launch="…"` XML attribute (the Windows clickable path). The
// attribute-breaking characters `& " < >` are XML-escaped, so Windows decodes
// them back to the real character when it parses the toast — crucially keeping
// `&` query separators intact (percent-encoding `&` would merge query params).
// The PowerShell here-string fallback expands `$` and a backtick BEFORE the XML
// is parsed, which XML-escaping cannot prevent, so those two are percent-encoded
// instead (a browser decodes %24/%60 to the same URL). Kept in this
// (non-build-tagged) file so it is unit-tested on every platform even though the
// toast push itself is Windows-only.
func safeToastArgs(u string) string {
	u = strings.NewReplacer(
		"&", "&amp;",
		`"`, "&quot;",
		"<", "&lt;",
		">", "&gt;",
	).Replace(u)
	return strings.NewReplacer("$", "%24", "`", "%60").Replace(u)
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
	// The GOOS set matches beeep's own unix notification backend build tag
	// (linux || freebsd || netbsd || openbsd || illumos), where the icon is a
	// D-Bus app_icon / notify-send -i that accepts a stock name. On every
	// other platform a string icon is a file path, so pass none.
	switch runtime.GOOS {
	case "linux", "freebsd", "netbsd", "openbsd", "illumos":
		return levelTable[level].stockIcon
	default:
		return ""
	}
}
