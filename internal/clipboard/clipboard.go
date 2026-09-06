// Package clipboard puts text on the system clipboard — macOS pasteboard,
// Windows clipboard, X11/Wayland selection.
//
// It is the delivery half of the remote-clipboard feature: the web API's
// POST /api/v1/remote/clipboard handler and the `dotvault clipboard` CLI both
// validate the text and hand it to a Setter, so a headless peer can place a
// value (typically a token needed to authenticate to a page opened via remote
// browse) on the workstation's clipboard over the same forwarded socket that
// carries the token borrow, remote browse, and remote notify. The enrolment
// wizard's best-effort device-code copy uses the same writers.
//
// Unlike internal/notify there is no sanitization: clipboard content is data,
// never interpolated into an evaluated context — the platform writers hand it
// to a tool's stdin (pbcopy, wl-copy, xclip, xsel) or place it in clipboard
// memory via the Win32 API (CF_UNICODETEXT) — and the typical payload is a
// credential that must arrive byte-for-byte intact. Set writes verbatim;
// ValidateText only rejects input no clipboard can faithfully carry (interior
// NULs, invalid UTF-8) or that signals a caller bug (empty, oversized).
//
// Writers stay CGO_ENABLED=0: exec-based on the Unix platforms, plain
// syscalls via golang.org/x/sys/windows on Windows.
package clipboard

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxTextLen caps the accepted text at 64 KiB. Clipboard payloads are tokens,
// passwords, at most a PEM block — the cap keeps a hostile or buggy peer from
// pushing megabytes into clipboard managers (which often persist history to
// disk) while leaving generous headroom for every legitimate use.
const MaxTextLen = 1 << 16 // 64 KiB

// Setter writes text to the system clipboard. Set is the real implementation;
// the web server and tests inject their own.
type Setter func(text string) error

// ValidateText rejects text no clipboard write can carry faithfully or that
// signals a caller bug. Empty text is rejected (a missing form field is far
// more likely than an intent to clear the clipboard); an interior NUL would
// silently truncate the value on paste (CF_UNICODETEXT and the X11/Wayland
// selections are NUL-terminated at the consumer); invalid UTF-8 cannot be
// re-encoded for the Windows clipboard. Error messages never include the text
// itself — it is typically a credential and must stay out of logs and error
// chains (the same never-log-content posture the remote-browse URL handling
// applies).
func ValidateText(text string) error {
	if text == "" {
		return errors.New("clipboard text must not be empty")
	}
	if len(text) > MaxTextLen {
		return fmt.Errorf("clipboard text exceeds the %d-byte limit", MaxTextLen)
	}
	if strings.ContainsRune(text, 0) {
		return errors.New("clipboard text must not contain NUL bytes")
	}
	if !utf8.ValidString(text) {
		return errors.New("clipboard text must be valid UTF-8")
	}
	return nil
}

// Set writes text to the system clipboard verbatim. It is the default Setter.
// The text is validated first (see ValidateText) so no platform writer ever
// sees input it would corrupt. Errors never include the text.
func Set(text string) error {
	if err := ValidateText(text); err != nil {
		return err
	}
	return platformSet(text)
}
