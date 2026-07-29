package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/clipboard"
)

// clipboardBodyLimit caps the request body for the remote-clipboard endpoint.
// The text itself is capped at clipboard.MaxTextLen (64 KiB), but the form
// encoding percent-escapes it — worst case three bytes per byte — so the body
// limit leaves room for a maximal payload plus field overhead rather than
// rejecting a legitimate one mid-decode.
const clipboardBodyLimit = 1 << 18 // 256 KiB

// clipboardSetTimeout bounds how long the handler waits for the clipboard
// writer. The Unix writers shell out to a tool (pbcopy / wl-copy / xclip)
// that can block on a broken display connection, and the Windows writer
// retries a held clipboard; like the browse/notify bounds this sits below the
// CLI's client-side POST timeout so the caller gets a diagnosable error. A
// hung writer is abandoned (not killed) on timeout.
const clipboardSetTimeout = 8 * time.Second

// handleRemoteClipboard accepts a form POST carrying text=<value> and places
// the value on this host's clipboard. It is the third peer action over the
// forwarded socket: remote browse opens a login page on the workstation,
// remote notify tells the user something happened, and remote clipboard puts
// the value they need to paste — a one-time token, a device code — where
// their Ctrl+V is:
//
//	curl --unix-socket ~/.ssh/dotvault.sock http://localhost/api/v1/remote/clipboard \
//	     -d text=s3cr3t-t0ken
//
// The CSRF/Origin posture is identical to handleRemoteBrowse (see its comment
// for the full rationale): deliberately not CSRF-protected because the
// consumer is a bare curl/CLI form POST over a forwarded socket, with
// cross-site browser traffic rejected by the Origin check instead. The input
// control is clipboard.ValidateText, which rejects input no clipboard write
// can carry faithfully (interior NULs, invalid UTF-8) or that signals a
// caller bug (empty, over 64 KiB); the text is otherwise written verbatim —
// clipboard content is data, never interpolated into an evaluated context, and
// the typical payload is a credential that must arrive byte-for-byte intact.
//
// The payload is the most secret-bearing of the three peer actions, so the
// never-log-content posture is absolute: log lines carry the text's length
// only, at every level, and even the error path scrubs the text from writer
// errors — both the log line and the HTTP response (unlike browse, which
// returns its opener error unredacted: a browse URL is something the caller
// may reasonably log, a clipboard value never is).
func (s *Server) handleRemoteClipboard(w http.ResponseWriter, r *http.Request) {
	if s.setClipboard == nil {
		writeError(w, "clipboard not available", http.StatusServiceUnavailable)
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
		writeError(w, "cross-site requests are not allowed", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, clipboardBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid form body", http.StatusBadRequest)
		return
	}
	// PostFormValue: the contract is a form POST — query-string fields are
	// deliberately ignored, matching browse and notify (and a URL is the last
	// place a secret should travel).
	text := r.PostFormValue("text")
	if err := clipboard.ValidateText(text); err != nil {
		// ValidateText error messages are content-free by contract.
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	slog.Debug("remote clipboard requested", "text_len", len(text))

	// Shared single-flight + bounded wait + panic recovery (guardedLaunch).
	timedOut, err := guardedLaunch(&s.clipboardMu, clipboardSetTimeout, func() error {
		return s.setClipboard(text)
	})
	switch {
	case errors.Is(err, errLauncherBusy):
		writeError(w, "a clipboard write is already in progress; try again shortly", http.StatusServiceUnavailable)
		return
	case timedOut:
		slog.Warn("remote clipboard timed out waiting for the clipboard writer", "text_len", len(text))
		writeError(w, "timed out writing to the clipboard (it may still be set)", http.StatusBadGateway)
		return
	case err != nil:
		// Scrub the text from the writer error before it reaches the log OR
		// the response: an exec-based writer could embed its stdin in an
		// error, and a clipboard value is a credential even to its sender's
		// own logs.
		redacted := strings.ReplaceAll(err.Error(), text, "<text>")
		slog.Warn("remote clipboard failed", "text_len", len(text), "error", redacted)
		writeError(w, fmt.Sprintf("failed to set clipboard: %s", redacted), http.StatusBadGateway)
		return
	}
	slog.Info("set clipboard via remote clipboard API", "text_len", len(text))
	writeJSON(w, map[string]any{"status": "clipboard set"})
}
