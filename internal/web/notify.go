package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/goodtune/dotvault/internal/notify"
)

// notifyBodyLimit caps the request body for the remote-notify endpoint — a
// few short form fields (level, title, body). The cap guards against a
// misbehaving peer streaming an unbounded body; notify.NewMessage separately
// truncates the individual fields to notification-sized lengths.
const notifyBodyLimit = 1 << 16 // 64 KiB

// notifySendTimeout bounds how long the handler waits for the notification
// backend. Delivery shells out to a launcher (D-Bus / notify-send / osascript
// / PowerShell) that can block, and this bound — like the browse endpoint's —
// sits below the CLI's client-side POST timeout so the caller gets a
// diagnosable error rather than a generic timeout. A hung backend is
// abandoned (not killed) on timeout.
const notifySendTimeout = 8 * time.Second

// handleRemoteNotify accepts a form POST carrying level/title/body and raises
// a native desktop notification on this host. It is the sibling of
// handleRemoteBrowse: over the same SSH-forwarded socket a headless peer (or
// `dotvault notify`) surfaces a toast/notification on the workstation, which
// is where a human is actually looking:
//
//	curl --unix-socket ~/.ssh/dotvault.sock http://localhost/api/v1/remote/notify \
//	     -d level=error -d title='Backup failed' -d body='see the logs'
//
// The CSRF/Origin posture is identical to handleRemoteBrowse (see its comment
// for the full rationale): deliberately not CSRF-protected because the
// consumer is a bare curl/CLI form POST over a forwarded socket, with
// cross-site browser traffic rejected by the Origin check instead. The
// input-validation control here is notify.NewMessage, which restricts the
// level to a known set and strips control characters from the title/body so
// nothing injects into the exec/XML/AppleScript delivery backends.
func (s *Server) handleRemoteNotify(w http.ResponseWriter, r *http.Request) {
	if s.sendNotification == nil {
		writeError(w, "notifications not available", http.StatusServiceUnavailable)
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
		writeError(w, "cross-site requests are not allowed", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, notifyBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid form body", http.StatusBadRequest)
		return
	}
	// PostFormValue: the contract is a form POST — query-string fields are
	// deliberately ignored, matching the browse endpoint.
	msg, err := notify.NewMessage(r.PostFormValue("level"), r.PostFormValue("title"), r.PostFormValue("body"))
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log the level and the title length only — never the title/body text,
	// which is arbitrary user content that may name secret paths or systems
	// (the same never-log-content posture the browse endpoint applies to
	// URLs). The requester already knows what it sent.
	slog.Debug("remote notify requested", "level", msg.Level, "title_len", len(msg.Title), "body_len", len(msg.Body))

	// Shared single-flight + bounded wait + panic recovery (guardedLaunch).
	timedOut, err := guardedLaunch(&s.notifyMu, notifySendTimeout, func() error {
		return s.sendNotification(msg)
	})
	switch {
	case errors.Is(err, errLauncherBusy):
		writeError(w, "a notification is already being delivered; try again shortly", http.StatusServiceUnavailable)
		return
	case timedOut:
		slog.Warn("remote notify timed out waiting for the notification backend", "level", msg.Level)
		writeError(w, "timed out delivering the notification (it may still appear)", http.StatusBadGateway)
		return
	case err != nil:
		slog.Warn("remote notify failed to deliver", "level", msg.Level, "error", err)
		writeError(w, fmt.Sprintf("failed to deliver notification: %v", err), http.StatusBadGateway)
		return
	}
	slog.Info("delivered notification via remote notify API", "level", msg.Level)
	writeJSON(w, map[string]any{"status": "notification delivered"})
}
