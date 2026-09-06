package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/goodtune/dotvault/internal/auth"
)

// Browse asks the peer dotvault named by the configured TokenSocket to open
// rawURL in a browser on the peer's host — the programmatic equivalent of
// `dotvault browse <url>` and of
//
//	curl --unix-socket <TokenSocket> http://localhost/api/v1/remote/browse -d url=<rawURL>
//
// It is for the headless-consumer topology: a program on a machine with no
// browser hands a URL back over the same SSH-forwarded socket it borrows its
// token from, so a browser-driven flow (an OAuth page, a report link) opens on
// the workstation where a human is looking. Unlike `dotvault browse`, the
// facade has no local fallback — a library on a headless box has no local
// browser to fall back to — so a peer that cannot be reached is an error, not
// a silent local open.
//
// The URL is validated authoritatively by the peer endpoint (http/https only,
// a host, no embedded credentials); a rejected URL comes back as a plain
// (uncategorised) error carrying the peer's message. A peer that cannot be
// reached, or that reports it could not open the browser, wraps
// ErrPeerUnavailable. Returns nil once the peer reports the browser opened.
func (c *Client) Browse(ctx context.Context, rawURL string) error {
	return c.peerAction(ctx, "browse", "/api/v1/remote/browse", url.Values{"url": {rawURL}})
}

// Notify asks the peer dotvault named by the configured TokenSocket to raise a
// native desktop notification on the peer's host — the programmatic equivalent
// of `dotvault notify <level> <title> [body]`. It is the notification sibling
// of Browse over the same socket: a long-running job on a headless box surfaces
// a toast/notification on the workstation.
//
// level must be one of "info", "warning", "error", "attention"; title is
// required; body and actionURL are optional. actionURL, when set, is an
// http/https link the notification takes the user to when clicked — clickable
// on Windows, appended to the body on macOS/Linux (see the notify docs). The
// level, text, and action URL are validated and sanitized authoritatively by
// the peer endpoint (the same neutralization the daemon applies before
// delivery), so a bad level, empty title, or malformed action URL comes back
// as a plain (uncategorised) error carrying the peer's message. A peer that
// cannot be reached, or that reports it could not deliver, wraps
// ErrPeerUnavailable.
func (c *Client) Notify(ctx context.Context, level, title, body, actionURL string) error {
	form := url.Values{
		"level": {level},
		"title": {title},
		"body":  {body},
	}
	if actionURL != "" {
		form.Set("action_url", actionURL)
	}
	return c.peerAction(ctx, "notify", "/api/v1/remote/notify", form)
}

// Clipboard asks the peer dotvault named by the configured TokenSocket to put
// text on the clipboard of the peer's host — the programmatic equivalent of
// `dotvault clipboard` and the third peer action over the same socket. Where
// Browse opens a login page on the workstation and Notify tells the user
// something happened, Clipboard delivers the value they need to paste — a
// one-time token, a device code — so a headless program can stage the
// credential right where the user's Ctrl+V is. Like the other peer actions
// there is no local fallback: an unreachable peer is an error, never a write
// to the headless host's (typically non-existent) clipboard.
//
// The text is validated authoritatively by the peer endpoint (non-empty,
// valid UTF-8, no NUL bytes, at most 64 KiB) and written verbatim — the peer
// never logs the content, only its length. A rejected text comes back as a
// plain (uncategorised) error carrying the peer's message. A peer that cannot
// be reached, or that reports it could not write the clipboard, wraps
// ErrPeerUnavailable. Returns nil once the peer reports the clipboard set.
func (c *Client) Clipboard(ctx context.Context, text string) error {
	return c.peerAction(ctx, "clipboard", "/api/v1/remote/clipboard", url.Values{"text": {text}})
}

// peerAction posts a peer-action form to apiPath over the configured
// TokenSocket and maps the shared transport's typed errors onto the facade's
// taxonomy:
//
//   - no socket configured, or the peer could not be contacted at all
//     (ErrPeerUnreachable) → ErrPeerUnavailable (retryable availability);
//   - the peer answered 5xx (it reached the action but could not complete it —
//     a 502 opener failure, a 503 "busy, try again") → ErrPeerUnavailable;
//   - any other non-200 (a 4xx: the peer rejected the request as invalid —
//     bad URL, unknown level, empty title) → a plain uncategorised error
//     carrying the peer's message, since that is a caller error to fix, not a
//     transient condition to retry.
//
// Keying availability on the 5xx class (rather than singling out 400) keeps a
// future 4xx the endpoint might grow — a 403, 405, 415 — correctly classified
// as a permanent request error rather than a retryable one.
func (c *Client) peerAction(ctx context.Context, action, apiPath string, form url.Values) error {
	socket := c.cfg.Vault.TokenSocket
	if socket == "" {
		return fmt.Errorf("%w: no peer socket configured (set vault.token_socket)", ErrPeerUnavailable)
	}
	err := auth.PostFormToPeer(ctx, socket, apiPath, form)
	if err == nil {
		return nil
	}
	var se *auth.PeerStatusError
	if errors.As(err, &se) && se.Status < 500 {
		return fmt.Errorf("dotvault: peer rejected %s request: %s", action, se.Message)
	}
	return fmt.Errorf("%w: %s: %w", ErrPeerUnavailable, action, err)
}
