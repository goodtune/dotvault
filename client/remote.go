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
// required; body is optional. The level and text are validated and sanitized
// authoritatively by the peer endpoint (the same neutralization the daemon
// applies before delivery), so a bad level or empty title comes back as a
// plain (uncategorised) error carrying the peer's message. A peer that cannot
// be reached, or that reports it could not deliver, wraps ErrPeerUnavailable.
func (c *Client) Notify(ctx context.Context, level, title, body string) error {
	return c.peerAction(ctx, "notify", "/api/v1/remote/notify", url.Values{
		"level": {level},
		"title": {title},
		"body":  {body},
	})
}

// peerAction posts a peer-action form to apiPath over the configured
// TokenSocket and maps the shared transport's typed errors onto the facade's
// taxonomy: a 400 (the peer rejected the request as invalid) stays a plain
// error so callers see the peer's message without treating it as a transient
// availability problem; everything else — no socket configured, unreachable
// peer, or a non-400 non-200 — wraps ErrPeerUnavailable.
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
	if errors.As(err, &se) && se.Status == 400 {
		// The peer validated the request and rejected it as malformed (bad
		// URL, unknown level, empty title). That is a caller error, not an
		// availability problem — surface it plainly with the peer's message.
		return fmt.Errorf("dotvault: peer rejected %s request: %s", action, se.Message)
	}
	return fmt.Errorf("%w: %s: %w", ErrPeerUnavailable, action, err)
}
