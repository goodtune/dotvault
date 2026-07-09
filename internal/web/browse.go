package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// browseBodyLimit caps the request body for the remote-browse endpoint. The
// payload is a single form-encoded URL; the limit just guards against a
// misbehaving peer streaming an unbounded body.
const browseBodyLimit = 1 << 16 // 64 KiB

// handleRemoteBrowse accepts a form POST carrying url=<target> and opens the
// target in this host's default browser. It is the outbound counterpart of
// GET /api/v1/token: where the token endpoint lets a headless peer borrow a
// credential from the workstation, this endpoint lets the headless peer hand
// a URL back to the workstation — over the same SSH-forwarded Unix socket —
// so browser-driven flows (OAuth device pages, docs links, `dotvault browse`
// as $BROWSER) land where an actual browser exists:
//
//	curl --unix-socket ~/.ssh/dotvault.sock http://localhost/api/v1/remote/browse -d url=https://example.com
//
// The endpoint is deliberately NOT CSRF-protected, unlike the other mutating
// routes. The documented consumer is a bare curl / `dotvault browse` form
// POST over a forwarded socket, which has no practical way to run the
// issue-then-spend CSRF handshake, and the CSRF calculus here is different
// from /api/v1/sync: the handler reads no state and returns nothing
// sensitive, and its only side effect — opening an http(s) URL in the user's
// default browser — is something any web page can already do to a visitor
// (window.open / a navigation) and any local process can do directly. The
// scheme allowlist below is what actually matters: it keeps a hostile page
// or peer from reaching non-web handlers (file://, custom protocol schemes)
// through xdg-open/ShellExecute. The middleware's loopback Host check still
// applies, as on every route.
func (s *Server) handleRemoteBrowse(w http.ResponseWriter, r *http.Request) {
	if s.openBrowser == nil {
		writeError(w, "browser launch not available", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, browseBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid form body", http.StatusBadRequest)
		return
	}
	target, err := ValidateBrowseURL(r.FormValue("url"))
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log the full URL: this endpoint lets a remote peer pop a browser on
	// this machine, so the operator gets an audit line naming exactly what
	// was opened. URLs are not treated as secrets (they are about to be
	// handed to a browser and its history anyway).
	if err := s.openBrowser(target); err != nil {
		slog.Warn("remote browse failed to open browser", "url", target, "error", err)
		writeError(w, fmt.Sprintf("failed to open browser: %v", err), http.StatusBadGateway)
		return
	}
	slog.Info("opened browser via remote browse API", "url", target)
	writeJSON(w, map[string]any{"status": "browser opened"})
}

// ValidateBrowseURL enforces the remote-browse scheme allowlist: the value
// must parse as an absolute http or https URL with a host. Everything else —
// file://, custom protocol handlers (vscode:, ssh:), scheme-relative or bare
// paths — is rejected, because the browser opener hands the string to
// xdg-open / `open` / ShellExecute, which would happily dispatch non-web
// schemes to arbitrary local handlers.
func ValidateBrowseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("missing url form value")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported url scheme %q (only http and https are allowed)", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("url has no host")
	}
	return u.String(), nil
}
