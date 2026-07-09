package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// browseBodyLimit caps the request body for the remote-browse endpoint. The
// payload is a single form-encoded URL; the limit just guards against a
// misbehaving peer streaming an unbounded body.
const browseBodyLimit = 1 << 16 // 64 KiB

// browseOpenTimeout bounds how long the handler waits for the browser opener.
// pkg/browser waits for the launcher process (xdg-open / `open` /
// ShellExecute) to exit, and a misconfigured launcher — e.g. a Linux session
// whose fallback resolves to a console browser — can block instead of
// erroring. The bound is deliberately below `dotvault browse`'s client-side
// POST timeout so the caller gets a diagnosable error from the peer rather
// than a generic timeout. On timeout the launcher keeps running (it cannot be
// safely killed mid-launch) and may still open the URL later; the error text
// says so because the CLI will have fallen back to a local open by then.
const browseOpenTimeout = 8 * time.Second

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
// routes: its documented consumer is a bare curl / `dotvault browse` form
// POST over a forwarded socket, which has no practical way to run the
// issue-then-spend CSRF handshake, and the handler reads no state and
// returns nothing sensitive. Cross-site browser traffic is instead rejected
// by the Origin check below — a hostile page's form/fetch POST is a CORS
// "simple request" that would sail through the loopback Host check, but
// browsers always attach an Origin header to cross-origin POSTs, and curl /
// the CLI send none. The remaining side-effect surface (a same-machine
// process opening a web URL) is something any local process can do directly.
// The scheme allowlist keeps non-web schemes (file://, custom protocol
// handlers) away from xdg-open/ShellExecute. The middleware's loopback Host
// check still applies, as on every route.
func (s *Server) handleRemoteBrowse(w http.ResponseWriter, r *http.Request) {
	if s.openBrowser == nil {
		writeError(w, "browser launch not available", http.StatusServiceUnavailable)
		return
	}

	// Reject browser-originated cross-site requests. A cross-origin form or
	// fetch POST always carries an Origin header naming the attacker's site
	// (or "null"); only an Origin naming this daemon's own loopback identity
	// — i.e. the SPA itself — is acceptable. Non-browser clients (curl,
	// `dotvault browse`) send no Origin header and pass.
	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
		writeError(w, "cross-site requests are not allowed", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, browseBodyLimit)
	if err := r.ParseForm(); err != nil {
		writeError(w, "invalid form body", http.StatusBadRequest)
		return
	}
	// PostFormValue: the contract is a form POST — a url in the query string
	// is deliberately ignored.
	target, err := ValidateBrowseURL(r.PostFormValue("url"))
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The INFO audit line carries scheme+host only; the full URL goes to
	// DEBUG. This endpoint lets a remote peer pop a browser here, so the
	// operator gets an audit trail — but URLs can be capability-bearing
	// (signed links, OAuth redirects), so the full string stays out of
	// default-level logs, consistent with the never-log-secrets posture.
	parsed, _ := url.Parse(target)
	slog.Debug("remote browse requested", "url", target)

	// Bounded wait: run the opener in a goroutine and give it
	// browseOpenTimeout to return. See the const's comment — the goroutine
	// (and launcher process) may outlive the request on timeout, which is
	// accepted over stranding the handler forever.
	errCh := make(chan error, 1)
	go func() { errCh <- s.openBrowser(target) }()
	timer := time.NewTimer(browseOpenTimeout)
	defer timer.Stop()
	select {
	case err := <-errCh:
		if err != nil {
			slog.Warn("remote browse failed to open browser",
				"scheme", parsed.Scheme, "host", parsed.Host, "error", err)
			writeError(w, fmt.Sprintf("failed to open browser: %v", err), http.StatusBadGateway)
			return
		}
	case <-timer.C:
		slog.Warn("remote browse timed out waiting for the browser opener",
			"scheme", parsed.Scheme, "host", parsed.Host)
		writeError(w, "timed out waiting for the browser opener (the URL may still open)", http.StatusBadGateway)
		return
	}
	slog.Info("opened browser via remote browse API", "scheme", parsed.Scheme, "host", parsed.Host)
	writeJSON(w, map[string]any{"status": "browser opened"})
}

// originAllowed reports whether an Origin header value names this daemon's
// own loopback identity — the same allowlist the Host check applies, so the
// SPA's own origin passes and everything else (including the literal "null"
// sent by sandboxed iframes and privacy-redirects) is rejected.
func (s *Server) originAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	// u.Hostname() strips the port and any IPv6 brackets, matching what
	// loopbackHostname expects.
	return s.loopbackHostname(u.Hostname())
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
