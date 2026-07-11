package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
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

// (browse and notify share the launcher plumbing in launcher.go.)

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
	u, err := ValidateBrowseURL(r.PostFormValue("url"))
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := u.String()

	// Log lines carry scheme+hostname only, at every level: query strings
	// and even path segments can be capability-bearing (signed links, OAuth
	// codes, reset tokens), and the never-log-secrets posture applies even
	// at DEBUG. The requester already knows the URL it posted, so nothing
	// is lost for troubleshooting.
	host := u.Hostname()
	slog.Debug("remote browse requested", "scheme", u.Scheme, "host", host)

	// Single-flight gate + bounded wait + panic recovery, shared with the
	// other remote-launch endpoints (see guardedLaunch). A launcher that
	// hangs is abandoned but cannot pile up goroutines; concurrent requests
	// fail fast and the CLI treats the non-200 like any other peer failure.
	timedOut, err := guardedLaunch(&s.browseOpenMu, browseOpenTimeout, func() error {
		return s.openBrowser(target)
	})
	switch {
	case errors.Is(err, errLauncherBusy):
		writeError(w, "a browser open is already in progress; try again shortly", http.StatusServiceUnavailable)
		return
	case timedOut:
		slog.Warn("remote browse timed out waiting for the browser opener",
			"scheme", u.Scheme, "host", host)
		writeError(w, "timed out waiting for the browser opener (the URL may still open)", http.StatusBadGateway)
		return
	case err != nil:
		// Some openers embed their argument in the error text; scrub the
		// target so the no-full-URL log invariant holds even then. The
		// unredacted error still goes back in the response — the requester
		// already knows the URL it posted.
		redacted := strings.ReplaceAll(err.Error(), target, "<url>")
		slog.Warn("remote browse failed to open browser",
			"scheme", u.Scheme, "host", host, "error", redacted)
		writeError(w, fmt.Sprintf("failed to open browser: %v", err), http.StatusBadGateway)
		return
	}
	slog.Info("opened browser via remote browse API", "scheme", u.Scheme, "host", host)
	writeJSON(w, map[string]any{"status": "browser opened"})
}

// originAllowed reports whether an Origin header value names this daemon's
// own origin — a loopback hostname (the same allowlist the Host check
// applies) AND the daemon's own listener port. The port matters here in a
// way it doesn't for the Host check: a request's Host names the listener it
// actually arrived on, but an Origin names whichever server served the page,
// and a hostname-only check would let a page from any other loopback-served
// origin (http://127.0.0.1:12345 — some other local app's UI rendering
// untrusted content) drive this endpoint. Only the SPA's own origin passes;
// everything else (including the literal "null" sent by sandboxed iframes
// and privacy-redirects) is rejected.
func (s *Server) originAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	// u.Hostname() strips the port and any IPv6 brackets, matching what
	// loopbackHostname expects.
	if !s.loopbackHostname(u.Hostname()) {
		return false
	}

	// Prefer the bound address (authoritative once Start has run — it
	// carries the real port when the configured one was 0 or fell back);
	// the configured listen address covers the pre-Start window. No known
	// port (possible only for a hand-constructed Server in tests) degrades
	// to the hostname-only check.
	listen := s.listenAddr
	if listen == "" {
		listen = s.cfg.Listen
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil || listenPort == "" {
		return true
	}
	originPort := u.Port()
	if originPort == "" {
		// An Origin without an explicit port is at the scheme default.
		switch strings.ToLower(u.Scheme) {
		case "http":
			originPort = "80"
		case "https":
			originPort = "443"
		}
	}
	return originPort == listenPort
}

// ValidateBrowseURL enforces the remote-browse allowlist: the value must
// parse as an absolute http or https URL with a host and no embedded
// credentials. Everything else — file://, custom protocol handlers (vscode:,
// ssh:), scheme-relative or bare paths, user:pass@ forms — is rejected,
// because the browser opener hands the string to xdg-open / `open` /
// ShellExecute, which would happily dispatch non-web schemes to arbitrary
// local handlers, and userinfo would carry credentials into the opener and
// its logs. Returns the parsed URL so callers never re-parse (the canonical
// string form is u.String()).
func ValidateBrowseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing url form value")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme %q (only http and https are allowed)", u.Scheme)
	}
	// Hostname() rather than Host: "http://:80" has a non-empty Host but no
	// actual hostname, and must be rejected like any other host-less form.
	if u.Hostname() == "" {
		return nil, errors.New("url has no host")
	}
	if u.User != nil {
		return nil, errors.New("url must not contain embedded credentials")
	}
	return u, nil
}
