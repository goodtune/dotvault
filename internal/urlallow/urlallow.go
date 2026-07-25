// Package urlallow is the single source of truth for the URL allowlist dotvault
// applies before handing a URL to an OS opener or a notification backend: an
// absolute http or https URL with a real host and no embedded credentials.
//
// It exists so the two surfaces that gate a URL against an OS action — the
// remote-browse endpoint (internal/web) and the notification action link
// (internal/notify) — enforce byte-for-byte the same rule from one
// implementation. internal/web imports internal/notify, so notify could not
// import web to reuse its validator; a shared leaf package both import breaks
// that would-be cycle and keeps the "same allowlist" invariant the docs
// advertise actually enforced rather than duplicated.
package urlallow

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Validate enforces the allowlist: the value must parse as an absolute http or
// https URL with a host and no embedded user:pass@ credentials. Everything else
// — file://, custom protocol handlers (vscode:, ssh:), javascript:/data:,
// scheme-relative or bare paths, userinfo forms — is rejected, because the URL
// is handed to an OS opener (xdg-open / `open` / ShellExecute) or a native
// notification backend, which would otherwise dispatch a non-web scheme to an
// arbitrary local handler or carry credentials into the launcher and its logs.
// It returns the parsed URL so callers never re-parse (the canonical string
// form is u.String(), which lowercases the scheme and percent-encodes hostile
// characters). A leading/trailing space is trimmed; an empty input is an error.
func Validate(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("missing url")
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
