package httpproxy

import (
	"fmt"
	"net/http"
	"net/url"
)

// Static parses override into a per-request proxy resolver that always
// returns the same URL, regardless of the target host. Intended for the
// case where the caller has been explicitly told which proxy to use
// (e.g. a `https_proxy:` YAML setting pinning a corporate Squid).
//
// Accepted schemes are http, https, socks5, and socks5h — the same set
// http.Transport will actually dial. Schemeless or unsupported-scheme
// inputs error out at configuration time so a misconfigured proxy
// surfaces before the first outbound request.
//
// PAC-style per-URL routing is not applied to a Static resolver — the
// override is a deliberate "use this proxy" instruction. Callers that
// want host-conditional routing should fall back to System() instead.
func Static(override string) (func(*http.Request) (*url.URL, error), error) {
	u, err := url.Parse(override)
	if err != nil {
		// url.Parse rejects truly malformed input. The error string
		// includes the raw input via %q, so it's safe to wrap as-is
		// here because we got nothing back to redact from.
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("proxy URL missing scheme: %s", redactedString(u))
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
		// supported
	default:
		return nil, fmt.Errorf("proxy URL scheme %q not supported (want http, https, socks5, socks5h)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy URL missing host: %s", redactedString(u))
	}
	return http.ProxyURL(u), nil
}

// redactedString renders a parsed proxy URL with any embedded userinfo
// stripped so error messages cannot leak a password supplied via
// http://user:pass@proxy:3128. Returns the URL in its standard form
// otherwise.
func redactedString(u *url.URL) string {
	if u.User == nil {
		return u.String()
	}
	clone := *u
	clone.User = url.User(u.User.Username())
	return clone.String()
}
