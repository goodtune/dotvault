package enrol

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ensureScheme prepends https:// if the URL has no scheme.
// The check is case-insensitive so that inputs like "HTTPS://host" are
// recognized as having a scheme rather than getting https:// prepended.
func ensureScheme(u string) string {
	lower := strings.ToLower(u)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return u
	}
	return "https://" + u
}

// normalizeBaseURL parses raw, enforces that it is a scheme+host-only URL (no
// path, query, or fragment), and returns the canonical string form. Engine
// API paths are concatenated directly onto this value, so any embedded path
// would route requests incorrectly and a query/fragment would appear verbatim
// in stored templates. A bare host gains an https:// scheme. name prefixes the
// error messages (e.g. "ghp", "jfrog") so callers don't have to re-wrap them.
func normalizeBaseURL(name, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%s url must not be empty", name)
	}
	u, err := url.Parse(ensureScheme(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s url: %w", name, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%s url must use http or https, got %q", name, raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s url must include a host: %q", name, raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s url must not include a query or fragment: %q", name, raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("%s url must be the base URL without a path (got %q)", name, raw)
	}
	return (&url.URL{Scheme: scheme, Host: u.Host}).String(), nil
}

// isLoopbackHost reports whether host (a URL hostname, no port) refers to the
// local machine. "localhost" is treated as loopback by convention; an IP
// literal is loopback when net's classification says so (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
