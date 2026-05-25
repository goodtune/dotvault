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
// PAC-style per-URL routing is not applied to a Static resolver — the
// override is a deliberate "use this proxy" instruction. Callers that
// want host-conditional routing should fall back to System() instead.
func Static(override string) (func(*http.Request) (*url.URL, error), error) {
	u, err := url.Parse(override)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy URL missing host: %q", override)
	}
	return http.ProxyURL(u), nil
}
