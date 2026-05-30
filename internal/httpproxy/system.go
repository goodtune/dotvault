//go:build !windows

package httpproxy

import (
	"net/http"
	"net/url"
)

// System returns a per-request proxy resolver that reads HTTP_PROXY,
// HTTPS_PROXY, and NO_PROXY (and their lowercase variants) from the
// process environment. On Linux this matches what corporate clients
// expect; on macOS it is a deliberate fallback in lieu of the native
// CFNetwork integration, which requires CGO.
func System() func(*http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment
}
