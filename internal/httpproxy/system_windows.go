package httpproxy

import (
	"net/http"
	"net/url"

	"github.com/mattn/go-ieproxy"
)

// System returns a per-request proxy resolver that honours the
// machine's Internet Explorer / WinHTTP configuration. PAC scripts are
// evaluated for every outbound request, so a policy that returns
// DIRECT for one host and a proxy for another is preserved.
//
// HTTP_PROXY-style environment variables, when set, still take
// precedence — go-ieproxy consults them first before falling back to
// the registry-driven settings.
func System() func(*http.Request) (*url.URL, error) {
	return ieproxy.GetProxyFunc()
}
