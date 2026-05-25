package enrol

import (
	"fmt"
	"net/http"
	"time"

	"github.com/goodtune/dotvault/internal/httpproxy"
)

// engineProxyOverride extracts a manually-configured proxy URL from an
// engine's settings map. Both `https_proxy` and `http_proxy` are
// accepted as aliases — the GitHub OAuth device flow and our other
// engines only ever talk HTTPS, and YAML authors reach for whichever
// name matches their mental model. The first non-empty value wins.
//
// Returns ("", nil) when neither key is present or both are empty.
func engineProxyOverride(settings map[string]any) (string, error) {
	for _, key := range []string{"https_proxy", "http_proxy"} {
		raw, ok := settings[key]
		if !ok {
			continue
		}
		s, ok := raw.(string)
		if !ok {
			return "", fmt.Errorf("invalid %s setting: expected string, got %T", key, raw)
		}
		if s != "" {
			return s, nil
		}
	}
	return "", nil
}

// engineHTTPClient builds the HTTP client engines use for outbound
// calls (OAuth device flow, REST polling, refresh requests). When
// settings carry an https_proxy/http_proxy override every request is
// pinned to that proxy; otherwise the host's native proxy machinery
// resolves on a per-request basis (system PAC on Windows, environment
// variables elsewhere).
func engineHTTPClient(settings map[string]any, timeout time.Duration) (*http.Client, error) {
	override, err := engineProxyOverride(settings)
	if err != nil {
		return nil, err
	}
	resolver := httpproxy.System()
	if override != "" {
		resolver, err = httpproxy.Static(override)
		if err != nil {
			return nil, err
		}
	}
	return httpproxy.NewClient(resolver, timeout), nil
}
