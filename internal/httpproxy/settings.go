package httpproxy

import (
	"fmt"
	"net/http"
	"time"
)

// SettingsKeys is the list of YAML map keys that carry a proxy URL in
// an enrolment engine's settings block. Both names are accepted as
// aliases: dotvault's HTTP-based engines only ever talk HTTPS, and
// YAML authors reach for whichever name matches their mental model.
// The first non-empty value wins, and lookup order is fixed for
// deterministic precedence (https_proxy > http_proxy).
var SettingsKeys = []string{"https_proxy", "http_proxy"}

// OverrideFromSettings extracts a manually-configured proxy URL from
// an engine's settings map, applying SettingsKeys in order. Returns
// ("", nil) when no override is configured; returns an error if a
// matching key holds a non-string value.
func OverrideFromSettings(settings map[string]any) (string, error) {
	for _, key := range SettingsKeys {
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

// ClientFromSettings is the convenience entry point engines use to
// build their outbound HTTP client. When the settings carry an
// https_proxy / http_proxy override every request is pinned to that
// URL; otherwise the host's native proxy machinery resolves on a
// per-request basis (System()).
//
// Lifts the per-engine plumbing out of internal/enrol so JFrog, the
// Vault client, and future HTTP-talking packages share one source of
// truth for the YAML key contract.
func ClientFromSettings(settings map[string]any, timeout time.Duration) (*http.Client, error) {
	override, err := OverrideFromSettings(settings)
	if err != nil {
		return nil, err
	}
	resolver := System()
	if override != "" {
		resolver, err = Static(override)
		if err != nil {
			return nil, err
		}
	}
	return NewClient(resolver, timeout), nil
}
