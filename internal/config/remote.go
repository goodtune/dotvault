package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// RemoteConfig configures the optional remote configuration overlay. When URL
// is set, the daemon (and the one-shot sync/status/enrol commands) fetch a
// partial configuration document — dynamic sections only: rules, enrolments,
// sync — from the remote service and merge it over the locally loaded base
// before validation. The section itself is local-only: ParsePartial rejects
// it inside a remote document, so a remote service can never re-point where
// configuration comes from.
//
// The inner fields deliberately do NOT carry `omitempty`, matching the
// round-trip contract documented on ObservabilityConfig: an exported config
// must re-emit cleared optional values so a re-import can blank them. The
// top-level RemoteConfig field on Config keeps `omitempty` so configs that
// don't use the overlay see no empty block in downloads.
type RemoteConfig struct {
	// URL is the remote configuration endpoint (e.g.
	// https://dotvault-config.example.com/v1/config). Empty disables the
	// overlay entirely. https is required unless the host is loopback /
	// localhost (local development).
	URL string `yaml:"url"`

	// RawRefreshInterval is how often a running daemon re-fetches the
	// document, as a duration string ("Nd" day shorthand accepted). Empty
	// defaults to the sync interval. Floor 1m. The parsed RefreshInterval
	// is populated only when URL is set — an inactive overlay never
	// influences the daemon's refresh cadence.
	RawRefreshInterval string        `yaml:"refresh_interval"`
	RefreshInterval    time.Duration `yaml:"-"`

	// CACert optionally pins the CA bundle used to verify the remote
	// service's TLS certificate. There is deliberately no skip-verify
	// option: configuration is not secret, but TLS integrity is the only
	// guarantee the client has that it is talking to the real service.
	CACert string `yaml:"ca_cert"`

	// Headers are extra dimension headers sent with every fetch (e.g.
	// X-Dotvault-Env: production). They cannot override the built-in
	// X-Dotvault-* identity headers.
	Headers map[string]string `yaml:"headers"`
}

// reservedRemoteHeaders are the identity headers the fetcher always sets;
// configured extras must not collide with them (case-insensitively, since
// HTTP header names fold case).
var reservedRemoteHeaders = []string{
	"X-Dotvault-OS",
	"X-Dotvault-User",
	"X-Dotvault-Arch",
	"X-Dotvault-Hostname",
	"X-Dotvault-Version",
}

func (r *RemoteConfig) validate() error {
	if r.URL != "" {
		u, err := url.Parse(r.URL)
		if err != nil {
			return fmt.Errorf("remote_config.url %q: %w", r.URL, err)
		}
		switch u.Scheme {
		case "https":
			// Always acceptable.
		case "http":
			if !isLoopbackHost(u.Hostname()) {
				return fmt.Errorf("remote_config.url %q: plain http is only permitted for loopback hosts (use https)", r.URL)
			}
		default:
			return fmt.Errorf("remote_config.url %q: scheme must be https (or http for a loopback host)", r.URL)
		}
		if u.Host == "" {
			return fmt.Errorf("remote_config.url %q: missing host", r.URL)
		}
	}

	// Parsed even when URL is empty so a typo'd interval doesn't hide until
	// the overlay is enabled — but only *applied* when a URL is configured:
	// without one the overlay is inactive and must not influence the
	// daemon's refresh cadence.
	if r.RawRefreshInterval != "" {
		d, err := ParseDuration(r.RawRefreshInterval)
		if err != nil {
			return fmt.Errorf("remote_config.refresh_interval %q: %w", r.RawRefreshInterval, err)
		}
		if d < time.Minute {
			return fmt.Errorf("remote_config.refresh_interval %q is below the 1m minimum", r.RawRefreshInterval)
		}
		if r.URL != "" {
			r.RefreshInterval = d
		}
	}

	// Same defence-in-depth as observability.headers: reject CR/LF/NUL (and
	// colon in names) so a configured header can't split the HTTP request.
	// Runs unconditionally so a config toggled on later starts sanitised.
	for k, v := range r.Headers {
		if strings.ContainsAny(k, "\r\n:\x00") {
			return fmt.Errorf("remote_config.headers: key %q must not contain CR, LF, NUL, or colon", k)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("remote_config.headers[%q]: value must not contain CR, LF, or NUL", k)
		}
		for _, reserved := range reservedRemoteHeaders {
			if strings.EqualFold(k, reserved) {
				return fmt.Errorf("remote_config.headers: %q is a built-in identity header and cannot be overridden", k)
			}
		}
	}

	return nil
}

// isLoopbackHost reports whether host is "localhost" or a literal loopback
// IP. Names that merely resolve to loopback are deliberately not honoured —
// the plain-http carve-out exists for local development, not for
// DNS-controlled downgrade of the integrity channel.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
