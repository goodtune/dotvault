package config

import (
	"fmt"
	"time"
)

// SlackReservedFields are the field names the slack engine writes beside its
// workspace fields, so no workspace may be named after one.
var SlackReservedFields = []string{"issued_at", "expires_at"}

// DefaultSlackRefreshInterval is how long a slack enrolment's minted tokens
// are treated as valid; the RefreshManager re-mints past half of it.
const DefaultSlackRefreshInterval = 24 * time.Hour

// minSlackRefreshInterval keeps a misconfigured enrolment from re-minting
// every workspace (one page load each) every few minutes.
const minSlackRefreshInterval = time.Hour

// SlackWorkspaces returns a slack enrolment's workspaces setting: the Slack
// subdomains (acme for acme.slack.com) it enrols, each also the name of its
// field in the secret. It is the one definition of the setting, shared by
// config load and the engine. At least one is required; a name must be a
// valid subdomain, unique, and not one of SlackReservedFields.
func SlackWorkspaces(settings map[string]any) ([]string, error) {
	raw, ok := settings["workspaces"]
	if !ok {
		return nil, fmt.Errorf("workspaces is required: the Slack subdomains to enrol, e.g. [acme] for acme.slack.com")
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspaces must be a list of Slack subdomains, got %T", raw)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("workspaces must name at least one Slack subdomain")
	}
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("workspaces entries must be strings, got %T", v)
		}
		if err := ValidSlackSubdomain(s); err != nil {
			return nil, fmt.Errorf("workspaces entry %q: %w", s, err)
		}
		for _, r := range SlackReservedFields {
			if s == r {
				return nil, fmt.Errorf("workspaces entry %q is reserved for the engine's own bookkeeping", s)
			}
		}
		if seen[s] {
			return nil, fmt.Errorf("workspaces entry %q is listed twice", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// ValidSlackSubdomain applies Slack's workspace URL rule: lowercase letters,
// digits and hyphens, 1–63 bytes, no leading or trailing hyphen. Being a
// single DNS label is also what makes it safe to put in a URL host: the slack
// engine re-checks it on every domain it is about to send a cookie to.
func ValidSlackSubdomain(s string) error {
	if s == "" || len(s) > 63 {
		return fmt.Errorf("must be 1-63 characters")
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return fmt.Errorf("must not start or end with '-'")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("must contain only a-z, 0-9 and '-' (the part before .slack.com)")
		}
	}
	return nil
}

// SlackRefreshInterval returns a slack enrolment's refresh_interval setting:
// how long minted tokens are treated as valid (default 24h, minimum 1h).
func SlackRefreshInterval(settings map[string]any) (time.Duration, error) {
	raw, ok := settings["refresh_interval"]
	if !ok {
		return DefaultSlackRefreshInterval, nil
	}
	s, ok := raw.(string)
	if !ok {
		return 0, fmt.Errorf("refresh_interval must be a duration string, got %T", raw)
	}
	d, err := ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("refresh_interval %q: %w", s, err)
	}
	if d < minSlackRefreshInterval {
		return 0, fmt.Errorf("refresh_interval %q is below the 1h minimum", s)
	}
	return d, nil
}
