package config

import (
	"fmt"
	"strings"
)

// SlackWorkspaces returns a slack enrolment's workspaces setting: the Slack
// subdomains (acme for acme.slack.com, acme.enterprise for an Enterprise
// Grid organisation) it enrols, each also the name of its
// field in the secret. It is the one definition of the setting, shared by
// config load and the engine. At least one is required; a name must be a
// valid subdomain and unique.
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
		if seen[s] {
			return nil, fmt.Errorf("workspaces entry %q is listed twice", s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// ValidSlackSubdomain applies Slack's workspace URL rule to what goes in
// front of .slack.com: one label (lowercase letters, digits and hyphens, 1–63
// bytes, no leading or trailing hyphen), optionally followed by ".enterprise"
// for an Enterprise Grid organisation (acme.enterprise for
// acme.enterprise.slack.com). Allowing exactly that is also what makes it
// safe for slk to put in a URL host in front of .slack.com.
func ValidSlackSubdomain(s string) error {
	label := strings.TrimSuffix(s, ".enterprise")
	if label == "" || len(label) > 63 {
		return fmt.Errorf("must be 1-63 characters, optionally followed by .enterprise for Enterprise Grid")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("must not start or end with '-'")
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("must contain only a-z, 0-9 and '-' (the part before .slack.com), plus .enterprise for Enterprise Grid")
		}
	}
	return nil
}
