package config

import (
	"fmt"
	"log/slog"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Partial is the restricted configuration document a remote configuration
// service delivers: the dynamic sections only. It is both the client-side
// wire format (fetched and merged over the local base via ApplyPartial) and
// the service-side layer format (global / os / group / user layers are
// Partials composed with MergePartial).
type Partial struct {
	Sync       *SyncConfig          `yaml:"sync,omitempty"`
	Rules      []Rule               `yaml:"rules,omitempty"`
	Enrolments map[string]Enrolment `yaml:"enrolments,omitempty"`
}

// partialStaticSections are the top-level keys that must never appear in a
// remote document. They are exclusively local: a remote service cannot
// redirect the Vault, open listeners, alter telemetry, grant itself a config
// bypass, or re-point the remote overlay itself. Their presence is a hard
// error rather than a warning because serving one means the service (or its
// layer author) believes it controls something it doesn't — silently
// dropping it would mask a real deployment mistake.
var partialStaticSections = []string{
	"agent",
	"bypass_system_config",
	"observability",
	"remote_config",
	"vault",
	"web",
}

// partialDynamicSections are the top-level keys ParsePartial understands.
var partialDynamicSections = map[string]bool{
	"sync":       true,
	"rules":      true,
	"enrolments": true,
}

// ParsePartial parses a partial configuration document, enforcing the wire
// contract: static sections are a hard error; unknown sections are ignored
// with a warning (forward compatibility — a newer server may serve sections
// an older daemon doesn't know about). The result is NOT validated; callers
// either run (*Partial).Validate (the service, at layer write/serve time) or
// merge into a Config and validate the merged result (the client).
func ParsePartial(data []byte) (*Partial, error) {
	var probe map[string]any
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse partial config: %w", err)
	}
	for _, key := range partialStaticSections {
		if _, ok := probe[key]; ok {
			return nil, fmt.Errorf("partial config: section %q is local-only and must not appear in a remote document", key)
		}
	}
	var unknown []string
	for key := range probe {
		if !partialDynamicSections[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		slog.Warn("partial config: ignoring unknown sections", "sections", unknown)
	}

	var p Partial
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse partial config: %w", err)
	}
	return &p, nil
}

// Validate applies the same per-entry checks the full config validation uses
// to the sections a Partial can carry. Defaults are NOT applied — a Partial
// is a fragment; defaulting happens when the merged Config validates.
func (p *Partial) Validate() error {
	if p.Sync != nil && p.Sync.RawInterval != "" {
		// time.ParseDuration, not the project ParseDuration: the merged
		// config's sync.interval is parsed with the stdlib form (see
		// Config.validate), so the fragment must accept exactly the same
		// grammar or a layer could validate here and fail on the client.
		if _, err := time.ParseDuration(p.Sync.RawInterval); err != nil {
			return fmt.Errorf("sync.interval %q: %w", p.Sync.RawInterval, err)
		}
	}
	seen := make(map[string]bool)
	for i, r := range p.Rules {
		if err := validateRule(i, r, seen); err != nil {
			return err
		}
	}
	for key, e := range p.Enrolments {
		if err := validateEnrolment(key, e); err != nil {
			return err
		}
	}
	return nil
}
