package config

import (
	"strings"
	"testing"
)

func TestParsePartialAcceptsDynamicSections(t *testing.T) {
	doc := []byte(`
sync:
  interval: 5m
rules:
  - name: aws
    vault_key: aws
    target:
      path: ~/.aws/credentials
      format: ini
enrolments:
  gh:
    engine: github
`)
	p, err := ParsePartial(doc)
	if err != nil {
		t.Fatalf("ParsePartial: %v", err)
	}
	if p.Sync == nil || p.Sync.RawInterval != "5m" {
		t.Errorf("Sync = %+v, want RawInterval 5m", p.Sync)
	}
	if len(p.Rules) != 1 || p.Rules[0].Name != "aws" {
		t.Errorf("Rules = %+v, want one rule named aws", p.Rules)
	}
	if _, ok := p.Enrolments["gh"]; !ok {
		t.Errorf("Enrolments = %+v, want key gh", p.Enrolments)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParsePartialRejectsStaticSections(t *testing.T) {
	cases := map[string]string{
		"vault":                "vault:\n  address: https://evil.example.com\n",
		"web":                  "web:\n  enabled: true\n",
		"agent":                "agent:\n  enabled: true\n",
		"observability":        "observability:\n  enabled: true\n",
		"bypass_system_config": "bypass_system_config: true\n",
		"remote_config":        "remote_config:\n  url: https://other.example.com\n",
	}
	for section, doc := range cases {
		t.Run(section, func(t *testing.T) {
			_, err := ParsePartial([]byte(doc))
			if err == nil {
				t.Fatalf("expected error for static section %q, got nil", section)
			}
			if !strings.Contains(err.Error(), section) {
				t.Errorf("error %q does not name the offending section %q", err, section)
			}
		})
	}
}

// TestParsePartialIgnoresUnknownSections pins the forward-compatibility
// contract: a newer server may serve sections an older daemon doesn't know,
// and the daemon must keep working.
func TestParsePartialIgnoresUnknownSections(t *testing.T) {
	doc := []byte(`
rules:
  - name: aws
    vault_key: aws
    target:
      path: ~/.aws/credentials
      format: ini
future_section:
  some: thing
`)
	p, err := ParsePartial(doc)
	if err != nil {
		t.Fatalf("ParsePartial: %v", err)
	}
	if len(p.Rules) != 1 {
		t.Errorf("Rules = %+v, want the known section parsed", p.Rules)
	}
}

func TestParsePartialEmptyDocument(t *testing.T) {
	p, err := ParsePartial([]byte(""))
	if err != nil {
		t.Fatalf("ParsePartial(empty): %v", err)
	}
	if p.Sync != nil || len(p.Rules) != 0 || len(p.Enrolments) != 0 {
		t.Errorf("expected empty partial, got %+v", p)
	}
}

func TestParsePartialRejectsNonMapping(t *testing.T) {
	if _, err := ParsePartial([]byte("- just\n- a\n- list\n")); err == nil {
		t.Fatal("expected error for non-mapping document, got nil")
	}
}

func TestPartialValidate(t *testing.T) {
	cases := []struct {
		name    string
		partial Partial
		wantErr string
	}{
		{
			name: "duplicate rule names",
			partial: Partial{Rules: []Rule{
				{Name: "a", VaultKey: "a", Target: Target{Path: "p", Format: "text"}},
				{Name: "a", VaultKey: "b", Target: Target{Path: "q", Format: "text"}},
			}},
			wantErr: "duplicate rule name",
		},
		{
			name:    "missing vault_key",
			partial: Partial{Rules: []Rule{{Name: "a", Target: Target{Path: "p", Format: "text"}}}},
			wantErr: "vault_key is required",
		},
		{
			name:    "invalid format",
			partial: Partial{Rules: []Rule{{Name: "a", VaultKey: "a", Target: Target{Path: "p", Format: "xml"}}}},
			wantErr: "invalid format",
		},
		{
			name:    "enrolment missing engine",
			partial: Partial{Enrolments: map[string]Enrolment{"gh": {}}},
			wantErr: "engine is required",
		},
		{
			name:    "enrolment bad key",
			partial: Partial{Enrolments: map[string]Enrolment{"a/b/c": {Engine: "github"}}},
			wantErr: "grouping level",
		},
		{
			name:    "bad sync interval",
			partial: Partial{Sync: &SyncConfig{RawInterval: "nonsense"}},
			wantErr: "sync.interval",
		},
		{
			name: "valid",
			partial: Partial{
				Sync:       &SyncConfig{RawInterval: "10m"},
				Rules:      []Rule{{Name: "a", VaultKey: "a", Target: Target{Path: "p", Format: "text"}}},
				Enrolments: map[string]Enrolment{"gh": {Engine: "github"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.partial.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
