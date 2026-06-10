package config

import (
	"reflect"
	"testing"
)

func baseConfigForMerge() *Config {
	return &Config{
		Vault: VaultConfig{Address: "https://vault.example.com:8200"},
		Sync:  SyncConfig{RawInterval: "15m"},
		Rules: []Rule{
			{Name: "aws", VaultKey: "aws", Target: Target{Path: "~/.aws/credentials", Format: "ini"}},
			{Name: "gh", VaultKey: "gh", Target: Target{Path: "~/.config/gh/hosts.yml", Format: "yaml"}},
		},
		Enrolments: map[string]Enrolment{
			"gh": {Engine: "github"},
		},
	}
}

func TestApplyPartialRulesByName(t *testing.T) {
	base := baseConfigForMerge()
	ApplyPartial(base, &Partial{Rules: []Rule{
		// Same name: replaces wholesale, keeps base position.
		{Name: "aws", VaultKey: "aws-sydney", Target: Target{Path: "~/.aws/credentials", Format: "ini"}},
		// New name: appended after base rules.
		{Name: "jfrog", VaultKey: "jfrog", Target: Target{Path: "~/.jfrog/jfrog-cli.conf.v6", Format: "json"}},
	}})

	wantNames := []string{"aws", "gh", "jfrog"}
	var gotNames []string
	for _, r := range base.Rules {
		gotNames = append(gotNames, r.Name)
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Errorf("rule order = %v, want %v", gotNames, wantNames)
	}
	if base.Rules[0].VaultKey != "aws-sydney" {
		t.Errorf("aws rule not replaced: VaultKey = %q", base.Rules[0].VaultKey)
	}
}

func TestApplyPartialRuleReplacementIsWholesale(t *testing.T) {
	base := baseConfigForMerge()
	base.Rules[0].Description = "base description"
	base.Rules[0].OAuth = &OAuthConfig{Provider: "okta"}

	// The overlay rule omits Description and OAuth — replacement must not
	// keep the base's field values (a rule is an atomic unit).
	ApplyPartial(base, &Partial{Rules: []Rule{
		{Name: "aws", VaultKey: "aws2", Target: Target{Path: "p", Format: "ini"}},
	}})
	if base.Rules[0].Description != "" || base.Rules[0].OAuth != nil {
		t.Errorf("replacement leaked base fields: %+v", base.Rules[0])
	}
}

func TestApplyPartialEnrolmentsByKey(t *testing.T) {
	base := baseConfigForMerge()
	ApplyPartial(base, &Partial{Enrolments: map[string]Enrolment{
		"gh":             {Engine: "github", Settings: map[string]any{"host": "github.example.com"}},
		"databricks/syd": {Engine: "databricks"},
	}})
	if len(base.Enrolments) != 2 {
		t.Fatalf("Enrolments = %+v, want 2 entries", base.Enrolments)
	}
	if base.Enrolments["gh"].Settings["host"] != "github.example.com" {
		t.Errorf("gh enrolment not replaced: %+v", base.Enrolments["gh"])
	}
}

func TestApplyPartialIntoNilEnrolments(t *testing.T) {
	base := baseConfigForMerge()
	base.Enrolments = nil
	ApplyPartial(base, &Partial{Enrolments: map[string]Enrolment{"gh": {Engine: "github"}}})
	if base.Enrolments["gh"].Engine != "github" {
		t.Errorf("Enrolments = %+v", base.Enrolments)
	}
}

func TestApplyPartialSyncInterval(t *testing.T) {
	base := baseConfigForMerge()
	ApplyPartial(base, &Partial{Sync: &SyncConfig{RawInterval: "5m"}})
	if base.Sync.RawInterval != "5m" {
		t.Errorf("RawInterval = %q, want 5m", base.Sync.RawInterval)
	}

	// Empty interval in the overlay leaves the base untouched.
	ApplyPartial(base, &Partial{Sync: &SyncConfig{}})
	if base.Sync.RawInterval != "5m" {
		t.Errorf("RawInterval = %q after empty overlay, want 5m", base.Sync.RawInterval)
	}
}

func TestApplyPartialNilSafe(t *testing.T) {
	base := baseConfigForMerge()
	before := *base
	ApplyPartial(base, nil)
	if !reflect.DeepEqual(base.Rules, before.Rules) {
		t.Errorf("nil partial mutated rules")
	}
	ApplyPartial(nil, &Partial{}) // must not panic
}

func TestMergePartialLayerComposition(t *testing.T) {
	// The Sydney/New York story: global defines the shared rule, each
	// office layer adds its enrolments; a user in both offices gets the
	// union, and the user layer overrides a single entry.
	global := &Partial{
		Rules: []Rule{{Name: "ssh", VaultKey: "ssh", Target: Target{Path: "~/.ssh/id_ed25519", Format: "text"}}},
	}
	sydney := &Partial{
		Enrolments: map[string]Enrolment{"artifactory/syd": {Engine: "jfrog"}},
	}
	newyork := &Partial{
		Enrolments: map[string]Enrolment{"artifactory/nyc": {Engine: "jfrog"}},
		Sync:       &SyncConfig{RawInterval: "10m"},
	}
	user := &Partial{
		Enrolments: map[string]Enrolment{"artifactory/syd": {Engine: "jfrog", Settings: map[string]any{"url": "https://override.jfrog.io"}}},
	}

	var composed *Partial
	for _, layer := range []*Partial{global, sydney, newyork, user} {
		composed = MergePartial(composed, layer)
	}

	if len(composed.Rules) != 1 || composed.Rules[0].Name != "ssh" {
		t.Errorf("Rules = %+v", composed.Rules)
	}
	if len(composed.Enrolments) != 2 {
		t.Errorf("Enrolments = %+v, want union of both offices", composed.Enrolments)
	}
	if composed.Enrolments["artifactory/syd"].Settings["url"] != "https://override.jfrog.io" {
		t.Errorf("user layer override lost: %+v", composed.Enrolments["artifactory/syd"])
	}
	if composed.Sync == nil || composed.Sync.RawInterval != "10m" {
		t.Errorf("Sync = %+v, want 10m from the newyork layer", composed.Sync)
	}

	// Source layers must not be mutated by composition.
	if len(global.Enrolments) != 0 || len(sydney.Enrolments) != 1 {
		t.Errorf("composition mutated source layers: global=%+v sydney=%+v", global, sydney)
	}
}

// TestValidateZeroRulesWithRemoteURL pins the relaxed validation gate: a base
// that declares a remote overlay may carry zero rules (the remote document
// supplies them), while a config without a remote URL keeps the hard error.
func TestValidateZeroRulesWithRemoteURL(t *testing.T) {
	cfg := &Config{
		Vault:        VaultConfig{Address: "https://vault.example.com:8200"},
		RemoteConfig: RemoteConfig{URL: "https://config.example.com/v1/config"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate with remote URL and zero rules: %v", err)
	}

	noRemote := &Config{Vault: VaultConfig{Address: "https://vault.example.com:8200"}}
	if err := noRemote.Validate(); err == nil {
		t.Error("Validate with zero rules and no remote URL should fail")
	}
}
