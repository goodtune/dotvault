package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValid(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: gh
    description: "GitHub CLI token"
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{.token}}"
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Vault.Address = %q, want %q", cfg.Vault.Address, "https://vault.example.com:8200")
	}
	if cfg.Vault.KVMount != "kv" {
		t.Errorf("Vault.KVMount = %q, want %q", cfg.Vault.KVMount, "kv")
	}
	if cfg.Vault.UserPrefix != "users/" {
		t.Errorf("Vault.UserPrefix = %q, want default %q", cfg.Vault.UserPrefix, "users/")
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("Vault.AuthMethod = %q, want %q", cfg.Vault.AuthMethod, "oidc")
	}
	if cfg.Sync.Interval != 5*time.Minute {
		t.Errorf("Sync.Interval = %v, want %v", cfg.Sync.Interval, 5*time.Minute)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(cfg.Rules))
	}
	r := cfg.Rules[0]
	if r.Name != "gh" {
		t.Errorf("Rule.Name = %q, want %q", r.Name, "gh")
	}
	if r.Target.Format != "yaml" {
		t.Errorf("Rule.Target.Format = %q, want %q", r.Target.Format, "yaml")
	}
	if r.Target.Merge != "deep" {
		t.Errorf("Rule.Target.Merge = %q, want %q", r.Target.Merge, "deep")
	}
}

func TestLoadCustomUserPrefix(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  user_prefix: "team/engineering/"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.UserPrefix != "team/engineering/" {
		t.Errorf("Vault.UserPrefix = %q, want %q", cfg.Vault.UserPrefix, "team/engineering/")
	}
}

func TestLoadCustomUserPrefixWithoutTrailingSlash(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  user_prefix: "team/engineering"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.UserPrefix != "team/engineering/" {
		t.Errorf("Vault.UserPrefix = %q, want %q", cfg.Vault.UserPrefix, "team/engineering/")
	}
}

func TestLoadWebConfig(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

web:
  enabled: true
  listen: "127.0.0.1:8200"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.Web.Enabled {
		t.Error("Web.Enabled = false, want true")
	}
	if cfg.Web.Listen != "127.0.0.1:8200" {
		t.Errorf("Web.Listen = %q, want %q", cfg.Web.Listen, "127.0.0.1:8200")
	}
}

func TestLoadMissingAddress(t *testing.T) {
	yaml := `
vault:
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing vault address")
	}
}

func TestLoadNoRules(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules: []
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestLoadInvalidInterval(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "not-a-duration"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid interval")
	}
}

func TestLoadDuplicateRuleNames(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
  - name: gh
    vault_key: "gh2"
    target:
      path: "~/.config/gh/other.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate rule names")
	}
}

func TestLoadInvalidFormat(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: xml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid format 'xml'")
	}
}

func TestLoadNonLoopbackWebAddress(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

web:
  enabled: true
  listen: "0.0.0.0:8200"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-loopback web address")
	}
}

func TestLoadOAuthRule(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: github-app
    vault_key: "github-app"
    oauth:
      engine_path: "github/token"
      provider: "GitHub"
      scopes:
        - repo
        - read:org
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{.token}}"
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	r := cfg.Rules[0]
	if r.OAuth == nil {
		t.Fatal("Rule.OAuth is nil, want non-nil")
	}
	if r.OAuth.EnginePath != "github/token" {
		t.Errorf("OAuth.EnginePath = %q, want %q", r.OAuth.EnginePath, "github/token")
	}
	if r.OAuth.Provider != "GitHub" {
		t.Errorf("OAuth.Provider = %q, want %q", r.OAuth.Provider, "GitHub")
	}
	if len(r.OAuth.Scopes) != 2 {
		t.Errorf("len(OAuth.Scopes) = %d, want 2", len(r.OAuth.Scopes))
	}
}

func TestLoadEnrolments(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep

enrolments:
  gh:
    engine: github
  gitlab:
    engine: gitlab
    settings:
      host: "gitlab.example.com"
      scopes:
        - api
        - read_user
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Enrolments) != 2 {
		t.Fatalf("len(Enrolments) = %d, want 2", len(cfg.Enrolments))
	}
	gh, ok := cfg.Enrolments["gh"]
	if !ok {
		t.Fatal("missing enrolment 'gh'")
	}
	if gh.Engine != "github" {
		t.Errorf("gh.Engine = %q, want %q", gh.Engine, "github")
	}
	gl := cfg.Enrolments["gitlab"]
	if gl.Engine != "gitlab" {
		t.Errorf("gitlab.Engine = %q, want %q", gl.Engine, "gitlab")
	}
	if gl.Settings["host"] != "gitlab.example.com" {
		t.Errorf("gitlab.Settings[host] = %v, want %q", gl.Settings["host"], "gitlab.example.com")
	}
}

func TestLoadEnrolmentMissingEngine(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep

enrolments:
  gh:
    settings:
      host: "github.com"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing engine field")
	}
}

func TestLoadEmptyEnrolments(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Enrolments) != 0 {
		t.Errorf("len(Enrolments) = %d, want 0", len(cfg.Enrolments))
	}
}

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"60d", 60 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"6h", 6 * time.Hour, false},
		{"10m", 10 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{"45s", 45 * time.Second, false},
		{"0d", 0, false},
		{"-5d", 0, true},     // negative not allowed for Nd
		{"1.5d", 0, true},     // stdlib rejects .5d as unknown unit
		{"bogus", 0, true},
		{"", 0, true},
		{"1w", 0, true}, // not supported
		// Overflow guard: time.Duration is int64 ns ≈ 292 years max, so
		// anything above ~106,751 days wraps. 200,000d comfortably overflows.
		{"200000d", 0, true},
		// Very large day count that overflows int64 at ParseInt — must
		// surface a dedicated "exceeds range" error, not "unknown unit d".
		{"99999999999999999999d", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseDuration(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDuration(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLoadTokenTTLFloor(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml

enrolments:
  jfrog:
    engine: jfrog
    settings:
      url: "https://mycompany.jfrog.io"
      token_ttl: "5m"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for token_ttl below 10m floor")
	}
}

func TestLoadTokenTTLValid(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml

enrolments:
  jfrog:
    engine: jfrog
    settings:
      url: "https://mycompany.jfrog.io"
      token_ttl: "6h"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	got := cfg.Enrolments["jfrog"].Settings["token_ttl"]
	if got != "6h" {
		t.Errorf("token_ttl = %v, want %q", got, "6h")
	}
}

func TestLoadTokenTTLInvalid(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml

enrolments:
  jfrog:
    engine: jfrog
    settings:
      url: "https://mycompany.jfrog.io"
      token_ttl: "bogus"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unparseable token_ttl")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
