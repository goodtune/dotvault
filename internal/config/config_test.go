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

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
