package config

import (
	"testing"
)

func TestLoadSystemFallsBackToFile(t *testing.T) {
	// On non-Windows (or Windows without GPO keys), LoadSystem should
	// behave identically to Load — reading the YAML file at the given path.
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
`
	path := writeTemp(t, yaml)

	cfg, err := LoadSystem(path)
	if err != nil {
		t.Fatalf("LoadSystem() error: %v", err)
	}
	if cfg.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Vault.Address = %q, want %q", cfg.Vault.Address, "https://vault.example.com:8200")
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(cfg.Rules))
	}
	if cfg.Rules[0].Name != "gh" {
		t.Errorf("Rules[0].Name = %q, want %q", cfg.Rules[0].Name, "gh")
	}
}

func TestLoadSystemFileNotFound(t *testing.T) {
	// When no registry config exists and the file is missing, LoadSystem
	// should return an error.
	_, err := LoadSystem("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}
