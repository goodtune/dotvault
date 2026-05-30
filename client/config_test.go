package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
vault:
  address: https://vault.example.com:8200
  kv_mount: secrets
  user_prefix: team/users
  auth_method: oidc
  auth_mount: oidc
  auth_role: dev
  tls_skip_verify: true
rules:
  - name: gh
    vault_key: gh
    target:
      path: /tmp/gh.yaml
      format: yaml
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Address = %q", cfg.Vault.Address)
	}
	if cfg.Vault.KVMount != "secrets" {
		t.Errorf("KVMount = %q, want secrets", cfg.Vault.KVMount)
	}
	// LoadConfig should inherit dotvault's trailing-slash normalisation.
	if cfg.Vault.UserPrefix != "team/users/" {
		t.Errorf("UserPrefix = %q, want team/users/", cfg.Vault.UserPrefix)
	}
	if cfg.Vault.AuthMethod != "oidc" || cfg.Vault.AuthMount != "oidc" || cfg.Vault.AuthRole != "dev" {
		t.Errorf("auth fields = %q/%q/%q", cfg.Vault.AuthMethod, cfg.Vault.AuthMount, cfg.Vault.AuthRole)
	}
	if !cfg.Vault.TLSSkipVerify {
		t.Error("TLSSkipVerify should be true")
	}
}

func TestLoadConfig_DefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
vault:
  address: https://vault.example.com:8200
rules:
  - name: gh
    vault_key: gh
    target:
      path: /tmp/gh.yaml
      format: yaml
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Vault.KVMount != "kv" {
		t.Errorf("KVMount default = %q, want kv", cfg.Vault.KVMount)
	}
	if cfg.Vault.UserPrefix != "users/" {
		t.Errorf("UserPrefix default = %q, want users/", cfg.Vault.UserPrefix)
	}
}

func TestLoadConfig_InvalidSurfacesError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Missing vault.address — dotvault's validator must reject it.
	yaml := `
vault:
  kv_mount: kv
rules:
  - name: gh
    vault_key: gh
    target:
      path: /tmp/gh.yaml
      format: yaml
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected validation error for missing vault.address")
	}
}

func TestDefaultPaths(t *testing.T) {
	if DefaultConfigPath() == "" {
		t.Error("DefaultConfigPath empty")
	}
	if DefaultTokenFile() == "" {
		t.Error("DefaultTokenFile empty")
	}
}

// TestDefaultTokenFile_HomeUnavailable verifies DefaultTokenFile recovers the
// panic paths.VaultTokenPath raises when the home directory can't be resolved,
// returning "" rather than crashing a consumer. On non-Windows, an empty $HOME
// makes os.UserHomeDir fail; Windows uses %USERPROFILE% and doesn't panic, so
// skip there.
func TestDefaultTokenFile_HomeUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("VaultTokenPath uses USERPROFILE on Windows; no panic path")
	}
	t.Setenv("HOME", "")
	got := DefaultTokenFile()
	if got != "" {
		t.Fatalf("DefaultTokenFile() = %q, want \"\" when home is unresolvable", got)
	}
}
