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
	// DefaultTokenFile is documented to return "" when the home directory
	// can't be resolved, so we don't assert non-empty here (that would
	// contradict the contract and fail in constrained environments). When a
	// home dir IS resolvable — the normal case and what CI provides — it
	// should be non-empty; gate the assertion on that.
	if _, err := os.UserHomeDir(); err == nil && DefaultTokenFile() == "" {
		t.Error("DefaultTokenFile empty despite a resolvable home directory")
	}
}

// TestDefaultTokenFile_HomeUnavailable verifies DefaultTokenFile recovers the
// panic paths.VaultTokenPath raises when the home directory can't be resolved,
// returning "" rather than crashing a consumer. Forcing that condition is
// platform-dependent (empty $HOME makes os.UserHomeDir fail on Unix, but
// Windows reads %USERPROFILE% and doesn't panic), so rather than assume, we
// gate on whether os.UserHomeDir actually errors under the forced environment
// and skip otherwise — keeping the test correct everywhere.
func TestDefaultTokenFile_HomeUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		// VaultTokenPath reads %USERPROFILE% directly (not os.UserHomeDir)
		// and never panics, so there's no recover path to exercise here.
		t.Skip("VaultTokenPath uses USERPROFILE on Windows; no panic path")
	}
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		// Some environments still resolve a home dir with $HOME empty; the
		// panic (and thus the recover) can't be triggered, so skip rather
		// than assert a condition that doesn't hold here.
		t.Skip("home directory still resolvable with $HOME empty; can't exercise the recover path")
	}
	if got := DefaultTokenFile(); got != "" {
		t.Fatalf("DefaultTokenFile() = %q, want \"\" when home is unresolvable", got)
	}
}
