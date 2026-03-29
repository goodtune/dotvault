//go:build windows

package config

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// testRegistryKey creates a temporary registry key under HKCU for testing
// and returns a cleanup function. Tests use HKCU\SOFTWARE\dotvault-test
// to avoid interfering with real configuration.
func testCreatePolicyKey(t *testing.T, subkey string) registry.Key {
	t.Helper()
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\Policies\dotvault-test\`+subkey,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create test registry key: %v", err)
	}
	t.Cleanup(func() {
		key.Close()
		// Clean up the subkey tree. Walk bottom-up.
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Policies\dotvault-test\`+subkey)
	})
	return key
}

func testCleanupPolicyRoot(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		// Best-effort cleanup of the test root keys.
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Policies\dotvault-test\Rules`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Policies\dotvault-test\Vault`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Policies\dotvault-test\Sync`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Policies\dotvault-test\Web`)
		registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\Policies\dotvault-test`)
	})
}

func TestApplyRegistryLayer(t *testing.T) {
	cfg := &Config{}

	layer := registryLayer{
		VaultAddress:    "https://vault.corp.example.com:8200",
		VaultKVMount:    "secret",
		VaultAuthMethod: "oidc",
		SyncInterval:    "10m",
	}
	applyRegistryLayer(cfg, layer)

	if cfg.Vault.Address != "https://vault.corp.example.com:8200" {
		t.Errorf("Address = %q, want %q", cfg.Vault.Address, "https://vault.corp.example.com:8200")
	}
	if cfg.Vault.KVMount != "secret" {
		t.Errorf("KVMount = %q, want %q", cfg.Vault.KVMount, "secret")
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("AuthMethod = %q, want %q", cfg.Vault.AuthMethod, "oidc")
	}
	if cfg.Sync.RawInterval != "10m" {
		t.Errorf("RawInterval = %q, want %q", cfg.Sync.RawInterval, "10m")
	}
}

func TestApplyRegistryLayerMerge(t *testing.T) {
	// Machine layer sets base values.
	cfg := &Config{}
	machine := registryLayer{
		VaultAddress:    "https://vault.corp.example.com:8200",
		VaultKVMount:    "kv",
		VaultAuthMethod: "ldap",
		SyncInterval:    "15m",
	}
	applyRegistryLayer(cfg, machine)

	// User layer overrides only AuthMethod.
	user := registryLayer{
		VaultAuthMethod: "oidc",
	}
	applyRegistryLayer(cfg, user)

	if cfg.Vault.Address != "https://vault.corp.example.com:8200" {
		t.Errorf("Address = %q, want machine value", cfg.Vault.Address)
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("AuthMethod = %q, want user override %q", cfg.Vault.AuthMethod, "oidc")
	}
	if cfg.Sync.RawInterval != "15m" {
		t.Errorf("RawInterval = %q, want machine value %q", cfg.Sync.RawInterval, "15m")
	}
}

func TestApplyRegistryLayerBooleans(t *testing.T) {
	cfg := &Config{}

	enabled := uint32(1)
	skipVerify := uint32(0)
	layer := registryLayer{
		VaultTLSSkipVerify: &skipVerify,
		WebEnabled:         &enabled,
		WebListen:          "127.0.0.1:9090",
	}
	applyRegistryLayer(cfg, layer)

	if cfg.Vault.TLSSkipVerify != false {
		t.Error("TLSSkipVerify should be false when DWORD is 0")
	}
	if cfg.Web.Enabled != true {
		t.Error("Web.Enabled should be true when DWORD is 1")
	}
	if cfg.Web.Listen != "127.0.0.1:9090" {
		t.Errorf("Web.Listen = %q, want %q", cfg.Web.Listen, "127.0.0.1:9090")
	}
}

func TestLoadFromRegistryNoKeys(t *testing.T) {
	// When no GPO keys exist, loadFromRegistry should return false.
	cfg, managed, err := loadFromRegistry()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// This test may return true if the machine happens to have dotvault
	// GPO keys installed. Skip in that case.
	if managed {
		t.Skip("GPO registry keys found on this machine; skipping no-keys test")
	}
	if cfg != nil {
		t.Error("expected nil config when no keys exist")
	}
}
