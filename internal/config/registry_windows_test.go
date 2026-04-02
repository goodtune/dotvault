//go:build windows

package config

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

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

	// Second layer overrides only AuthMethod.
	override := registryLayer{
		VaultAuthMethod: "oidc",
	}
	applyRegistryLayer(cfg, override)

	if cfg.Vault.Address != "https://vault.corp.example.com:8200" {
		t.Errorf("Address = %q, want base value", cfg.Vault.Address)
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("AuthMethod = %q, want override %q", cfg.Vault.AuthMethod, "oidc")
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

func TestReadSingleEnrolment(t *testing.T) {
	// Create a temporary registry key tree simulating:
	//   <testRoot>\Enrolments\gh\Engine = "github"
	//   <testRoot>\Enrolments\gh\Settings\Host = "github.com"
	//   <testRoot>\Enrolments\gh\Settings\Scopes = ["repo", "read:org"]
	base, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test\Enrolments\gh`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create test key: %v", err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments\gh\Settings`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments\gh`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test`)

	if err := base.SetStringValue("Engine", "github"); err != nil {
		t.Fatalf("set Engine: %v", err)
	}
	base.Close()

	settings, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test\Enrolments\gh\Settings`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create Settings key: %v", err)
	}
	if err := settings.SetStringValue("Host", "github.com"); err != nil {
		t.Fatalf("set Host: %v", err)
	}
	if err := settings.SetStringsValue("Scopes", []string{"repo", "read:org"}); err != nil {
		t.Fatalf("set Scopes: %v", err)
	}
	settings.Close()

	enrolment, err := readSingleEnrolment(registry.CURRENT_USER, `SOFTWARE\dotvault-test`, "gh")
	if err != nil {
		t.Fatalf("readSingleEnrolment() error: %v", err)
	}
	if enrolment.Engine != "github" {
		t.Errorf("Engine = %q, want %q", enrolment.Engine, "github")
	}
	if enrolment.Settings == nil {
		t.Fatal("Settings is nil")
	}
	if host, ok := enrolment.Settings["Host"]; !ok || host != "github.com" {
		t.Errorf("Settings[Host] = %v, want %q", enrolment.Settings["Host"], "github.com")
	}
	scopes, ok := enrolment.Settings["Scopes"]
	if !ok {
		t.Fatal("Settings[Scopes] missing")
	}
	scopeSlice, ok := scopes.([]any)
	if !ok {
		t.Fatalf("Settings[Scopes] type = %T, want []any", scopes)
	}
	if len(scopeSlice) != 2 || scopeSlice[0] != "repo" || scopeSlice[1] != "read:org" {
		t.Errorf("Settings[Scopes] = %v, want [repo read:org]", scopeSlice)
	}
}

func TestReadRegistryEnrolmentsNotExist(t *testing.T) {
	// Use a path that definitely doesn't exist.
	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, `SOFTWARE\dotvault-nonexistent`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enrolments != nil {
		t.Errorf("expected nil enrolments, got %v", enrolments)
	}
}

func TestReadRegistryEnrolmentsMultiple(t *testing.T) {
	// Create two enrolment subkeys under a temporary registry path.
	for _, name := range []string{"gh", "gitlab"} {
		key, _, err := registry.CreateKey(
			registry.CURRENT_USER,
			`SOFTWARE\dotvault-test-enrol\Enrolments\`+name,
			registry.ALL_ACCESS,
		)
		if err != nil {
			t.Fatalf("create key %s: %v", name, err)
		}
		engine := "github"
		if name == "gitlab" {
			engine = "gitlab"
		}
		if err := key.SetStringValue("Engine", engine); err != nil {
			t.Fatalf("set Engine for %s: %v", name, err)
		}
		key.Close()
	}
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments\gh`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments\gitlab`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol`)

	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol`)
	if err != nil {
		t.Fatalf("readRegistryEnrolments() error: %v", err)
	}
	if len(enrolments) != 2 {
		t.Fatalf("len(enrolments) = %d, want 2", len(enrolments))
	}
	if enrolments["gh"].Engine != "github" {
		t.Errorf("gh.Engine = %q, want %q", enrolments["gh"].Engine, "github")
	}
	if enrolments["gitlab"].Engine != "gitlab" {
		t.Errorf("gitlab.Engine = %q, want %q", enrolments["gitlab"].Engine, "gitlab")
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
