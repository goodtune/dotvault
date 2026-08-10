package auth

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"

	"github.com/goodtune/dotvault/internal/vaulttest"
)

func skipIfNoVault(t *testing.T) {
	t.Helper()
	cmd := exec.Command("curl", "-sf", "http://127.0.0.1:8200/v1/sys/health")
	if err := cmd.Run(); err != nil {
		t.Skip("Vault dev server not available")
	}
}

func TestManagerAuthenticate_ExistingToken(t *testing.T) {
	skipIfNoVault(t)

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	os.WriteFile(tokenPath, []byte(vaulttest.RootToken(t)), 0600)

	m := &Manager{
		VaultClient:   mustVaultClient(t),
		TokenFilePath: tokenPath,
		AuthMethod:    "token",
		Username:      "testuser",
	}

	err := m.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if m.VaultClient.Token() != vaulttest.RootToken(t) {
		t.Errorf("token = %q, want %q", m.VaultClient.Token(), vaulttest.RootToken(t))
	}
}

func TestManagerAuthenticate_EnvToken(t *testing.T) {
	skipIfNoVault(t)
	t.Setenv("DOTVAULT_TOKEN", vaulttest.RootToken(t))

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	m := &Manager{
		VaultClient:   mustVaultClient(t),
		TokenFilePath: tokenPath,
		AuthMethod:    "token",
		Username:      "testuser",
	}

	err := m.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
}

func TestManagerAuthenticate_NoToken(t *testing.T) {
	skipIfNoVault(t)
	t.Setenv("DOTVAULT_TOKEN", "")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")

	m := &Manager{
		VaultClient:   mustVaultClient(t),
		TokenFilePath: tokenPath,
		AuthMethod:    "token", // "token" method with no token should fail
		Username:      "testuser",
	}

	err := m.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error when no token available")
	}
}

func mustVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}
