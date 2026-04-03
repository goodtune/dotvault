package auth

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaulttest"
)

var testVC *vault.Client

func TestMain(m *testing.M) {
	ctx := context.Background()
	vc, cleanup, err := vaulttest.Start(ctx)
	if err != nil {
		log.Fatalf("start vault testcontainer: %v", err)
	}
	defer cleanup()
	testVC = vc
	os.Exit(m.Run())
}

func mustVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	// Create a fresh client pointing at the same container but without
	// a pre-set token, matching the original test's expectations.
	vc, err := vault.NewClient(vault.Config{
		Address: testVC.Raw().Address(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return vc
}

func TestManagerAuthenticate_ExistingToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, ".vault-token")
	os.WriteFile(tokenPath, []byte(vaulttest.DevRootToken), 0600)

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
	if m.VaultClient.Token() != vaulttest.DevRootToken {
		t.Errorf("token = %q, want %q", m.VaultClient.Token(), vaulttest.DevRootToken)
	}
}

func TestManagerAuthenticate_EnvToken(t *testing.T) {
	t.Setenv("VAULT_TOKEN", vaulttest.DevRootToken)

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
	t.Setenv("VAULT_TOKEN", "")

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
