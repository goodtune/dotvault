package vault

import (
	"context"
	"os"
	"os/exec"
	"testing"
)

func skipIfNoVault(t *testing.T) {
	t.Helper()
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	// Quick check: try to reach Vault
	cmd := exec.Command("curl", "-sf", addr+"/v1/sys/health")
	if err := cmd.Run(); err != nil {
		t.Skip("Vault dev server not available, skipping integration test")
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	skipIfNoVault(t)
	c, err := NewClient(Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClient(t *testing.T) {
	skipIfNoVault(t)
	c, err := NewClient(Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

func TestReadKVv2(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Seed test data — enable kv-v2 at "secret/" and write a secret
	seedTestSecret(t, c)

	secret, err := c.ReadKVv2(ctx, "secret", "users/testuser/gh")
	if err != nil {
		t.Fatalf("ReadKVv2: %v", err)
	}
	if secret == nil {
		t.Fatal("secret is nil")
	}
	if secret.Data["token"] != "test-gh-token" {
		t.Errorf("token = %v, want 'test-gh-token'", secret.Data["token"])
	}
	if secret.Version < 1 {
		t.Errorf("version = %d, want >= 1", secret.Version)
	}
}

func TestReadKVv2NotFound(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	secret, err := c.ReadKVv2(ctx, "secret", "users/testuser/nonexistent")
	if err != nil {
		t.Fatalf("ReadKVv2: %v", err)
	}
	if secret != nil {
		t.Errorf("expected nil secret for nonexistent path, got %+v", secret)
	}
}

func TestListKVv2(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	seedTestSecret(t, c)

	keys, err := c.ListKVv2(ctx, "secret", "users/testuser/")
	if err != nil {
		t.Fatalf("ListKVv2: %v", err)
	}
	if len(keys) == 0 {
		t.Error("ListKVv2 returned empty list")
	}

	found := false
	for _, k := range keys {
		if k == "gh" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListKVv2 keys = %v, want to contain 'gh'", keys)
	}
}

func seedTestSecret(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()

	// Enable KVv2 at "secret/" if not already
	err := c.EnableKVv2(ctx, "secret")
	if err != nil {
		// May already be enabled — that's fine
		t.Logf("EnableKVv2: %v (may already exist)", err)
	}

	// Write test secret
	err = c.WriteKVv2(ctx, "secret", "users/testuser/gh", map[string]any{
		"token": "test-gh-token",
		"user":  "testuser",
	})
	if err != nil {
		t.Fatalf("WriteKVv2: %v", err)
	}
}
