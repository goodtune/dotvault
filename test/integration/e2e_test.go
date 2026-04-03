package integration

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/sync"
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

func TestEndToEnd(t *testing.T) {
	vc := testVC
	ctx := context.Background()

	// Seed data
	vc.EnableKVv2(ctx, "secret")
	vc.WriteKVv2(ctx, "secret", "users/e2euser/gh", map[string]any{
		"token": "ghp_e2e_token",
		"user":  "e2euser",
	})
	vc.WriteKVv2(ctx, "secret", "users/e2euser/docker", map[string]any{
		"registry": "ghcr.io",
		"auth":     "ZTJlOnBhc3M=",
	})
	vc.WriteKVv2(ctx, "secret", "users/e2euser/npm", map[string]any{
		"token": "npm_e2e_token",
	})

	dir := t.TempDir()

	cfg := &config.Config{
		Vault: config.VaultConfig{
			KVMount:    "secret",
			UserPrefix: "users/",
		},
		Rules: []config.Rule{
			{
				Name: "gh", VaultKey: "gh",
				Target: config.Target{
					Path: filepath.Join(dir, "hosts.yml"), Format: "yaml",
					Template: "github.com:\n  oauth_token: \"{{.token}}\"\n  user: \"{{.user}}\"\n  git_protocol: https",
					Merge:    "deep",
				},
			},
			{
				Name: "docker", VaultKey: "docker",
				Target: config.Target{
					Path: filepath.Join(dir, "docker-config.json"), Format: "json",
					Template: "{\"auths\":{\"{{.registry}}\":{\"auth\":\"{{.auth}}\"}}}",
					Merge:    "deep",
				},
			},
			{
				Name: "npm", VaultKey: "npm",
				Target: config.Target{
					Path: filepath.Join(dir, ".npmrc"), Format: "ini",
					Template: "//registry.npmjs.org/:_authToken={{.token}}",
					Merge:    "line-replace",
				},
			},
		},
	}

	statePath := filepath.Join(dir, "state.json")
	engine := sync.NewEngine(cfg, vc, "e2euser", statePath)

	// Run sync
	err := engine.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Verify YAML output
	ghData, _ := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	assertContains(t, string(ghData), "ghp_e2e_token", "gh hosts.yml")
	assertContains(t, string(ghData), "e2euser", "gh hosts.yml")

	// Verify JSON output
	dockerData, _ := os.ReadFile(filepath.Join(dir, "docker-config.json"))
	var dockerMap map[string]any
	json.Unmarshal(dockerData, &dockerMap)
	auths := dockerMap["auths"].(map[string]any)
	if auths["ghcr.io"] == nil {
		t.Error("docker config missing ghcr.io")
	}

	// Verify INI output
	npmData, _ := os.ReadFile(filepath.Join(dir, ".npmrc"))
	assertContains(t, string(npmData), "npm_e2e_token", ".npmrc")

	// Run again — should be a no-op
	err = engine.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce (second): %v", err)
	}

	t.Log("end-to-end test passed")
}

func assertContains(t *testing.T, s, substr, context string) {
	t.Helper()
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return
		}
	}
	t.Errorf("%s: output missing %q:\n%s", context, substr, s)
}
