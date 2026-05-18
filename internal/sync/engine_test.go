package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

func skipIfNoVault(t *testing.T) {
	t.Helper()
	cmd := exec.Command("curl", "-sf", "http://127.0.0.1:8200/v1/sys/health")
	if err := cmd.Run(); err != nil {
		t.Skip("Vault dev server not available")
	}
}

func testVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	c, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func seedVaultData(t *testing.T, c *vault.Client) {
	t.Helper()
	ctx := context.Background()

	// Enable secret/ mount if needed
	c.EnableKVv2(ctx, "secret")

	// Seed a GitHub token
	c.WriteKVv2(ctx, "secret", "users/testuser/gh", map[string]any{
		"token": "ghp_testtoken123",
		"user":  "testuser",
	})

	// Seed a Docker config
	c.WriteKVv2(ctx, "secret", "users/testuser/docker", map[string]any{
		"registry": "docker.io",
		"auth":     "dGVzdDp0ZXN0",
	})
}

func TestEngine_RunOnce(t *testing.T) {
	skipIfNoVault(t)

	vc := testVaultClient(t)
	seedVaultData(t, vc)

	dir := t.TempDir()
	ghPath := filepath.Join(dir, "hosts.yml")
	dockerPath := filepath.Join(dir, "config.json")
	statePath := filepath.Join(dir, "state.json")

	cfg := &config.Config{
		Vault: config.VaultConfig{
			KVMount:    "secret",
			UserPrefix: "users/",
		},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:   ghPath,
					Format: "yaml",
					Template: `github.com:
  oauth_token: "{{.token}}"
  user: "{{.user}}"
  git_protocol: https`,
					Merge: "deep",
				},
			},
			{
				Name:     "docker",
				VaultKey: "docker",
				Target: config.Target{
					Path:   dockerPath,
					Format: "json",
					Template: `{
  "auths": {
    "{{.registry}}": {
      "auth": "{{.auth}}"
    }
  }
}`,
					Merge: "deep",
				},
			},
		},
	}

	engine := NewEngine(cfg, vc, "testuser", statePath)
	err := engine.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Verify gh hosts.yml was created
	ghData, err := os.ReadFile(ghPath)
	if err != nil {
		t.Fatalf("read gh output: %v", err)
	}
	if !strings.Contains(string(ghData), "ghp_testtoken123") {
		t.Errorf("gh output missing token:\n%s", ghData)
	}

	// Verify docker config.json was created
	dockerData, err := os.ReadFile(dockerPath)
	if err != nil {
		t.Fatalf("read docker output: %v", err)
	}
	var dockerConfig map[string]any
	json.Unmarshal(dockerData, &dockerConfig)
	auths, _ := dockerConfig["auths"].(map[string]any)
	if auths["docker.io"] == nil {
		t.Errorf("docker config missing docker.io auth:\n%s", dockerData)
	}

	// Verify state was updated
	store := NewStateStore(statePath)
	store.Load()
	ghState := store.Get("gh")
	if ghState.VaultVersion < 1 {
		t.Errorf("gh vault_version = %d, want >= 1", ghState.VaultVersion)
	}
	if ghState.FileChecksum == "" {
		t.Error("gh file_checksum is empty")
	}
}

func TestEngine_RunOnceSkipsUnchanged(t *testing.T) {
	skipIfNoVault(t)

	vc := testVaultClient(t)
	seedVaultData(t, vc)

	dir := t.TempDir()
	ghPath := filepath.Join(dir, "hosts.yml")
	statePath := filepath.Join(dir, "state.json")

	cfg := &config.Config{
		Vault: config.VaultConfig{
			KVMount:    "secret",
			UserPrefix: "users/",
		},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     ghPath,
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"{{.token}}\"",
					Merge:    "deep",
				},
			},
		},
	}

	engine := NewEngine(cfg, vc, "testuser", statePath)

	// First run — should write
	engine.RunOnce(context.Background())
	info1, _ := os.Stat(ghPath)
	modTime1 := info1.ModTime()

	// Small delay
	time.Sleep(50 * time.Millisecond)

	// Second run — should skip (no change in Vault)
	engine.RunOnce(context.Background())
	info2, _ := os.Stat(ghPath)
	modTime2 := info2.ModTime()

	if !modTime1.Equal(modTime2) {
		t.Error("file was rewritten despite no Vault changes")
	}
}

func TestEngine_RunOnceResyncAfterFileDeleted(t *testing.T) {
	skipIfNoVault(t)

	vc := testVaultClient(t)
	seedVaultData(t, vc)

	dir := t.TempDir()
	ghPath := filepath.Join(dir, "hosts.yml")
	statePath := filepath.Join(dir, "state.json")

	cfg := &config.Config{
		Vault: config.VaultConfig{
			KVMount:    "secret",
			UserPrefix: "users/",
		},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     ghPath,
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"{{.token}}\"",
					Merge:    "deep",
				},
			},
		},
	}

	engine := NewEngine(cfg, vc, "testuser", statePath)

	// First run — should write
	engine.RunOnce(context.Background())
	if _, err := os.Stat(ghPath); err != nil {
		t.Fatalf("file not created after first sync: %v", err)
	}

	// Delete the target file
	os.Remove(ghPath)

	// Second run — should re-sync because file is missing
	engine.RunOnce(context.Background())

	data, err := os.ReadFile(ghPath)
	if err != nil {
		t.Fatalf("file not recreated after re-sync: %v", err)
	}
	if !strings.Contains(string(data), "ghp_testtoken123") {
		t.Errorf("re-synced file missing token:\n%s", data)
	}
}

func TestEngine_RunOnceResyncAfterFileModified(t *testing.T) {
	skipIfNoVault(t)

	vc := testVaultClient(t)
	seedVaultData(t, vc)

	dir := t.TempDir()
	ghPath := filepath.Join(dir, "hosts.yml")
	statePath := filepath.Join(dir, "state.json")

	cfg := &config.Config{
		Vault: config.VaultConfig{
			KVMount:    "secret",
			UserPrefix: "users/",
		},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     ghPath,
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"{{.token}}\"",
					Merge:    "deep",
				},
			},
		},
	}

	engine := NewEngine(cfg, vc, "testuser", statePath)

	// First run — should write
	engine.RunOnce(context.Background())

	// Modify the target file externally (simulates removing a section)
	os.WriteFile(ghPath, []byte("{}\n"), 0644)

	// Second run — should re-sync because file content changed
	engine.RunOnce(context.Background())

	data, err := os.ReadFile(ghPath)
	if err != nil {
		t.Fatalf("read file after re-sync: %v", err)
	}
	if !strings.Contains(string(data), "ghp_testtoken123") {
		t.Errorf("re-synced file missing token:\n%s", data)
	}
}

// TestEngine_RunLoopAfterInitialSyncHook confirms three contracts
// of the RunLoop public API:
//
//  1. The AfterInitialSync hook fires exactly once, between the
//     initial RunOnce and the long-running loop. The daemon uses
//     this to gate sd_notify(READY=1) and the web /readyz flag.
//  2. The hook fires AFTER the initial RunOnce completes (proven
//     by checking the target file exists at the time the hook
//     runs).
//  3. The loop body itself does not implicitly perform a *second*
//     sync — once the hook has fired, only the ticker / event
//     triggers move the engine forward. With a one-hour sync
//     interval and a short context timeout, a spurious second
//     RunOnce would re-write the file (the test pins file
//     modification time to catch this).
//
// Runs as a standard unit test (no skipIfNoVault) — the httptest
// server serves /sys/health as 503 (so the Enterprise events
// subscription is skipped) and a valid KVv2 envelope for the
// secret read (so a real RunOnce actually writes a file). This
// is what makes the negative-second-sync assertion load-bearing:
// a future regression that re-introduces an implicit sync inside
// the loop body would advance the file's mtime, which we check.
func TestEngine_RunLoopAfterInitialSyncHook(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /sys/health: fail so the engine treats this as a
		// community Vault and skips event subscription.
		if strings.HasSuffix(r.URL.Path, "/sys/health") {
			http.Error(w, "vault unavailable", http.StatusServiceUnavailable)
			return
		}
		// /v1/{mount}/data/{path}: return a valid KVv2
		// envelope so a successful RunOnce writes the file.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{"token": "test-token-value"},
				"metadata": map[string]any{
					"version":       json.Number("1"),
					"created_time":  "2024-01-01T00:00:00Z",
					"deletion_time": "",
					"destroyed":     false,
				},
			},
		})
	}))
	defer ts.Close()

	vc, err := vault.NewClient(vault.Config{Address: ts.URL, Token: "test"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	dir := t.TempDir()
	ghPath := filepath.Join(dir, "hosts.yml")
	statePath := filepath.Join(dir, "state.json")

	cfg := &config.Config{
		Vault: config.VaultConfig{
			KVMount:    "secret",
			UserPrefix: "users/",
		},
		Sync: config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     ghPath,
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: \"{{.token}}\"",
					Merge:    "deep",
				},
			},
		},
	}

	engine := NewEngine(cfg, vc, "testuser", statePath)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	var (
		hookCalls          int
		fileExistedAtHook  bool
		mtimeAtHook        time.Time
	)
	if err := engine.RunLoop(ctx, AfterInitialSync(func() {
		hookCalls++
		if info, err := os.Stat(ghPath); err == nil {
			fileExistedAtHook = true
			mtimeAtHook = info.ModTime()
		}
	})); err != nil {
		t.Fatalf("RunLoop: %v", err)
	}
	if hookCalls != 1 {
		t.Errorf("AfterInitialSync hook called %d time(s), want 1", hookCalls)
	}
	if !fileExistedAtHook {
		t.Error("AfterInitialSync fired before the initial RunOnce wrote the target file")
	}
	// A spurious second RunOnce inside the loop body would
	// advance the file's mtime past mtimeAtHook (the engine
	// would refresh content / permissions). With the one-hour
	// sync interval, the ticker can't have fired in our 200ms
	// window, so any post-hook write is a regression.
	if info, err := os.Stat(ghPath); err != nil {
		t.Fatalf("stat target after loop: %v", err)
	} else if !info.ModTime().Equal(mtimeAtHook) {
		t.Errorf("target mtime advanced after the hook (%v → %v) — loop performed a redundant second sync", mtimeAtHook, info.ModTime())
	}
}
