package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/goodtune/dotvault/internal/vaulttest"
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
		Token:   vaulttest.RootToken(t),
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

// TestEngine_RunOnceReappliesOnTemplateChange is the end-to-end guard for the
// ruleRenderHash skip gate: with the Vault secret and the on-disk file both
// unchanged, editing only the rule's template must still re-render and rewrite
// the file. Before the rule-hash gate this skipped forever (version + checksum
// both matched), which is the ssh_config forward "{{ username }} edit never applies"
// bug this fixes.
func TestEngine_RunOnceReappliesOnTemplateChange(t *testing.T) {
	skipIfNoVault(t)

	vc := testVaultClient(t)
	seedVaultData(t, vc)

	dir := t.TempDir()
	ghPath := filepath.Join(dir, "hosts.yml")
	statePath := filepath.Join(dir, "state.json")

	mkRule := func(host string) config.Rule {
		return config.Rule{
			Name:     "gh",
			VaultKey: "gh",
			Target: config.Target{
				Path:     ghPath,
				Format:   "yaml",
				Template: "github.com:\n  oauth_token: \"{{.token}}\"\n  host: " + host,
				Merge:    "deep",
			},
		}
	}

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{mkRule("oldhost")},
	}

	engine := NewEngine(cfg, vc, "testuser", statePath)

	// First run writes the old template output.
	engine.RunOnce(context.Background())
	first, err := os.ReadFile(ghPath)
	if err != nil {
		t.Fatalf("read after first sync: %v", err)
	}
	if !strings.Contains(string(first), "host: oldhost") {
		t.Fatalf("first sync missing old host:\n%s", first)
	}

	// Swap only the template — the Vault secret is untouched, and the file is
	// exactly what we last wrote, so the only thing that changed is the rule
	// definition (and thus its render hash).
	engine.UpdateConfig([]config.Rule{mkRule("newhost")}, 0)

	engine.RunOnce(context.Background())
	second, err := os.ReadFile(ghPath)
	if err != nil {
		t.Fatalf("read after second sync: %v", err)
	}
	if !strings.Contains(string(second), "host: newhost") {
		t.Errorf("template change not re-applied (skip gate still firing):\n%s", second)
	}
	if strings.Contains(string(second), "host: oldhost") {
		t.Errorf("old template output lingering after re-sync:\n%s", second)
	}
}

// TestEngine_RunOnceKeylessRule exercises a rule with no vault_key: it manages
// a file built purely from {{ username }} and literals, never contacts Vault
// (so a nil Vault client is fine), and still resolves the username. It then
// confirms the keyless skip path (unchanged file is not rewritten) and that a
// template edit re-applies via the rule-hash gate without a secret version to
// lean on.
func TestEngine_RunOnceKeylessRule(t *testing.T) {
	dir := t.TempDir()
	sshPath := filepath.Join(dir, "config")
	statePath := filepath.Join(dir, "state.json")

	mkRule := func(forward string) config.Rule {
		return config.Rule{
			Name: "ssh", // no VaultKey
			Target: config.Target{
				Path:     sshPath,
				Format:   "ssh_config",
				Template: "Host *\n    User {{ username }}\n    RemoteForward /home/{{ username }}/.ssh/dotvault.sock " + forward + "\n",
			},
		}
	}

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{mkRule("127.0.0.1:8200")},
	}

	// nil Vault client: a keyless rule must never dereference it.
	engine := NewEngine(cfg, nil, "goodtune", statePath)

	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (keyless): %v", err)
	}
	first, err := os.ReadFile(sshPath)
	if err != nil {
		t.Fatalf("read after first sync: %v", err)
	}
	if !strings.Contains(string(first), "User goodtune") {
		t.Errorf("username not resolved in keyless rule:\n%s", first)
	}
	if !strings.Contains(string(first), "/home/goodtune/.ssh/dotvault.sock 127.0.0.1:8200") {
		t.Errorf("forward not written from {{ username }}:\n%s", first)
	}

	// Second run with no change must skip — the file is not rewritten.
	info1, _ := os.Stat(sshPath)
	time.Sleep(20 * time.Millisecond)
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (keyless, unchanged): %v", err)
	}
	info2, _ := os.Stat(sshPath)
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("keyless rule rewrote an unchanged file (skip gate not firing without a vault version)")
	}

	// Editing only the template must re-apply, even though there is no secret
	// version to compare — the rule hash carries it.
	engine.UpdateConfig([]config.Rule{mkRule("127.0.0.1:8201")}, 0)
	if err := engine.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce (keyless, template changed): %v", err)
	}
	second, err := os.ReadFile(sshPath)
	if err != nil {
		t.Fatalf("read after template change: %v", err)
	}
	if !strings.Contains(string(second), "dotvault.sock 127.0.0.1:8201") {
		t.Errorf("keyless template change not re-applied:\n%s", second)
	}
	if strings.Contains(string(second), "127.0.0.1:8200\n") {
		t.Errorf("old forward target lingering after re-sync:\n%s", second)
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
		hookCalls         int
		fileExistedAtHook bool
		mtimeAtHook       time.Time
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

// TestEngine_RunKeyless pins the pre-authentication pass the daemon runs
// between its listeners coming up and its auth gate: only the rules with no
// vault_key are synced, and the pass neither contacts Vault nor disturbs the
// keyed rules it leaves alone. The Vault client points at a closed port, so a
// read attempted on behalf of the keyed rule would surface as a failure count
// and a written file — both asserted against.
func TestEngine_RunKeyless(t *testing.T) {
	dir := t.TempDir()
	keylessPath := filepath.Join(dir, "ssh_config")
	keyedPath := filepath.Join(dir, "hosts.yml")
	statePath := filepath.Join(dir, "state.json")

	vc, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:1", // nothing listens here
		Token:   "unused",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{
				Name: "ssh", // keyless
				Target: config.Target{
					Path:     keylessPath,
					Format:   "ssh_config",
					Template: "Host vault\n    User {{ username }}\n",
				},
			},
			{
				Name:     "gh",
				VaultKey: "gh",
				Target: config.Target{
					Path:     keyedPath,
					Format:   "yaml",
					Template: "github.com:\n  oauth_token: {{ .token }}\n",
				},
			},
		},
	}

	engine := NewEngine(cfg, vc, "goodtune", statePath)

	ok, failed := engine.RunKeyless(context.Background())
	if ok != 1 || failed != 0 {
		t.Fatalf("RunKeyless = (%d ok, %d failed), want (1, 0) — the keyed rule must not be attempted and the keyless one needs no vault", ok, failed)
	}

	got, err := os.ReadFile(keylessPath)
	if err != nil {
		t.Fatalf("keyless rule did not write its target: %v", err)
	}
	if !strings.Contains(string(got), "User goodtune") {
		t.Errorf("username not resolved in keyless rule:\n%s", got)
	}

	if _, err := os.Stat(keyedPath); !os.IsNotExist(err) {
		t.Errorf("RunKeyless synced a rule with a vault_key (stat %s: %v)", keyedPath, err)
	}

	// The state the pass writes is the same state the first full cycle reads,
	// so that cycle must find nothing to do. This is the claim that keeps the
	// pass from meaning "every keyless file is written twice on every start".
	info1, err := os.Stat(keylessPath)
	if err != nil {
		t.Fatalf("stat after first pass: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if ok, failed := engine.RunKeyless(context.Background()); ok != 1 || failed != 0 {
		t.Fatalf("second RunKeyless = (%d ok, %d failed), want (1, 0)", ok, failed)
	}
	info2, err := os.Stat(keylessPath)
	if err != nil {
		t.Fatalf("stat after second pass: %v", err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("second keyless pass rewrote an unchanged file — the state written pre-auth is not being read by the next cycle")
	}

	// Nothing keyless configured: the pass is a no-op the daemon reports
	// nothing about, rather than a logged pass that does no work.
	keyedOnly := NewEngine(&config.Config{
		Vault: cfg.Vault,
		Sync:  cfg.Sync,
		Rules: cfg.Rules[1:],
	}, vc, "goodtune", filepath.Join(dir, "state-keyed.json"))
	if ok, failed := keyedOnly.RunKeyless(context.Background()); ok != 0 || failed != 0 {
		t.Errorf("RunKeyless = (%d ok, %d failed) for a rule set where every rule names a vault_key, want (0, 0)", ok, failed)
	}
}

// TestEngine_RunKeylessPerRuleIsolation pins that one unrenderable keyless rule
// does not cost the others their sync — the engine's per-rule isolation
// invariant, which an early return on the first error would silently drop.
func TestEngine_RunKeylessPerRuleIsolation(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad")
	goodPath := filepath.Join(dir, "good")

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{
				Name: "bad", // first, so an early return would skip "good"
				Target: config.Target{
					Path:     badPath,
					Format:   "ssh_config",
					Template: "Host x\n    User {{ .nope | nosuchfunc }}\n",
				},
			},
			{
				Name: "good",
				Target: config.Target{
					Path:     goodPath,
					Format:   "ssh_config",
					Template: "Host y\n    User {{ username }}\n",
				},
			},
		},
	}

	// nil Vault client: neither rule may dereference it.
	engine := NewEngine(cfg, nil, "goodtune", filepath.Join(dir, "state.json"))

	ok, failed := engine.RunKeyless(context.Background())
	if ok != 1 || failed != 1 {
		t.Errorf("RunKeyless = (%d ok, %d failed), want (1, 1)", ok, failed)
	}
	if _, err := os.Stat(goodPath); err != nil {
		t.Errorf("a later keyless rule was skipped after an earlier one failed: %v", err)
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Errorf("the failing rule wrote a file (stat %s: %v)", badPath, err)
	}
}

// TestEngine_RunKeylessDryRun pins that --dry-run suppresses the writes of the
// pre-authentication pass too. The daemon sets DryRun on the engine before the
// pass runs, and a pass that ignored it would make --dry-run mutate the very
// files it promises not to touch.
func TestEngine_RunKeylessDryRun(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ssh_config")

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{{
			Name: "ssh",
			Target: config.Target{
				Path:     target,
				Format:   "ssh_config",
				Template: "Host z\n    User {{ username }}\n",
			},
		}},
	}

	engine := NewEngine(cfg, nil, "goodtune", filepath.Join(dir, "state.json"))
	engine.DryRun = true

	if ok, failed := engine.RunKeyless(context.Background()); ok != 1 || failed != 0 {
		t.Fatalf("RunKeyless = (%d ok, %d failed), want (1, 0)", ok, failed)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("dry-run keyless pass wrote %s (stat: %v)", target, err)
	}
}

// TestEngine_RunKeylessStopsOnCancelledContext pins the between-rules
// cancellation check: syncRule is synchronous file I/O that observes no
// deadline, so stopping between rules is the only granularity available — and
// without it a shutdown would work through the whole rule set writing files it
// has been told to stop writing.
func TestEngine_RunKeylessStopsOnCancelledContext(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ssh_config")

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{{
			Name: "ssh",
			Target: config.Target{
				Path:     target,
				Format:   "ssh_config",
				Template: "Host z\n    User {{ username }}\n",
			},
		}},
	}

	engine := NewEngine(cfg, nil, "goodtune", filepath.Join(dir, "state.json"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if ok, failed := engine.RunKeyless(ctx); ok != 0 || failed != 0 {
		t.Errorf("RunKeyless = (%d ok, %d failed) under a cancelled context, want (0, 0)", ok, failed)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("cancelled keyless pass still wrote %s (stat: %v)", target, err)
	}
}

// TestSyncOutcome pins the label a finished cycle carries on
// dotvault.sync.ticks. The cancelled case is the one with history: an
// interrupted cycle used to break out of the rule loop without setting an
// error, so RunOnce returned nil and recorded the partial cycle as "ok" —
// inflating the success rate with cycles that never ran their whole rule set.
// Folding it into "error" instead would be the opposite mistake, putting every
// daemon shutdown into the failure rate an operator alerts on.
func TestSyncOutcome(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"complete", nil, "ok"},
		{"rule failed", errors.New("render template: boom"), "error"},
		{"cancelled", context.Canceled, "cancelled"},
		{"deadline", context.DeadlineExceeded, "cancelled"},
		{"wrapped cancellation", fmt.Errorf("sync cycle interrupted after 2 rules: %w", context.Canceled), "cancelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := syncOutcome(tc.err); got != tc.want {
				t.Errorf("syncOutcome(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestEngine_RunOnceReportsInterruption pins that a cycle cancelled *between*
// rules is reported as interrupted rather than as a clean sweep. This is the
// exact shape that previously returned nil: some rules already synced fine, no
// rule error, and then cancellation — so nothing ever set the error and RunOnce
// recorded a partial cycle as a completed one.
//
// The interleaving is forced through the include predicate rather than raced
// for: runRulesLocked calls it before the between-rules ctx check, so a
// predicate that cancels once it has admitted the first rule puts the loop in
// precisely that state every run.
func TestEngine_RunOnceReportsInterruption(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first")
	secondPath := filepath.Join(dir, "second")

	mkRule := func(name, path, host string) config.Rule {
		return config.Rule{
			Name: name, // keyless throughout: no vault client is needed
			Target: config.Target{
				Path:     path,
				Format:   "ssh_config",
				Template: "Host " + host + "\n    User {{ username }}\n",
			},
		}
	}

	cfg := &config.Config{
		Vault: config.VaultConfig{KVMount: "secret", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{mkRule("first", firstPath, "one"), mkRule("second", secondPath, "two")},
	}
	engine := NewEngine(cfg, nil, "goodtune", filepath.Join(dir, "state.json"))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var admitted int
	include := func(config.Rule) bool {
		admitted++
		if admitted == 2 {
			// The first rule has been synced; stop the cycle before the second.
			cancel()
		}
		return true
	}

	engine.mu.Lock()
	ok, failed, err := engine.runRulesLocked(ctx, include)
	engine.mu.Unlock()

	if ok != 1 || failed != 0 {
		t.Fatalf("runRulesLocked = (%d ok, %d failed), want (1, 0) — the setup must sync one rule cleanly and then be cancelled", ok, failed)
	}
	if err == nil {
		t.Fatal("runRulesLocked returned nil for a cycle stopped by cancellation — RunOnce would record the partial cycle as \"ok\" on dotvault.sync.ticks")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want one wrapping context.Canceled so syncOutcome can label it", err)
	}
	if got := syncOutcome(err); got != "cancelled" {
		t.Errorf("interrupted cycle labelled %q, want \"cancelled\"", got)
	}
	if _, statErr := os.Stat(firstPath); statErr != nil {
		t.Errorf("rule before the cancellation point was not synced: %v", statErr)
	}
	if _, statErr := os.Stat(secondPath); !os.IsNotExist(statErr) {
		t.Errorf("rule after the cancellation point was still synced (stat %s: %v)", secondPath, statErr)
	}
}
