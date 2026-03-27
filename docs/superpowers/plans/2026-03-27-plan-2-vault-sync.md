# Plan 2: Vault Client, Auth, Sync Engine, CLI

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Vault integration layer — client wrapper, authentication flows (token reuse, OIDC, LDAP), token lifecycle management, hybrid event/poll sync engine, and the CLI. After this plan, `dotvault run` and `dotvault sync` work end-to-end.

**Architecture:** `internal/vault` wraps the Vault SDK. `internal/auth` orchestrates authentication with pluggable methods. `internal/sync` wires vault reads, template rendering, and file handlers into a hybrid event-driven + polling loop. `cmd/dotvault` exposes CLI commands via cobra.

**Tech Stack:** Go 1.25+, `github.com/hashicorp/vault/api`, `github.com/spf13/cobra`, `github.com/pkg/browser`, `golang.org/x/term`, `nhooyr.io/websocket`

**Prerequisites:** Plan 1 (Foundation) must be complete — this plan depends on `internal/paths`, `internal/config`, `internal/tmpl`, and `internal/handlers`.

**Dev Vault:** Integration tests use a local Vault dev server at `http://127.0.0.1:8200` with root token `dev-root-token`.

---

## File Structure

```
internal/
├── vault/
│   ├── client.go            # Vault API wrapper, KVv2 reads/lists
│   ├── client_test.go       # Integration tests against dev Vault
│   ├── events.go            # WebSocket event subscription
│   └── events_test.go
├── auth/
│   ├── auth.go              # Auth orchestrator
│   ├── auth_test.go
│   ├── token.go             # Token read/write/refresh
│   ├── token_test.go
│   ├── oidc.go              # OIDC browser flow
│   ├── ldap.go              # LDAP auth
│   └── lifecycle.go         # Token lifecycle goroutine
│   └── lifecycle_test.go
├── sync/
│   ├── engine.go            # Hybrid event/poll sync loop
│   ├── engine_test.go
│   ├── state.go             # State file management
│   └── state_test.go
cmd/
└── dotvault/
    └── main.go              # CLI entry point with cobra
```

---

### Task 1: Vault Client — KVv2 Read + List

**Files:**
- Create: `internal/vault/client.go`
- Create: `internal/vault/client_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/vault/client_test.go`:

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vault/`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement Vault client**

Create `internal/vault/client.go`:

```go
package vault

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config holds Vault connection settings.
type Config struct {
	Address       string
	Token         string
	CACert        string
	TLSSkipVerify bool
}

// Secret represents a KVv2 secret with its data and version metadata.
type Secret struct {
	Data    map[string]any
	Version int
}

// Client wraps the Vault API client.
type Client struct {
	raw *vaultapi.Client
}

// NewClient creates a new Vault API client.
func NewClient(cfg Config) (*Client, error) {
	vaultCfg := vaultapi.DefaultConfig()
	vaultCfg.Address = cfg.Address

	if cfg.CACert != "" {
		tlsCfg := &vaultapi.TLSConfig{CACert: cfg.CACert}
		if err := vaultCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}
	if cfg.TLSSkipVerify {
		tlsCfg := &vaultapi.TLSConfig{Insecure: true}
		if err := vaultCfg.ConfigureTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("configure TLS skip verify: %w", err)
		}
	}

	client, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}

	return &Client{raw: client}, nil
}

// Raw returns the underlying Vault API client for direct access.
func (c *Client) Raw() *vaultapi.Client {
	return c.raw
}

// SetToken sets the auth token on the client.
func (c *Client) SetToken(token string) {
	c.raw.SetToken(token)
}

// Token returns the current auth token.
func (c *Client) Token() string {
	return c.raw.Token()
}

// ReadKVv2 reads a KVv2 secret at the given mount and path.
// Returns nil (not error) if the secret doesn't exist.
func (c *Client) ReadKVv2(ctx context.Context, mount, path string) (*Secret, error) {
	secret, err := c.raw.KVv2(mount).Get(ctx, path)
	if err != nil {
		// Check for 404 — secret doesn't exist
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read kv %s/%s: %w", mount, path, err)
	}
	if secret == nil {
		return nil, nil
	}

	version := 0
	if secret.VersionMetadata != nil {
		version = secret.VersionMetadata.Version
	}

	return &Secret{
		Data:    secret.Data,
		Version: version,
	}, nil
}

// ListKVv2 lists keys under the given path in a KVv2 mount.
func (c *Client) ListKVv2(ctx context.Context, mount, path string) ([]string, error) {
	secret, err := c.raw.Logical().ListWithContext(ctx, fmt.Sprintf("%s/metadata/%s", mount, path))
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list kv %s/%s: %w", mount, path, err)
	}
	if secret == nil {
		return nil, nil
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return nil, nil
	}

	keysSlice, ok := keysRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys type: %T", keysRaw)
	}

	keys := make([]string, len(keysSlice))
	for i, k := range keysSlice {
		keys[i] = fmt.Sprintf("%v", k)
	}
	return keys, nil
}

// EnableKVv2 enables a KVv2 secrets engine at the given path.
// Used for testing. Returns an error if it already exists (non-fatal).
func (c *Client) EnableKVv2(ctx context.Context, path string) error {
	err := c.raw.Sys().MountWithContext(ctx, path, &vaultapi.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	})
	if err != nil {
		return fmt.Errorf("enable kv-v2 at %s: %w", path, err)
	}
	return nil
}

// WriteKVv2 writes data to a KVv2 secret. Used for testing/seeding.
func (c *Client) WriteKVv2(ctx context.Context, mount, path string, data map[string]any) error {
	_, err := c.raw.KVv2(mount).Put(ctx, path, data)
	if err != nil {
		return fmt.Errorf("write kv %s/%s: %w", mount, path, err)
	}
	return nil
}

// LookupSelf returns the current token's metadata, or an error if invalid.
func (c *Client) LookupSelf(ctx context.Context) (*vaultapi.Secret, error) {
	secret, err := c.raw.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("token lookup-self: %w", err)
	}
	return secret, nil
}

// RenewSelf renews the current token.
func (c *Client) RenewSelf(ctx context.Context, increment int) (*vaultapi.Secret, error) {
	secret, err := c.raw.Auth().Token().RenewSelfWithContext(ctx, increment)
	if err != nil {
		return nil, fmt.Errorf("token renew-self: %w", err)
	}
	return secret, nil
}

func isNotFound(err error) bool {
	if respErr, ok := err.(*vaultapi.ResponseError); ok {
		return respErr.StatusCode == 404
	}
	return false
}
```

- [ ] **Step 4: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/vault/ -v
```

Expected: all PASS (with Vault dev server running).

- [ ] **Step 5: Commit**

```bash
git add internal/vault/client.go internal/vault/client_test.go go.mod go.sum
git commit -m "feat: add Vault client wrapper with KVv2 read/list/write"
```

---

### Task 2: Vault Events — WebSocket Subscription

**Files:**
- Create: `internal/vault/events.go`
- Create: `internal/vault/events_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/vault/events_test.go`:

```go
package vault

import (
	"context"
	"testing"
	"time"
)

func TestSubscribeEvents(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seedTestSecret(t, c)

	// Subscribe to kv-v2 data-write events
	events, errCh, err := c.SubscribeEvents(ctx, "kv-v2/data-write")
	if err != nil {
		// Events API may not be available in dev mode — skip gracefully
		t.Skipf("SubscribeEvents: %v (events API may not be available)", err)
	}

	// Trigger a write to generate an event
	go func() {
		time.Sleep(500 * time.Millisecond)
		c.WriteKVv2(ctx, "secret", "users/testuser/gh", map[string]any{
			"token": "updated-token",
			"user":  "testuser",
		})
	}()

	// Wait for event or timeout
	select {
	case evt := <-events:
		if evt.EventType != "kv-v2/data-write" {
			t.Errorf("event type = %q, want 'kv-v2/data-write'", evt.EventType)
		}
		if evt.Path == "" {
			t.Error("event path is empty")
		}
		t.Logf("received event: type=%s path=%s", evt.EventType, evt.Path)
	case err := <-errCh:
		t.Fatalf("event subscription error: %v", err)
	case <-ctx.Done():
		t.Skip("timed out waiting for event (events API may not support this in dev mode)")
	}
}

func TestSubscribeEventsGracefulDegradation(t *testing.T) {
	// Test that subscription to a nonexistent Vault fails gracefully
	c, err := NewClient(Config{
		Address: "http://127.0.0.1:19999", // No server here
		Token:   "fake-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = c.SubscribeEvents(ctx, "kv-v2/data-write")
	if err == nil {
		t.Error("expected error connecting to nonexistent server")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/vault/ -run TestSubscribe`
Expected: FAIL — `SubscribeEvents` not defined.

- [ ] **Step 3: Implement event subscription**

Create `internal/vault/events.go`:

```go
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"nhooyr.io/websocket"
)

// Event represents a Vault event notification.
type Event struct {
	EventType string
	Path      string
	DataPath  string
	MountPath string
	Version   int
}

// SubscribeEvents connects to the Vault Events API via WebSocket and
// returns a channel of events and an error channel.
// The caller should cancel the context to disconnect.
func (c *Client) SubscribeEvents(ctx context.Context, eventType string) (<-chan Event, <-chan error, error) {
	wsURL, err := c.buildEventsURL(eventType)
	if err != nil {
		return nil, nil, fmt.Errorf("build events URL: %w", err)
	}

	headers := make(map[string][]string)
	headers["X-Vault-Token"] = []string{c.raw.Token()}

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: headers,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("connect to events API: %w", err)
	}

	events := make(chan Event, 16)
	errCh := make(chan error, 1)

	go func() {
		defer conn.Close(websocket.StatusNormalClosure, "done")
		defer close(events)
		defer close(errCh)

		for {
			_, msg, err := conn.Read(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled, clean shutdown
				}
				errCh <- fmt.Errorf("read event: %w", err)
				return
			}

			evt, err := parseEvent(msg)
			if err != nil {
				continue // Skip unparseable events
			}

			select {
			case events <- evt:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, errCh, nil
}

func (c *Client) buildEventsURL(eventType string) (string, error) {
	addr := c.raw.Address()
	u, err := url.Parse(addr)
	if err != nil {
		return "", fmt.Errorf("parse vault address: %w", err)
	}

	// Switch scheme to ws/wss
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}

	u.Path = fmt.Sprintf("/v1/sys/events/subscribe/%s", eventType)
	q := u.Query()
	q.Set("json", "true")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// cloudEvent is the CloudEvents envelope used by Vault's Events API.
type cloudEvent struct {
	Data json.RawMessage `json:"data"`
}

type eventData struct {
	EventType string        `json:"event_type"`
	Event     eventPayload  `json:"event"`
}

type eventPayload struct {
	ID       string          `json:"id"`
	Metadata json.RawMessage `json:"metadata"`
}

type eventMetadata struct {
	Path        string `json:"path"`
	DataPath    string `json:"data_path"`
	MountPath   string `json:"mount_path"`
	Operation   string `json:"operation"`
	CurrentVersion int `json:"current_version"`
}

func parseEvent(msg []byte) (Event, error) {
	// Vault Events API wraps in CloudEvents format
	// Try to parse the nested structure
	var ce cloudEvent
	if err := json.Unmarshal(msg, &ce); err != nil {
		return Event{}, fmt.Errorf("unmarshal cloud event: %w", err)
	}

	var ed eventData
	if err := json.Unmarshal(ce.Data, &ed); err != nil {
		// Try direct parse if not wrapped
		if err2 := json.Unmarshal(msg, &ed); err2 != nil {
			return Event{}, fmt.Errorf("unmarshal event data: %w", err)
		}
	}

	var meta eventMetadata
	if err := json.Unmarshal(ed.Event.Metadata, &meta); err != nil {
		return Event{}, fmt.Errorf("unmarshal event metadata: %w", err)
	}

	// Clean up the path — remove "data/" prefix for KVv2
	path := meta.DataPath
	if path == "" {
		path = meta.Path
	}
	// Strip mount prefix and "data/" segment
	path = strings.TrimPrefix(path, meta.MountPath)
	path = strings.TrimPrefix(path, "data/")

	return Event{
		EventType: ed.EventType,
		Path:      path,
		DataPath:  meta.DataPath,
		MountPath: meta.MountPath,
		Version:   meta.CurrentVersion,
	}, nil
}
```

- [ ] **Step 4: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/vault/ -v -run TestSubscribe
```

Expected: tests pass (or skip gracefully if events API unavailable in dev mode).

- [ ] **Step 5: Commit**

```bash
git add internal/vault/events.go internal/vault/events_test.go go.mod go.sum
git commit -m "feat: add Vault Events API WebSocket subscription"
```

---

### Task 3: Auth — Token Management

**Files:**
- Create: `internal/auth/token.go`
- Create: `internal/auth/token_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/auth/token_test.go`:

```go
package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault-token")
	os.WriteFile(path, []byte("s.test-token-value\n"), 0600)

	token, err := ReadTokenFile(path)
	if err != nil {
		t.Fatalf("ReadTokenFile: %v", err)
	}
	if token != "s.test-token-value" {
		t.Errorf("token = %q, want %q", token, "s.test-token-value")
	}
}

func TestReadTokenFromFileMissing(t *testing.T) {
	token, err := ReadTokenFile("/nonexistent/path/.vault-token")
	if err != nil {
		t.Fatalf("ReadTokenFile should not error for missing file: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty for missing file", token)
	}
}

func TestReadTokenFromEnv(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "env-token-value")
	token := ReadTokenEnv()
	if token != "env-token-value" {
		t.Errorf("token = %q, want %q", token, "env-token-value")
	}
}

func TestWriteTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault-token")

	err := WriteTokenFile(path, "new-token-value")
	if err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}

	// Read it back
	data, _ := os.ReadFile(path)
	if string(data) != "new-token-value" {
		t.Errorf("file content = %q, want %q", data, "new-token-value")
	}

	// Check permissions
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestResolveToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault-token")

	// No file, no env — empty
	token := ResolveToken(path)
	if token != "" {
		t.Errorf("token = %q, want empty", token)
	}

	// File exists
	os.WriteFile(path, []byte("file-token"), 0600)
	token = ResolveToken(path)
	if token != "file-token" {
		t.Errorf("token = %q, want %q", token, "file-token")
	}

	// Env takes precedence
	t.Setenv("VAULT_TOKEN", "env-token")
	token = ResolveToken(path)
	if token != "env-token" {
		t.Errorf("token = %q, want %q (env should take precedence)", token, "env-token")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement token management**

Create `internal/auth/token.go`:

```go
package auth

import (
	"fmt"
	"os"
	"strings"
)

// ReadTokenFile reads a Vault token from a file, trimming whitespace.
// Returns empty string (not error) if file doesn't exist.
func ReadTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read token file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadTokenEnv reads the Vault token from VAULT_TOKEN environment variable.
func ReadTokenEnv() string {
	return os.Getenv("VAULT_TOKEN")
}

// ResolveToken returns a Vault token, checking VAULT_TOKEN env var first,
// then the token file. Returns empty string if neither is set.
func ResolveToken(tokenFilePath string) string {
	if token := ReadTokenEnv(); token != "" {
		return token
	}
	token, _ := ReadTokenFile(tokenFilePath)
	return token
}

// WriteTokenFile writes a Vault token to a file with 0600 permissions.
func WriteTokenFile(path string, token string) error {
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/token.go internal/auth/token_test.go
git commit -m "feat: add token file read/write/resolve"
```

---

### Task 4: Auth — Orchestrator

**Files:**
- Create: `internal/auth/auth.go`
- Create: `internal/auth/auth_test.go`
- Create: `internal/auth/oidc.go`
- Create: `internal/auth/ldap.go`

- [ ] **Step 1: Write failing tests for the auth orchestrator**

Create `internal/auth/auth_test.go`:

```go
package auth

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
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
	os.WriteFile(tokenPath, []byte("dev-root-token"), 0600)

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
	if m.VaultClient.Token() != "dev-root-token" {
		t.Errorf("token = %q, want %q", m.VaultClient.Token(), "dev-root-token")
	}
}

func TestManagerAuthenticate_EnvToken(t *testing.T) {
	skipIfNoVault(t)
	t.Setenv("VAULT_TOKEN", "dev-root-token")

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/`
Expected: FAIL — `Manager` not defined.

- [ ] **Step 3: Implement auth orchestrator and stubs**

Create `internal/auth/auth.go`:

```go
package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/goodtune/dotvault/internal/vault"
)

// Manager orchestrates Vault authentication.
type Manager struct {
	VaultClient   *vault.Client
	TokenFilePath string
	AuthMethod    string // "oidc", "ldap", "token"
	AuthMount     string // auth mount path
	AuthRole      string // optional role
	Username      string
}

// Authenticate attempts to authenticate with Vault.
// It first tries to reuse an existing token, then falls back to the configured method.
func (m *Manager) Authenticate(ctx context.Context) error {
	// Step 1: Try existing token
	token := ResolveToken(m.TokenFilePath)
	if token != "" {
		m.VaultClient.SetToken(token)
		_, err := m.VaultClient.LookupSelf(ctx)
		if err == nil {
			slog.Info("reusing existing vault token")
			return nil
		}
		slog.Warn("existing token invalid, proceeding to fresh auth", "error", err)
	}

	// Step 2: Authenticate with configured method
	switch m.AuthMethod {
	case "oidc":
		return m.authenticateOIDC(ctx)
	case "ldap":
		return m.authenticateLDAP(ctx)
	case "token":
		return fmt.Errorf("auth method 'token' requires a valid token in %s or VAULT_TOKEN env", m.TokenFilePath)
	default:
		return fmt.Errorf("unsupported auth method: %q", m.AuthMethod)
	}
}
```

Create `internal/auth/oidc.go`:

```go
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/pkg/browser"
)

func (m *Manager) authenticateOIDC(ctx context.Context) error {
	mount := m.AuthMount
	if mount == "" {
		mount = "oidc"
	}

	// Start local callback listener on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start callback listener: %w", err)
	}
	defer listener.Close()

	callbackPort := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/oidc/callback", callbackPort)

	// Request auth URL from Vault
	data := map[string]interface{}{
		"redirect_uri": callbackURL,
		"role":         m.AuthRole,
	}
	secret, err := m.VaultClient.Raw().Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		return fmt.Errorf("get OIDC auth URL: %w", err)
	}

	authURL, ok := secret.Data["auth_url"].(string)
	if !ok || authURL == "" {
		return fmt.Errorf("no auth_url in OIDC response")
	}

	// Channel to receive the callback result
	type callbackResult struct {
		code  string
		state string
		err   error
	}
	resultCh := make(chan callbackResult, 1)

	// Handle the callback
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" {
			errMsg := r.URL.Query().Get("error")
			resultCh <- callbackResult{err: fmt.Errorf("OIDC callback error: %s", errMsg)}
			fmt.Fprint(w, "Authentication failed. You can close this window.")
			return
		}
		resultCh <- callbackResult{code: code, state: state}
		fmt.Fprint(w, "Authentication successful! You can close this window.")
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Shutdown(ctx)

	// Open browser
	slog.Info("opening browser for OIDC authentication", "url", authURL)
	if err := browser.OpenURL(authURL); err != nil {
		slog.Warn("failed to open browser, please visit URL manually", "url", authURL, "error", err)
	}

	// Wait for callback
	select {
	case result := <-resultCh:
		if result.err != nil {
			return result.err
		}

		// Exchange code for token via Vault
		loginData := map[string]interface{}{
			"code":  result.code,
			"state": result.state,
		}
		loginSecret, err := m.VaultClient.Raw().Logical().WriteWithContext(ctx,
			fmt.Sprintf("auth/%s/oidc/callback", mount), loginData)
		if err != nil {
			return fmt.Errorf("OIDC token exchange: %w", err)
		}
		if loginSecret == nil || loginSecret.Auth == nil {
			return fmt.Errorf("no auth data in OIDC callback response")
		}

		token := loginSecret.Auth.ClientToken
		m.VaultClient.SetToken(token)

		if err := WriteTokenFile(m.TokenFilePath, token); err != nil {
			slog.Warn("failed to write token file", "error", err)
		}

		slog.Info("OIDC authentication successful")
		return nil

	case <-ctx.Done():
		return fmt.Errorf("OIDC auth timed out: %w", ctx.Err())
	}
}
```

Create `internal/auth/ldap.go`:

```go
package auth

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/term"
)

func (m *Manager) authenticateLDAP(ctx context.Context) error {
	mount := m.AuthMount
	if mount == "" {
		mount = "ldap"
	}

	// Prompt for password
	password, err := promptPassword(fmt.Sprintf("LDAP password for %s: ", m.Username))
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	// Authenticate via Vault
	data := map[string]interface{}{
		"password": password,
	}
	secret, err := m.VaultClient.Raw().Logical().WriteWithContext(ctx,
		fmt.Sprintf("auth/%s/login/%s", mount, m.Username), data)
	if err != nil {
		return fmt.Errorf("LDAP authentication: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("no auth data in LDAP response")
	}

	token := secret.Auth.ClientToken
	m.VaultClient.SetToken(token)

	if err := WriteTokenFile(m.TokenFilePath, token); err != nil {
		slog.Warn("failed to write token file", "error", err)
	}

	slog.Info("LDAP authentication successful")
	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after password input
	if err != nil {
		return "", err
	}
	return string(password), nil
}
```

- [ ] **Step 4: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/auth/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/ go.mod go.sum
git commit -m "feat: add auth orchestrator with token reuse, OIDC, and LDAP"
```

---

### Task 5: Auth — Token Lifecycle

**Files:**
- Create: `internal/auth/lifecycle.go`
- Create: `internal/auth/lifecycle_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/auth/lifecycle_test.go`:

```go
package auth

import (
	"context"
	"testing"
	"time"
)

func TestLifecycleManager_Start(t *testing.T) {
	skipIfNoVault(t)

	vc := mustVaultClient(t)
	vc.SetToken("dev-root-token")

	lm := NewLifecycleManager(vc, 1*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start should not block
	errCh := lm.Start(ctx)

	// Should get at least one check cycle without error
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("lifecycle error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Good — no error within timeout
	}
}

func TestLifecycleManager_NeedsReauth(t *testing.T) {
	skipIfNoVault(t)

	vc := mustVaultClient(t)
	vc.SetToken("dev-root-token")

	lm := NewLifecycleManager(vc, 1*time.Second)

	// With a valid root token, should not need reauth
	if lm.NeedsReauth() {
		t.Error("NeedsReauth() = true for valid root token")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/ -run TestLifecycle`
Expected: FAIL — `NewLifecycleManager` not defined.

- [ ] **Step 3: Implement lifecycle manager**

Create `internal/auth/lifecycle.go`:

```go
package auth

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

// LifecycleManager manages token TTL checks and renewal.
type LifecycleManager struct {
	client       *vault.Client
	checkInterval time.Duration
	needsReauth  atomic.Bool
}

// NewLifecycleManager creates a new token lifecycle manager.
func NewLifecycleManager(client *vault.Client, checkInterval time.Duration) *LifecycleManager {
	return &LifecycleManager{
		client:        client,
		checkInterval: checkInterval,
	}
}

// NeedsReauth returns true if the token is expired or needs re-authentication.
func (lm *LifecycleManager) NeedsReauth() bool {
	return lm.needsReauth.Load()
}

// Start begins the token lifecycle goroutine. Returns a channel that receives
// errors (e.g., when re-auth is needed). The goroutine stops when ctx is cancelled.
func (lm *LifecycleManager) Start(ctx context.Context) <-chan error {
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)

		ticker := time.NewTicker(lm.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := lm.checkAndRenew(ctx); err != nil {
					slog.Warn("token lifecycle check failed", "error", err)
					lm.needsReauth.Store(true)
					select {
					case errCh <- err:
					default:
					}
				}
			}
		}
	}()

	return errCh
}

func (lm *LifecycleManager) checkAndRenew(ctx context.Context) error {
	secret, err := lm.client.LookupSelf(ctx)
	if err != nil {
		return err
	}

	// Extract TTL
	ttlRaw, ok := secret.Data["ttl"]
	if !ok {
		return nil // No TTL = root token or non-expiring
	}

	var ttl time.Duration
	switch v := ttlRaw.(type) {
	case json.Number:
		secs, _ := v.Int64()
		ttl = time.Duration(secs) * time.Second
	case float64:
		ttl = time.Duration(v) * time.Second
	default:
		return nil
	}

	if ttl <= 0 {
		slog.Warn("token expired")
		lm.needsReauth.Store(true)
		return nil
	}

	// Check if renewable
	renewableRaw, _ := secret.Data["renewable"]
	renewable, _ := renewableRaw.(bool)

	// Renew at 75% of TTL
	renewThreshold := ttl / 4
	if ttl <= renewThreshold && renewable {
		slog.Info("renewing token", "ttl_remaining", ttl)
		_, err := lm.client.RenewSelf(ctx, 0)
		if err != nil {
			return err
		}
		slog.Info("token renewed successfully")
		lm.needsReauth.Store(false)
	}

	return nil
}
```

Note: Add the missing import at the top of `lifecycle.go`:

```go
import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -v -run TestLifecycle`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/lifecycle.go internal/auth/lifecycle_test.go
git commit -m "feat: add token lifecycle manager with TTL check and renewal"
```

---

### Task 6: Sync State Management

**Files:**
- Create: `internal/sync/state.go`
- Create: `internal/sync/state_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/sync/state_test.go`:

```go
package sync

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStateStore_LoadEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewStateStore(path)
	err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Rules()) != 0 {
		t.Errorf("expected empty rules, got %d", len(s.Rules()))
	}
}

func TestStateStore_GetSetSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewStateStore(path)
	s.Load()

	now := time.Now().Truncate(time.Second)
	s.Set("gh", RuleState{
		VaultVersion: 3,
		LastSynced:   now,
		FileChecksum: "sha256:abcdef",
	})

	// Save
	err := s.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into new store
	s2 := NewStateStore(path)
	s2.Load()

	rs := s2.Get("gh")
	if rs.VaultVersion != 3 {
		t.Errorf("VaultVersion = %d, want 3", rs.VaultVersion)
	}
	if !rs.LastSynced.Equal(now) {
		t.Errorf("LastSynced = %v, want %v", rs.LastSynced, now)
	}
	if rs.FileChecksum != "sha256:abcdef" {
		t.Errorf("FileChecksum = %q, want %q", rs.FileChecksum, "sha256:abcdef")
	}
}

func TestStateStore_GetMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := NewStateStore(path)
	s.Load()

	rs := s.Get("nonexistent")
	if rs.VaultVersion != 0 {
		t.Errorf("VaultVersion = %d, want 0 for missing rule", rs.VaultVersion)
	}
}

func TestFileChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	writeFile(t, path, "hello world\n")

	sum, err := FileChecksum(path)
	if err != nil {
		t.Fatalf("FileChecksum: %v", err)
	}
	if sum == "" {
		t.Error("checksum is empty")
	}
	// Same content = same checksum
	sum2, _ := FileChecksum(path)
	if sum != sum2 {
		t.Errorf("checksums differ for same content: %q vs %q", sum, sum2)
	}
}

func TestFileChecksum_Missing(t *testing.T) {
	sum, err := FileChecksum("/nonexistent/file")
	if err != nil {
		t.Fatalf("FileChecksum should not error for missing file: %v", err)
	}
	if sum != "" {
		t.Errorf("checksum = %q, want empty for missing file", sum)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}
```

Add `"os"` import to the test file.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sync/`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement state management**

Create `internal/sync/state.go`:

```go
package sync

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RuleState tracks the sync state for a single rule.
type RuleState struct {
	VaultVersion int       `json:"vault_version"`
	LastSynced   time.Time `json:"last_synced"`
	FileChecksum string    `json:"file_checksum"`
}

type stateFile struct {
	Rules map[string]RuleState `json:"rules"`
}

// StateStore manages sync state persistence.
type StateStore struct {
	path  string
	mu    sync.Mutex
	state stateFile
}

// NewStateStore creates a new state store at the given path.
func NewStateStore(path string) *StateStore {
	return &StateStore{
		path: path,
		state: stateFile{
			Rules: make(map[string]RuleState),
		},
	}
}

// Load reads the state file from disk. If the file doesn't exist, starts empty.
func (s *StateStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.state.Rules = make(map[string]RuleState)
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}

	if err := json.Unmarshal(data, &s.state); err != nil {
		return fmt.Errorf("parse state file: %w", err)
	}
	if s.state.Rules == nil {
		s.state.Rules = make(map[string]RuleState)
	}
	return nil
}

// Save writes the state file to disk atomically.
func (s *StateStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}

// Get returns the state for a rule. Returns zero-value RuleState if not found.
func (s *StateStore) Get(name string) RuleState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Rules[name]
}

// Set updates the state for a rule.
func (s *StateStore) Set(name string, rs RuleState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Rules[name] = rs
}

// Rules returns a copy of all rule states.
func (s *StateStore) Rules() map[string]RuleState {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string]RuleState, len(s.state.Rules))
	for k, v := range s.state.Rules {
		cp[k] = v
	}
	return cp
}

// FileChecksum computes sha256 of a file's contents.
// Returns empty string (not error) for missing files.
func FileChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read file for checksum: %w", err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sync/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sync/state.go internal/sync/state_test.go
git commit -m "feat: add sync state management with atomic persistence"
```

---

### Task 7: Sync Engine

**Files:**
- Create: `internal/sync/engine.go`
- Create: `internal/sync/engine_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/sync/engine_test.go`:

```go
package sync

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
	if !containsStr(string(ghData), "ghp_testtoken123") {
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
					Template: `github.com:\n  oauth_token: "{{.token}}"`,
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

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sync/ -run TestEngine`
Expected: FAIL — `NewEngine` not defined.

- [ ] **Step 3: Implement sync engine**

Create `internal/sync/engine.go`:

```go
package sync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/handlers"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/tmpl"
	"github.com/goodtune/dotvault/internal/vault"
)

// Engine manages the sync loop.
type Engine struct {
	cfg       *config.Config
	vault     *vault.Client
	username  string
	state     *StateStore
	triggerCh chan struct{}
	mu        sync.Mutex
}

// NewEngine creates a new sync engine.
func NewEngine(cfg *config.Config, vc *vault.Client, username, statePath string) *Engine {
	store := NewStateStore(statePath)
	store.Load()

	return &Engine{
		cfg:       cfg,
		vault:     vc,
		username:  username,
		state:     store,
		triggerCh: make(chan struct{}, 1),
	}
}

// TriggerSync requests an immediate sync cycle.
func (e *Engine) TriggerSync() {
	select {
	case e.triggerCh <- struct{}{}:
	default:
	}
}

// RunOnce executes a single sync cycle across all rules.
func (e *Engine) RunOnce(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var lastErr error
	for _, rule := range e.cfg.Rules {
		if err := e.syncRule(ctx, rule); err != nil {
			slog.Error("sync rule failed", "rule", rule.Name, "error", err)
			lastErr = err
		}
	}
	return lastErr
}

// RunLoop runs the hybrid event/poll sync loop until ctx is cancelled.
func (e *Engine) RunLoop(ctx context.Context) error {
	// Initial sync
	e.RunOnce(ctx)

	// Try to subscribe to events
	eventCh, errCh := e.trySubscribeEvents(ctx)

	ticker := time.NewTicker(e.cfg.Sync.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			slog.Debug("poll sync cycle")
			e.RunOnce(ctx)

		case <-e.triggerCh:
			slog.Info("manual sync triggered")
			e.RunOnce(ctx)

		case evt, ok := <-eventCh:
			if !ok {
				// Channel closed — switch to poll-only
				slog.Warn("event subscription closed, falling back to poll-only")
				eventCh = nil
				continue
			}
			slog.Info("vault event received", "path", evt.Path, "type", evt.EventType)
			e.syncRuleByPath(ctx, evt.Path)

		case err, ok := <-errCh:
			if ok && err != nil {
				slog.Warn("event subscription error, falling back to poll-only", "error", err)
				eventCh = nil
				// Try to reconnect after a delay
				go func() {
					time.Sleep(30 * time.Second)
					newEvents, newErrCh := e.trySubscribeEvents(ctx)
					if newEvents != nil {
						eventCh = newEvents
						errCh = newErrCh
						slog.Info("event subscription reconnected")
					}
				}()
			}
		}
	}
}

// State returns the underlying state store for external access.
func (e *Engine) State() *StateStore {
	return e.state
}

func (e *Engine) trySubscribeEvents(ctx context.Context) (<-chan vault.Event, <-chan error) {
	prefix := e.cfg.Vault.UserPrefix + e.username + "/"
	eventCh, errCh, err := e.vault.SubscribeEvents(ctx, "kv-v2/data-write")
	if err != nil {
		slog.Info("event subscription not available, using poll-only mode", "error", err)
		return nil, nil
	}

	// Filter events by user prefix
	filtered := make(chan vault.Event, 16)
	go func() {
		defer close(filtered)
		for evt := range eventCh {
			if hasPrefix(evt.Path, prefix) {
				filtered <- evt
			}
		}
	}()

	slog.Info("subscribed to vault events", "prefix", prefix)
	return filtered, errCh
}

func (e *Engine) syncRuleByPath(ctx context.Context, path string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	prefix := e.cfg.Vault.UserPrefix + e.username + "/"
	vaultKey := trimPrefix(path, prefix)

	for _, rule := range e.cfg.Rules {
		if rule.VaultKey == vaultKey {
			if err := e.syncRule(ctx, rule); err != nil {
				slog.Error("sync rule failed", "rule", rule.Name, "error", err)
			}
			return
		}
	}
}

func (e *Engine) syncRule(ctx context.Context, rule config.Rule) error {
	log := slog.With("rule", rule.Name)

	// Read secret from Vault
	secretPath := e.cfg.Vault.UserPrefix + e.username + "/" + rule.VaultKey
	secret, err := e.vault.ReadKVv2(ctx, e.cfg.Vault.KVMount, secretPath)
	if err != nil {
		return fmt.Errorf("read vault secret: %w", err)
	}
	if secret == nil {
		log.Warn("secret not found in vault", "path", secretPath)
		return nil
	}

	// Check version — skip if unchanged
	currentState := e.state.Get(rule.Name)
	if secret.Version == currentState.VaultVersion && currentState.VaultVersion > 0 {
		log.Debug("secret unchanged, skipping")
		return nil
	}

	// Resolve target path
	targetPath, err := paths.ExpandHome(rule.Target.Path)
	if err != nil {
		return fmt.Errorf("expand target path: %w", err)
	}

	// Get handler
	handler, err := handlers.HandlerFor(rule.Target.Format)
	if err != nil {
		return fmt.Errorf("get handler: %w", err)
	}

	// Render template if present
	var incomingData any
	if rule.Target.Template != "" {
		rendered, err := tmpl.Render(rule.Name, rule.Target.Template, secret.Data)
		if err != nil {
			return fmt.Errorf("render template: %w", err)
		}

		// Parse rendered output through handler
		parser, ok := handler.(handlers.Parser)
		if !ok {
			return fmt.Errorf("handler for %q does not support Parse", rule.Target.Format)
		}
		incomingData, err = parser.Parse(rendered)
		if err != nil {
			return fmt.Errorf("parse rendered template: %w", err)
		}
	} else {
		// No template — use vault data directly (for netrc)
		incomingData = secret.Data
	}

	// Read existing file
	existingData, err := handler.Read(targetPath)
	if err != nil {
		return fmt.Errorf("read existing file: %w", err)
	}

	// Check for external modification
	currentChecksum, _ := FileChecksum(targetPath)
	if currentChecksum != "" && currentState.FileChecksum != "" && currentChecksum != currentState.FileChecksum {
		log.Warn("file modified externally since last sync", "path", targetPath)
	}

	// Merge
	merged, err := handler.Merge(existingData, incomingData)
	if err != nil {
		return fmt.Errorf("merge data: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	// Determine file permissions
	perm := os.FileMode(0644)
	if rule.Target.Format == "netrc" {
		perm = 0600
	}

	// Write
	if err := handler.Write(targetPath, merged, perm); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	// Update state
	newChecksum, _ := FileChecksum(targetPath)
	e.state.Set(rule.Name, RuleState{
		VaultVersion: secret.Version,
		LastSynced:   time.Now(),
		FileChecksum: newChecksum,
	})
	if err := e.state.Save(); err != nil {
		log.Warn("failed to save state", "error", err)
	}

	log.Info("synced secret to file", "path", targetPath, "version", secret.Version)
	return nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func trimPrefix(s, prefix string) string {
	if hasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}
```

- [ ] **Step 4: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/sync/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/sync/engine.go internal/sync/engine_test.go
git commit -m "feat: add hybrid event/poll sync engine"
```

---

### Task 8: CLI with Cobra

**Files:**
- Create: `cmd/dotvault/main.go`

- [ ] **Step 1: Implement CLI**

Create `cmd/dotvault/main.go`:

```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/spf13/cobra"
)

var version = "dev"

var (
	flagConfig   string
	flagLogLevel string
	flagDryRun   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dotvault",
		Short: "Vault-to-file secret synchronisation daemon",
		RunE:  runDaemon,
	}

	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "override system config path")
	rootCmd.PersistentFlags().StringVar(&flagLogLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "show what would change without writing")

	rootCmd.AddCommand(
		&cobra.Command{
			Use:   "run",
			Short: "Run daemon in foreground",
			RunE:  runDaemon,
		},
		&cobra.Command{
			Use:     "sync",
			Short:   "Run one sync cycle and exit",
			Aliases: []string{},
			RunE:    runSync,
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show auth and sync status",
			RunE:  runStatus,
		},
		&cobra.Command{
			Use:   "version",
			Short: "Print version",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Println(version)
			},
		},
	)

	// --once as alias for sync
	rootCmd.PersistentFlags().Bool("once", false, "run one sync cycle and exit")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupLogging() {
	var level slog.Level
	switch flagLogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if isTerminal() {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func loadConfig() (*config.Config, error) {
	path := flagConfig
	if path == "" {
		path = paths.SystemConfigPath()
	}
	return config.Load(path)
}

func runDaemon(cmd *cobra.Command, args []string) error {
	setupLogging()

	once, _ := cmd.Flags().GetBool("once")
	if once {
		return runSync(cmd, args)
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("received shutdown signal", "signal", sig)
				cancel()
			case syscall.SIGHUP:
				slog.Info("received SIGHUP, reloading config")
				// Reload handled by engine restart in future
			}
		}
	}()

	// Authenticate
	username, vc, err := authenticate(ctx, cfg)
	if err != nil {
		return err
	}

	// Create and run engine
	statePath := filepath.Join(paths.CacheDir(), "state.json")
	engine := sync.NewEngine(cfg, vc, username, statePath)

	slog.Info("starting dotvault daemon", "version", version, "user", username)
	return engine.RunLoop(ctx)
}

func runSync(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	username, vc, err := authenticate(ctx, cfg)
	if err != nil {
		return err
	}

	statePath := filepath.Join(paths.CacheDir(), "state.json")
	engine := sync.NewEngine(cfg, vc, username, statePath)

	slog.Info("running single sync cycle", "user", username)
	return engine.RunOnce(ctx)
}

func runStatus(cmd *cobra.Command, args []string) error {
	setupLogging()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	// Try to connect to Vault
	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		fmt.Printf("Vault connection: ERROR (%v)\n", err)
		return nil
	}

	token := auth.ResolveToken(paths.VaultTokenPath())
	if token == "" {
		fmt.Println("Auth: not authenticated (no token)")
	} else {
		vc.SetToken(token)
		secret, err := vc.LookupSelf(ctx)
		if err != nil {
			fmt.Printf("Auth: token invalid (%v)\n", err)
		} else {
			ttl, _ := secret.Data["ttl"]
			fmt.Printf("Auth: authenticated (TTL: %v)\n", ttl)
		}
	}

	// Show sync state
	statePath := filepath.Join(paths.CacheDir(), "state.json")
	store := sync.NewStateStore(statePath)
	store.Load()

	fmt.Println("\nSync Rules:")
	for _, rule := range cfg.Rules {
		rs := store.Get(rule.Name)
		if rs.VaultVersion == 0 {
			fmt.Printf("  %-20s never synced\n", rule.Name)
		} else {
			fmt.Printf("  %-20s v%d synced %s\n", rule.Name, rs.VaultVersion, rs.LastSynced.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

func authenticate(ctx context.Context, cfg *config.Config) (string, *vault.Client, error) {
	username, err := paths.Username()
	if err != nil {
		return "", nil, fmt.Errorf("resolve username: %w", err)
	}

	vc, err := vault.NewClient(vault.Config{
		Address:       cfg.Vault.Address,
		CACert:        cfg.Vault.CACert,
		TLSSkipVerify: cfg.Vault.TLSSkipVerify,
	})
	if err != nil {
		return "", nil, fmt.Errorf("create vault client: %w", err)
	}

	mgr := &auth.Manager{
		VaultClient:   vc,
		TokenFilePath: paths.VaultTokenPath(),
		AuthMethod:    cfg.Vault.AuthMethod,
		AuthMount:     cfg.Vault.AuthMount,
		AuthRole:      cfg.Vault.AuthRole,
		Username:      username,
	}

	if err := mgr.Authenticate(ctx); err != nil {
		return "", nil, fmt.Errorf("authenticate: %w", err)
	}

	return username, vc, nil
}

func isTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
```

- [ ] **Step 2: Verify it compiles**

Run:
```bash
go mod tidy
go build ./cmd/dotvault/
```

Expected: compiles without errors.

- [ ] **Step 3: Test version command**

Run: `go run ./cmd/dotvault version`
Expected: prints `dev`.

- [ ] **Step 4: Commit**

```bash
git add cmd/dotvault/main.go go.mod go.sum
git commit -m "feat: add CLI with run, sync, status, and version commands"
```

---

### Task 9: End-to-End Integration Test

**Files:**
- Create: `test/integration/e2e_test.go`

- [ ] **Step 1: Write end-to-end test**

Create `test/integration/e2e_test.go`:

```go
package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/sync"
	"github.com/goodtune/dotvault/internal/vault"
)

func TestEndToEnd(t *testing.T) {
	// Skip if Vault not available
	vc, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Skip("Vault not available")
	}
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
	vc.WriteKVv2(ctx, "secret", "users/e2euser/netrc", map[string]any{
		"api.github.com": `{"login":"e2euser","password":"ghp_e2e"}`,
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
					Merge: "deep",
				},
			},
			{
				Name: "docker", VaultKey: "docker",
				Target: config.Target{
					Path: filepath.Join(dir, "docker-config.json"), Format: "json",
					Template: "{\"auths\":{\"{{.registry}}\":{\"auth\":\"{{.auth}}\"}}}",
					Merge: "deep",
				},
			},
			{
				Name: "npm", VaultKey: "npm",
				Target: config.Target{
					Path: filepath.Join(dir, ".npmrc"), Format: "ini",
					Template: "//registry.npmjs.org/:_authToken={{.token}}",
					Merge: "line-replace",
				},
			},
		},
	}

	statePath := filepath.Join(dir, "state.json")
	engine := sync.NewEngine(cfg, vc, "e2euser", statePath)

	// Run sync
	err = engine.RunOnce(ctx)
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
```

- [ ] **Step 2: Run the end-to-end test**

Run: `go test ./test/integration/ -v`
Expected: all PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/e2e_test.go
git commit -m "feat: add end-to-end integration test"
```
