# Plan 1: Foundation — Paths, Config, Template, File Handlers

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational packages that have no Vault dependency — OS paths, YAML config parsing, template rendering, and all four file format handlers (YAML, JSON, INI, netrc).

**Architecture:** Bottom-up layered packages under `internal/`. Each package is independently testable with unit tests. File handlers implement a common `FileHandler` interface. Template package renders Go templates with custom functions. Config package parses the system YAML config into validated Go structs.

**Tech Stack:** Go 1.25+, `gopkg.in/yaml.v3`, `gopkg.in/ini.v1`, `github.com/jdx/go-netrc`

---

## File Structure

```
dotvault/
├── go.mod
├── go.sum
├── Makefile
├── internal/
│   ├── paths/
│   │   ├── paths.go              # OS-specific path resolution
│   │   └── paths_test.go
│   ├── config/
│   │   ├── config.go             # YAML config parsing & validation
│   │   └── config_test.go
│   ├── tmpl/
│   │   ├── tmpl.go               # Template rendering with custom funcs
│   │   └── tmpl_test.go
│   └── handlers/
│       ├── handler.go            # FileHandler interface + factory
│       ├── yaml.go               # YAML read/merge/write
│       ├── yaml_test.go
│       ├── json.go               # JSON read/merge/write
│       ├── json_test.go
│       ├── ini.go                # INI read/merge/write
│       ├── ini_test.go
│       ├── netrc.go              # Netrc read/merge/write
│       ├── netrc_test.go
│       └── testdata/             # Fixture files for handler tests
│           ├── existing.yml
│           ├── incoming.yml
│           ├── merged.yml
│           ├── existing.json
│           ├── incoming.json
│           ├── merged.json
│           ├── existing.ini
│           ├── incoming.ini
│           ├── merged.ini
│           ├── existing.netrc
│           └── merged.netrc
```

Note: the template package is named `tmpl` to avoid colliding with the stdlib `template` package.

---

### Task 1: Go Module Init + Makefile

**Files:**
- Create: `go.mod`
- Create: `Makefile`

- [ ] **Step 1: Initialize Go module**

Run:
```bash
go mod init github.com/goodtune/dotvault
```

Expected: `go.mod` created with module path `github.com/goodtune/dotvault`.

- [ ] **Step 2: Create Makefile**

Create `Makefile`:

```makefile
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: test
test:
	go test ./...

.PHONY: build
build:
	go build $(LDFLAGS) -o dist/dotvault ./cmd/dotvault

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-linux-amd64 ./cmd/dotvault

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/dotvault-linux-arm64 ./cmd/dotvault

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-darwin-amd64 ./cmd/dotvault

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/dotvault-darwin-arm64 ./cmd/dotvault

build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-windows-amd64.exe ./cmd/dotvault

.PHONY: clean
clean:
	rm -rf dist/
```

- [ ] **Step 3: Create .gitignore**

Create `.gitignore`:

```
dist/
```

- [ ] **Step 4: Commit**

```bash
git add go.mod Makefile .gitignore
git commit -m "feat: initialize Go module and Makefile"
```

---

### Task 2: Paths Package

**Files:**
- Create: `internal/paths/paths.go`
- Create: `internal/paths/paths_test.go`

- [ ] **Step 1: Write failing tests for paths**

Create `internal/paths/paths_test.go`:

```go
package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot get home dir: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "tilde prefix",
			input: "~/.config/gh/hosts.yml",
			want:  filepath.Join(home, ".config/gh/hosts.yml"),
		},
		{
			name:  "tilde alone",
			input: "~",
			want:  home,
		},
		{
			name:  "no tilde",
			input: "/etc/foo/bar",
			want:  "/etc/foo/bar",
		},
		{
			name:  "tilde in middle not expanded",
			input: "/foo/~/bar",
			want:  "/foo/~/bar",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHome(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ExpandHome(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSystemConfigPath(t *testing.T) {
	path := SystemConfigPath()
	if path == "" {
		t.Fatal("SystemConfigPath() returned empty string")
	}
	// Just verify it ends with the expected filename
	if filepath.Base(path) != "config.yaml" {
		t.Errorf("SystemConfigPath() = %q, want basename config.yaml", path)
	}
}

func TestCacheDir(t *testing.T) {
	dir := CacheDir()
	if dir == "" {
		t.Fatal("CacheDir() returned empty string")
	}
	// Should contain "dotvault" somewhere in the path
	if filepath.Base(dir) != "dotvault" {
		t.Errorf("CacheDir() = %q, want dir ending in dotvault", dir)
	}
}

func TestLogDir(t *testing.T) {
	dir := LogDir()
	if dir == "" {
		t.Fatal("LogDir() returned empty string")
	}
}

func TestVaultTokenPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	path := VaultTokenPath()
	want := filepath.Join(home, ".vault-token")
	if path != want {
		t.Errorf("VaultTokenPath() = %q, want %q", path, want)
	}
}

func TestUsername(t *testing.T) {
	name, err := Username()
	if err != nil {
		t.Fatalf("Username() error: %v", err)
	}
	if name == "" {
		t.Fatal("Username() returned empty string")
	}
	// Should not contain backslash (domain prefix stripped)
	for _, c := range name {
		if c == '\\' {
			t.Errorf("Username() = %q, contains backslash (domain not stripped)", name)
		}
	}
}

func TestPlatformPaths(t *testing.T) {
	// Verify paths are appropriate for current OS
	switch runtime.GOOS {
	case "darwin":
		if got := CacheDir(); filepath.Dir(got) != filepath.Join(mustHomeDir(t), "Library/Caches") {
			t.Errorf("CacheDir() on darwin = %q, want parent ~/Library/Caches", got)
		}
	case "linux":
		if got := CacheDir(); filepath.Dir(got) != filepath.Join(mustHomeDir(t), ".cache") {
			t.Errorf("CacheDir() on linux = %q, want parent ~/.cache", got)
		}
	}
}

func mustHomeDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("cannot get home dir: %v", err)
	}
	return home
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/paths/`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement paths package**

Create `internal/paths/paths.go`:

```go
package paths

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// SystemConfigPath returns the OS-appropriate path for the system config file.
func SystemConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/dotvault/config.yaml"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "dotvault", "config.yaml")
	default: // linux and others
		// Check XDG_CONFIG_DIRS first
		if dirs := os.Getenv("XDG_CONFIG_DIRS"); dirs != "" {
			for _, dir := range strings.Split(dirs, ":") {
				p := filepath.Join(dir, "dotvault", "config.yaml")
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
		return "/etc/xdg/dotvault/config.yaml"
	}
}

// CacheDir returns the OS-appropriate cache directory for dotvault.
func CacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(mustHomeDir(), "Library", "Caches", "dotvault")
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "dotvault", "cache")
	default:
		return filepath.Join(mustHomeDir(), ".cache", "dotvault")
	}
}

// LogDir returns the OS-appropriate log directory for dotvault.
func LogDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(mustHomeDir(), "Library", "Logs", "dotvault")
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "dotvault", "logs")
	default:
		return filepath.Join(mustHomeDir(), ".cache", "dotvault", "logs")
	}
}

// VaultTokenPath returns the path to the Vault token file.
func VaultTokenPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("USERPROFILE"), ".vault-token")
	default:
		return filepath.Join(mustHomeDir(), ".vault-token")
	}
}

// Username returns the current OS username with any domain prefix stripped.
func Username() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user: %w", err)
	}
	name := u.Username
	// Strip domain prefix (e.g., DOMAIN\gary → gary)
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	return name, nil
}

// ExpandHome expands a leading ~ in a path to the user's home directory.
func ExpandHome(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if path == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home: %w", err)
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func mustHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Sprintf("cannot determine home directory: %v", err))
	}
	return home
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/paths/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/paths/
git commit -m "feat: add paths package for OS-specific path resolution"
```

---

### Task 3: Config Package

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write failing tests for config**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValid(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: gh
    description: "GitHub CLI token"
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{.token}}"
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Vault.Address = %q, want %q", cfg.Vault.Address, "https://vault.example.com:8200")
	}
	if cfg.Vault.KVMount != "kv" {
		t.Errorf("Vault.KVMount = %q, want %q", cfg.Vault.KVMount, "kv")
	}
	if cfg.Vault.UserPrefix != "users/" {
		t.Errorf("Vault.UserPrefix = %q, want default %q", cfg.Vault.UserPrefix, "users/")
	}
	if cfg.Vault.AuthMethod != "oidc" {
		t.Errorf("Vault.AuthMethod = %q, want %q", cfg.Vault.AuthMethod, "oidc")
	}
	if cfg.Sync.Interval != 5*time.Minute {
		t.Errorf("Sync.Interval = %v, want %v", cfg.Sync.Interval, 5*time.Minute)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(cfg.Rules))
	}
	r := cfg.Rules[0]
	if r.Name != "gh" {
		t.Errorf("Rule.Name = %q, want %q", r.Name, "gh")
	}
	if r.Target.Format != "yaml" {
		t.Errorf("Rule.Target.Format = %q, want %q", r.Target.Format, "yaml")
	}
	if r.Target.Merge != "deep" {
		t.Errorf("Rule.Target.Merge = %q, want %q", r.Target.Merge, "deep")
	}
}

func TestLoadCustomUserPrefix(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  user_prefix: "team/engineering/"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.UserPrefix != "team/engineering/" {
		t.Errorf("Vault.UserPrefix = %q, want %q", cfg.Vault.UserPrefix, "team/engineering/")
	}
}

func TestLoadWebConfig(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

web:
  enabled: true
  listen: "127.0.0.1:8200"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.Web.Enabled {
		t.Error("Web.Enabled = false, want true")
	}
	if cfg.Web.Listen != "127.0.0.1:8200" {
		t.Errorf("Web.Listen = %q, want %q", cfg.Web.Listen, "127.0.0.1:8200")
	}
}

func TestLoadMissingAddress(t *testing.T) {
	yaml := `
vault:
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing vault address")
	}
}

func TestLoadNoRules(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules: []
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty rules")
	}
}

func TestLoadInvalidInterval(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "not-a-duration"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid interval")
	}
}

func TestLoadDuplicateRuleNames(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
  - name: gh
    vault_key: "gh2"
    target:
      path: "~/.config/gh/other.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate rule names")
	}
}

func TestLoadInvalidFormat(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: xml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid format 'xml'")
	}
}

func TestLoadNonLoopbackWebAddress(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"

sync:
  interval: "5m"

web:
  enabled: true
  listen: "0.0.0.0:8200"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      merge: deep
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-loopback web address")
	}
}

func TestLoadOAuthRule(t *testing.T) {
	yaml := `
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  auth_method: "oidc"

sync:
  interval: "5m"

rules:
  - name: github-app
    vault_key: "github-app"
    oauth:
      engine_path: "github/token"
      provider: "GitHub"
      scopes:
        - repo
        - read:org
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{.token}}"
      merge: deep
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	r := cfg.Rules[0]
	if r.OAuth == nil {
		t.Fatal("Rule.OAuth is nil, want non-nil")
	}
	if r.OAuth.EnginePath != "github/token" {
		t.Errorf("OAuth.EnginePath = %q, want %q", r.OAuth.EnginePath, "github/token")
	}
	if r.OAuth.Provider != "GitHub" {
		t.Errorf("OAuth.Provider = %q, want %q", r.OAuth.Provider, "GitHub")
	}
	if len(r.OAuth.Scopes) != 2 {
		t.Errorf("len(OAuth.Scopes) = %d, want 2", len(r.OAuth.Scopes))
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement config package**

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level system configuration.
type Config struct {
	Vault VaultConfig `yaml:"vault"`
	Sync  SyncConfig  `yaml:"sync"`
	Web   WebConfig   `yaml:"web"`
	Rules []Rule      `yaml:"rules"`
}

// VaultConfig holds Vault connection settings.
type VaultConfig struct {
	Address       string `yaml:"address"`
	CACert        string `yaml:"ca_cert"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify"`
	KVMount       string `yaml:"kv_mount"`
	UserPrefix    string `yaml:"user_prefix"`
	AuthMethod    string `yaml:"auth_method"`
	AuthRole      string `yaml:"auth_role"`
	AuthMount     string `yaml:"auth_mount"`
}

// SyncConfig holds sync settings.
type SyncConfig struct {
	Interval time.Duration `yaml:"-"`
	RawInterval string    `yaml:"interval"`
}

// WebConfig holds optional web UI settings.
type WebConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

// Rule defines a single sync rule.
type Rule struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	VaultKey    string      `yaml:"vault_key"`
	OAuth       *OAuthConfig `yaml:"oauth"`
	Target      Target      `yaml:"target"`
}

// OAuthConfig holds optional OAuth2 settings for a rule.
type OAuthConfig struct {
	EnginePath string   `yaml:"engine_path"`
	Provider   string   `yaml:"provider"`
	Scopes     []string `yaml:"scopes"`
}

// Target defines where and how a secret is written.
type Target struct {
	Path     string `yaml:"path"`
	Format   string `yaml:"format"`
	Template string `yaml:"template"`
	Merge    string `yaml:"merge"`
}

var validFormats = map[string]bool{
	"yaml":  true,
	"json":  true,
	"ini":   true,
	"netrc": true,
}

// Load reads and validates a config file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	// Vault address required
	if c.Vault.Address == "" {
		return fmt.Errorf("vault.address is required")
	}

	// Default KV mount
	if c.Vault.KVMount == "" {
		c.Vault.KVMount = "kv"
	}

	// Default user prefix
	if c.Vault.UserPrefix == "" {
		c.Vault.UserPrefix = "users/"
	}

	// Parse sync interval
	if c.Sync.RawInterval == "" {
		c.Sync.Interval = 15 * time.Minute // default fallback interval
	} else {
		d, err := time.ParseDuration(c.Sync.RawInterval)
		if err != nil {
			return fmt.Errorf("sync.interval %q: %w", c.Sync.RawInterval, err)
		}
		c.Sync.Interval = d
	}

	// Web UI validation
	if c.Web.Enabled {
		if c.Web.Listen == "" {
			c.Web.Listen = "127.0.0.1:8200"
		}
		if err := validateLoopback(c.Web.Listen); err != nil {
			return fmt.Errorf("web.listen: %w", err)
		}
	}

	// Rules validation
	if len(c.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	seen := make(map[string]bool)
	for i, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("rules[%d].name is required", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true

		if r.VaultKey == "" {
			return fmt.Errorf("rules[%d] (%s): vault_key is required", i, r.Name)
		}
		if r.Target.Path == "" {
			return fmt.Errorf("rules[%d] (%s): target.path is required", i, r.Name)
		}
		if !validFormats[r.Target.Format] {
			return fmt.Errorf("rules[%d] (%s): invalid format %q (must be yaml, json, ini, or netrc)", i, r.Name, r.Target.Format)
		}
	}

	return nil
}

func validateLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Try resolving hostname
		addrs, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("cannot resolve %q: %w", host, err)
		}
		for _, a := range addrs {
			ip = net.ParseIP(a)
			if ip != nil && !ip.IsLoopback() {
				return fmt.Errorf("address %q resolves to non-loopback %s", addr, a)
			}
		}
		return nil
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("address %q is not loopback", addr)
	}
	return nil
}
```

- [ ] **Step 4: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/config/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/ go.mod go.sum
git commit -m "feat: add config package for YAML config parsing and validation"
```

---

### Task 4: Template Package

**Files:**
- Create: `internal/tmpl/tmpl.go`
- Create: `internal/tmpl/tmpl_test.go`

- [ ] **Step 1: Write failing tests for template rendering**

Create `internal/tmpl/tmpl_test.go`:

```go
package tmpl

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestRender(t *testing.T) {
	tests := []struct {
		name     string
		template string
		data     map[string]any
		want     string
		wantErr  bool
	}{
		{
			name:     "simple substitution",
			template: `token: "{{.token}}"`,
			data:     map[string]any{"token": "abc123"},
			want:     `token: "abc123"`,
		},
		{
			name: "multiple fields",
			template: `github.com:
  oauth_token: "{{.token}}"
  user: "{{.user}}"
  git_protocol: https`,
			data: map[string]any{"token": "ghp_xxx", "user": "gary"},
			want: `github.com:
  oauth_token: "ghp_xxx"
  user: "gary"
  git_protocol: https`,
		},
		{
			name:     "default function with value present",
			template: `port: {{default .port "8080"}}`,
			data:     map[string]any{"port": "9090"},
			want:     `port: 9090`,
		},
		{
			name:     "default function with missing value",
			template: `port: {{default .port "8080"}}`,
			data:     map[string]any{},
			want:     `port: 8080`,
		},
		{
			name:     "base64encode",
			template: `auth: {{base64encode .creds}}`,
			data:     map[string]any{"creds": "user:pass"},
			want:     `auth: ` + base64.StdEncoding.EncodeToString([]byte("user:pass")),
		},
		{
			name:     "base64decode",
			template: `plain: {{base64decode .encoded}}`,
			data:     map[string]any{"encoded": base64.StdEncoding.EncodeToString([]byte("hello"))},
			want:     `plain: hello`,
		},
		{
			name:     "quote function",
			template: `val: {{quote .val}}`,
			data:     map[string]any{"val": `it's a "test"`},
			want:     `val: 'it'"'"'s a "test"'`,
		},
		{
			name:     "invalid template syntax",
			template: `{{.foo`,
			data:     map[string]any{},
			wantErr:  true,
		},
		{
			name:     "missing required field errors",
			template: `{{.token}}`,
			data:     map[string]any{},
			want:     `<no value>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.name, tt.template, tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Render() =\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestRenderEnvFunction(t *testing.T) {
	os.Setenv("DOTVAULT_TEST_VAR", "test-value")
	defer os.Unsetenv("DOTVAULT_TEST_VAR")

	got, err := Render("env-test", `home: {{env "DOTVAULT_TEST_VAR"}}`, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `home: test-value`
	if got != want {
		t.Errorf("Render() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/tmpl/`
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Implement template package**

Create `internal/tmpl/tmpl.go`:

```go
package tmpl

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"text/template"
)

// Render parses and executes a Go template with custom functions.
// The data map is the dot context.
func Render(name, tmplStr string, data map[string]any) (string, error) {
	t, err := template.New(name).Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("parse template %s: %w", name, err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template %s: %w", name, err)
	}

	return buf.String(), nil
}

var funcMap = template.FuncMap{
	"env":          envFunc,
	"base64encode": base64EncodeFunc,
	"base64decode": base64DecodeFunc,
	"default":      defaultFunc,
	"quote":        quoteFunc,
}

func envFunc(key string) string {
	return os.Getenv(key)
}

func base64EncodeFunc(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func base64DecodeFunc(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64decode: %w", err)
	}
	return string(b), nil
}

func defaultFunc(val any, fallback string) string {
	if val == nil {
		return fallback
	}
	s := fmt.Sprintf("%v", val)
	if s == "" || s == "<no value>" {
		return fallback
	}
	return s
}

func quoteFunc(s string) string {
	// Shell-safe single quoting: wrap in single quotes,
	// escape embedded single quotes with '"'"'
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tmpl/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tmpl/
git commit -m "feat: add template package with custom functions"
```

---

### Task 5: Handler Interface + Factory

**Files:**
- Create: `internal/handlers/handler.go`

- [ ] **Step 1: Create the FileHandler interface and factory**

Create `internal/handlers/handler.go`:

```go
package handlers

import (
	"fmt"
	"os"
)

// FileHandler defines the interface for reading, merging, and writing config files.
type FileHandler interface {
	// Read parses the target file and returns structured data.
	// If the file doesn't exist, returns empty/zero state (not an error).
	Read(path string) (any, error)

	// Merge takes existing data and incoming data and returns the merged result.
	// Existing keys not present in incoming are preserved.
	Merge(existing any, incoming any) (any, error)

	// Write serialises the merged data back to the file atomically.
	Write(path string, data any, perm os.FileMode) error
}

// Parse parses raw content (e.g., from a rendered template) into the handler's
// native data structure, suitable for passing as the "incoming" argument to Merge.
type Parser interface {
	Parse(content string) (any, error)
}

// HandlerFor returns the appropriate FileHandler for the given format.
func HandlerFor(format string) (FileHandler, error) {
	switch format {
	case "yaml":
		return &YAMLHandler{}, nil
	case "json":
		return &JSONHandler{}, nil
	case "ini":
		return &INIHandler{}, nil
	case "netrc":
		return &NetrcHandler{}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %q", format)
	}
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/handlers/handler.go
git commit -m "feat: add FileHandler interface and factory"
```

---

### Task 6: YAML Handler

**Files:**
- Create: `internal/handlers/yaml.go`
- Create: `internal/handlers/yaml_test.go`
- Create: `internal/handlers/testdata/existing.yml`
- Create: `internal/handlers/testdata/incoming.yml`
- Create: `internal/handlers/testdata/merged.yml`

- [ ] **Step 1: Create test fixtures**

Create `internal/handlers/testdata/existing.yml`:

```yaml
github.com:
  oauth_token: "old-token"
  user: gary
  git_protocol: https
github.example.com:
  oauth_token: "enterprise-token"
  user: gary
```

Create `internal/handlers/testdata/incoming.yml`:

```yaml
github.com:
  oauth_token: "new-token-from-vault"
  user: gary
  git_protocol: https
```

Create `internal/handlers/testdata/merged.yml`:

```yaml
github.com:
  oauth_token: "new-token-from-vault"
  user: gary
  git_protocol: https
github.example.com:
  oauth_token: "enterprise-token"
  user: gary
```

- [ ] **Step 2: Write failing tests**

Create `internal/handlers/yaml_test.go`:

```go
package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestYAMLHandler_ReadExisting(t *testing.T) {
	h := &YAMLHandler{}
	data, err := h.Read("testdata/existing.yml")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	node, ok := data.(*yaml.Node)
	if !ok {
		t.Fatalf("Read() returned %T, want *yaml.Node", data)
	}
	if node.Kind != yaml.DocumentNode {
		t.Errorf("node.Kind = %d, want DocumentNode (%d)", node.Kind, yaml.DocumentNode)
	}
}

func TestYAMLHandler_ReadMissing(t *testing.T) {
	h := &YAMLHandler{}
	data, err := h.Read("testdata/nonexistent.yml")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	// Should return an empty document node
	node, ok := data.(*yaml.Node)
	if !ok {
		t.Fatalf("Read() returned %T, want *yaml.Node", data)
	}
	if node.Kind != yaml.DocumentNode {
		t.Errorf("node.Kind = %d, want DocumentNode", node.Kind)
	}
}

func TestYAMLHandler_Parse(t *testing.T) {
	h := &YAMLHandler{}
	data, err := h.Parse(`github.com:
  oauth_token: "new-token"`)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	node, ok := data.(*yaml.Node)
	if !ok {
		t.Fatalf("Parse() returned %T, want *yaml.Node", data)
	}
	if node.Kind != yaml.DocumentNode {
		t.Errorf("node.Kind = %d, want DocumentNode", node.Kind)
	}
}

func TestYAMLHandler_MergeDeep(t *testing.T) {
	h := &YAMLHandler{}

	existing, err := h.Read("testdata/existing.yml")
	if err != nil {
		t.Fatalf("Read existing: %v", err)
	}
	incoming, err := h.Read("testdata/incoming.yml")
	if err != nil {
		t.Fatalf("Read incoming: %v", err)
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	// Write merged to temp and compare with expected
	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.yml")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	want, err := os.ReadFile("testdata/merged.yml")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("merged output:\n%s\nwant:\n%s", got, want)
	}
}

func TestYAMLHandler_MergePreservesExistingKeys(t *testing.T) {
	h := &YAMLHandler{}

	existingYAML := `top:
  keep_this: original
  update_this: old`
	incomingYAML := `top:
  update_this: new
  add_this: added`

	existing, _ := h.Parse(existingYAML)
	incoming, _ := h.Parse(incomingYAML)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	// Serialize and check all three keys present
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.yml")
	h.Write(outPath, merged, 0644)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	for _, want := range []string{"keep_this: original", "update_this: new", "add_this: added"} {
		if !contains(s, want) {
			t.Errorf("merged output missing %q:\n%s", want, s)
		}
	}
}

func TestYAMLHandler_WriteAtomicAndPermissions(t *testing.T) {
	h := &YAMLHandler{}
	data, _ := h.Parse(`key: value`)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.yml")
	if err := h.Write(outPath, data, 0600); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
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

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/handlers/`
Expected: FAIL — `YAMLHandler` not defined.

- [ ] **Step 4: Implement YAML handler**

Create `internal/handlers/yaml.go`:

```go
package handlers

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// YAMLHandler handles YAML files with deep merge using yaml.Node trees.
type YAMLHandler struct{}

func (h *YAMLHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyYAMLDoc(), nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return emptyYAMLDoc(), nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}
	return &doc, nil
}

func (h *YAMLHandler) Parse(content string) (any, error) {
	if content == "" {
		return emptyYAMLDoc(), nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, fmt.Errorf("parse yaml content: %w", err)
	}
	return &doc, nil
}

func (h *YAMLHandler) Merge(existing any, incoming any) (any, error) {
	existDoc, ok := existing.(*yaml.Node)
	if !ok {
		return nil, fmt.Errorf("existing: expected *yaml.Node, got %T", existing)
	}
	incDoc, ok := incoming.(*yaml.Node)
	if !ok {
		return nil, fmt.Errorf("incoming: expected *yaml.Node, got %T", incoming)
	}

	// Both should be DocumentNodes wrapping the actual content
	if existDoc.Kind != yaml.DocumentNode || incDoc.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("expected DocumentNode, got kinds %d and %d", existDoc.Kind, incDoc.Kind)
	}

	// Empty existing doc — just return incoming
	if len(existDoc.Content) == 0 {
		return incDoc, nil
	}
	// Empty incoming — return existing unchanged
	if len(incDoc.Content) == 0 {
		return existDoc, nil
	}

	mergeNodes(existDoc.Content[0], incDoc.Content[0])
	return existDoc, nil
}

func (h *YAMLHandler) Write(path string, data any, perm os.FileMode) error {
	doc, ok := data.(*yaml.Node)
	if !ok {
		return fmt.Errorf("expected *yaml.Node, got %T", data)
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	return atomicWrite(path, out, perm)
}

// mergeNodes recursively merges src into dst.
// For MappingNodes: add/update keys from src, preserve existing keys not in src.
// For other node types: replace dst with src.
func mergeNodes(dst, src *yaml.Node) {
	if dst.Kind != yaml.MappingNode || src.Kind != yaml.MappingNode {
		// Replace entirely for non-mapping nodes
		*dst = *src
		return
	}

	// Iterate over src key/value pairs
	for i := 0; i < len(src.Content); i += 2 {
		srcKey := src.Content[i]
		srcVal := src.Content[i+1]

		found := false
		for j := 0; j < len(dst.Content); j += 2 {
			dstKey := dst.Content[j]
			if dstKey.Value == srcKey.Value {
				// Key exists — recurse if both values are mappings, else replace
				if dst.Content[j+1].Kind == yaml.MappingNode && srcVal.Kind == yaml.MappingNode {
					mergeNodes(dst.Content[j+1], srcVal)
				} else {
					dst.Content[j+1] = srcVal
				}
				found = true
				break
			}
		}

		if !found {
			dst.Content = append(dst.Content, srcKey, srcVal)
		}
	}
}

func emptyYAMLDoc() *yaml.Node {
	return &yaml.Node{
		Kind: yaml.DocumentNode,
	}
}

// atomicWrite writes data to a temp file then renames for atomic replacement.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".dotvault-*")
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
	if err := os.Chmod(tmpName, perm); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/handlers/ -v -run TestYAML
```

Expected: all YAML tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/handlers/yaml.go internal/handlers/yaml_test.go internal/handlers/handler.go internal/handlers/testdata/ go.mod go.sum
git commit -m "feat: add YAML handler with deep merge via yaml.Node"
```

---

### Task 7: JSON Handler

**Files:**
- Create: `internal/handlers/json.go`
- Create: `internal/handlers/json_test.go`
- Create: `internal/handlers/testdata/existing.json`
- Create: `internal/handlers/testdata/incoming.json`
- Create: `internal/handlers/testdata/merged.json`

- [ ] **Step 1: Create test fixtures**

Create `internal/handlers/testdata/existing.json`:

```json
{
  "auths": {
    "docker.io": {
      "auth": "old-auth-token"
    },
    "ghcr.io": {
      "auth": "ghcr-token"
    }
  },
  "credsStore": "desktop"
}
```

Create `internal/handlers/testdata/incoming.json`:

```json
{
  "auths": {
    "docker.io": {
      "auth": "new-auth-token"
    }
  }
}
```

Create `internal/handlers/testdata/merged.json`:

```json
{
  "auths": {
    "docker.io": {
      "auth": "new-auth-token"
    },
    "ghcr.io": {
      "auth": "ghcr-token"
    }
  },
  "credsStore": "desktop"
}
```

- [ ] **Step 2: Write failing tests**

Create `internal/handlers/json_test.go`:

```go
package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONHandler_ReadExisting(t *testing.T) {
	h := &JSONHandler{}
	data, err := h.Read("testdata/existing.json")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("Read() returned %T, want map[string]any", data)
	}
	if _, ok := m["auths"]; !ok {
		t.Error("missing key 'auths' in parsed data")
	}
}

func TestJSONHandler_ReadMissing(t *testing.T) {
	h := &JSONHandler{}
	data, err := h.Read("testdata/nonexistent.json")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	m, ok := data.(map[string]any)
	if !ok {
		t.Fatalf("Read() returned %T, want map[string]any", data)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestJSONHandler_Parse(t *testing.T) {
	h := &JSONHandler{}
	data, err := h.Parse(`{"key": "value"}`)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	m := data.(map[string]any)
	if m["key"] != "value" {
		t.Errorf("parsed key = %v, want 'value'", m["key"])
	}
}

func TestJSONHandler_MergeDeep(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Read("testdata/existing.json")
	incoming, _ := h.Read("testdata/incoming.json")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.json")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	want, _ := os.ReadFile("testdata/merged.json")

	// Compare as parsed JSON to ignore whitespace differences
	var gotMap, wantMap map[string]any
	json.Unmarshal(got, &gotMap)
	json.Unmarshal(want, &wantMap)

	gotJSON, _ := json.Marshal(gotMap)
	wantJSON, _ := json.Marshal(wantMap)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("merged output:\n%s\nwant:\n%s", got, want)
	}
}

func TestJSONHandler_MergePreservesExistingKeys(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Parse(`{"a": {"keep": "yes", "update": "old"}, "b": "stays"}`)
	incoming, _ := h.Parse(`{"a": {"update": "new", "add": "added"}}`)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	m := merged.(map[string]any)

	// Top-level "b" preserved
	if m["b"] != "stays" {
		t.Errorf("top-level 'b' = %v, want 'stays'", m["b"])
	}

	a := m["a"].(map[string]any)
	if a["keep"] != "yes" {
		t.Errorf("a.keep = %v, want 'yes'", a["keep"])
	}
	if a["update"] != "new" {
		t.Errorf("a.update = %v, want 'new'", a["update"])
	}
	if a["add"] != "added" {
		t.Errorf("a.add = %v, want 'added'", a["add"])
	}
}

func TestJSONHandler_MergeArraysReplaced(t *testing.T) {
	h := &JSONHandler{}

	existing, _ := h.Parse(`{"items": [1, 2, 3]}`)
	incoming, _ := h.Parse(`{"items": [4, 5]}`)

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	m := merged.(map[string]any)
	items := m["items"].([]any)
	if len(items) != 2 {
		t.Errorf("items length = %d, want 2 (arrays replaced wholesale)", len(items))
	}
}

func TestJSONHandler_WriteTrailingNewline(t *testing.T) {
	h := &JSONHandler{}
	data, _ := h.Parse(`{"key": "value"}`)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.json")
	h.Write(outPath, data, 0644)

	got, _ := os.ReadFile(outPath)
	if got[len(got)-1] != '\n' {
		t.Error("output missing trailing newline")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/handlers/ -run TestJSON`
Expected: FAIL — `JSONHandler` not defined.

- [ ] **Step 4: Implement JSON handler**

Create `internal/handlers/json.go`:

```go
package handlers

import (
	"encoding/json"
	"fmt"
	"os"
)

// JSONHandler handles JSON files with deep merge.
type JSONHandler struct{}

func (h *JSONHandler) Read(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse json %s: %w", path, err)
	}
	return m, nil
}

func (h *JSONHandler) Parse(content string) (any, error) {
	if content == "" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		return nil, fmt.Errorf("parse json content: %w", err)
	}
	return m, nil
}

func (h *JSONHandler) Merge(existing any, incoming any) (any, error) {
	dst, ok := existing.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("existing: expected map[string]any, got %T", existing)
	}
	src, ok := incoming.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("incoming: expected map[string]any, got %T", incoming)
	}

	return deepMergeJSON(dst, src), nil
}

func (h *JSONHandler) Write(path string, data any, perm os.FileMode) error {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("expected map[string]any, got %T", data)
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	// Trailing newline
	out = append(out, '\n')

	return atomicWrite(path, out, perm)
}

// deepMergeJSON recursively merges src into dst.
// Maps are merged recursively. All other types (arrays, scalars) are replaced.
func deepMergeJSON(dst, src map[string]any) map[string]any {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}

		// If both are maps, recurse
		dstMap, dstOk := dstVal.(map[string]any)
		srcMap, srcOk := srcVal.(map[string]any)
		if dstOk && srcOk {
			dst[key] = deepMergeJSON(dstMap, srcMap)
		} else {
			// Replace (arrays, scalars, type mismatch)
			dst[key] = srcVal
		}
	}
	return dst
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/handlers/ -v -run TestJSON`
Expected: all JSON tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/handlers/json.go internal/handlers/json_test.go internal/handlers/testdata/existing.json internal/handlers/testdata/incoming.json internal/handlers/testdata/merged.json
git commit -m "feat: add JSON handler with recursive deep merge"
```

---

### Task 8: INI Handler

**Files:**
- Create: `internal/handlers/ini.go`
- Create: `internal/handlers/ini_test.go`
- Create: `internal/handlers/testdata/existing.ini`
- Create: `internal/handlers/testdata/incoming.ini`
- Create: `internal/handlers/testdata/merged.ini`

- [ ] **Step 1: Create test fixtures**

Create `internal/handlers/testdata/existing.ini`:

```ini
; NPM configuration
//registry.npmjs.org/:_authToken=old-token
registry=https://registry.npmjs.org/
```

Create `internal/handlers/testdata/incoming.ini`:

```ini
//registry.npmjs.org/:_authToken=new-token-from-vault
```

Create `internal/handlers/testdata/merged.ini`:

```ini
; NPM configuration
//registry.npmjs.org/:_authToken=new-token-from-vault
registry=https://registry.npmjs.org/
```

- [ ] **Step 2: Write failing tests**

Create `internal/handlers/ini_test.go`:

```go
package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestINIHandler_ReadExisting(t *testing.T) {
	h := &INIHandler{}
	data, err := h.Read("testdata/existing.ini")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil")
	}
}

func TestINIHandler_ReadMissing(t *testing.T) {
	h := &INIHandler{}
	data, err := h.Read("testdata/nonexistent.ini")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil for missing file")
	}
}

func TestINIHandler_Parse(t *testing.T) {
	h := &INIHandler{}
	data, err := h.Parse("key=value\nother=thing")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if data == nil {
		t.Fatal("Parse() returned nil")
	}
}

func TestINIHandler_MergeLineReplace(t *testing.T) {
	h := &INIHandler{}

	existing, _ := h.Read("testdata/existing.ini")
	incoming, _ := h.Parse("//registry.npmjs.org/:_authToken=new-token-from-vault")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.ini")
	if err := h.Write(outPath, merged, 0644); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Token should be updated
	if !strings.Contains(s, "new-token-from-vault") {
		t.Errorf("merged output missing updated token:\n%s", s)
	}
	// Old token should be gone
	if strings.Contains(s, "old-token") {
		t.Errorf("merged output still contains old token:\n%s", s)
	}
	// Registry setting preserved
	if !strings.Contains(s, "registry=https://registry.npmjs.org/") {
		t.Errorf("merged output missing preserved registry setting:\n%s", s)
	}
}

func TestINIHandler_MergeAppendsNewKey(t *testing.T) {
	h := &INIHandler{}

	existing, _ := h.Parse("existing_key=existing_value")
	incoming, _ := h.Parse("new_key=new_value")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.ini")
	h.Write(outPath, merged, 0644)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	if !strings.Contains(s, "existing_key=existing_value") {
		t.Errorf("missing existing key:\n%s", s)
	}
	if !strings.Contains(s, "new_key=new_value") {
		t.Errorf("missing new key:\n%s", s)
	}
}

func TestINIHandler_MergeWithSections(t *testing.T) {
	h := &INIHandler{}

	existing, _ := h.Parse("[section1]\nkey1=old\nkey2=keep\n\n[section2]\nkey3=stays")
	incoming, _ := h.Parse("[section1]\nkey1=new\nkey4=added")

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.ini")
	h.Write(outPath, merged, 0644)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	if !strings.Contains(s, "key1=new") {
		t.Errorf("key1 not updated:\n%s", s)
	}
	if !strings.Contains(s, "key2=keep") {
		t.Errorf("key2 not preserved:\n%s", s)
	}
	if !strings.Contains(s, "key3=stays") {
		t.Errorf("key3 not preserved:\n%s", s)
	}
	if !strings.Contains(s, "key4=added") {
		t.Errorf("key4 not added:\n%s", s)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/handlers/ -run TestINI`
Expected: FAIL — `INIHandler` not defined.

- [ ] **Step 4: Implement INI handler**

Create `internal/handlers/ini.go`:

```go
package handlers

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/ini.v1"
)

// INIHandler handles INI files with line-replace merge.
type INIHandler struct{}

func (h *INIHandler) Read(path string) (any, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ini.Empty(), nil
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowBooleanKeys:       true,
		SkipUnrecognizableLines: true,
	}, path)
	if err != nil {
		return nil, fmt.Errorf("parse ini %s: %w", path, err)
	}
	return cfg, nil
}

func (h *INIHandler) Parse(content string) (any, error) {
	if content == "" {
		return ini.Empty(), nil
	}
	cfg, err := ini.LoadSources(ini.LoadOptions{
		AllowBooleanKeys:       true,
		SkipUnrecognizableLines: true,
	}, []byte(content))
	if err != nil {
		return nil, fmt.Errorf("parse ini content: %w", err)
	}
	return cfg, nil
}

func (h *INIHandler) Merge(existing any, incoming any) (any, error) {
	dst, ok := existing.(*ini.File)
	if !ok {
		return nil, fmt.Errorf("existing: expected *ini.File, got %T", existing)
	}
	src, ok := incoming.(*ini.File)
	if !ok {
		return nil, fmt.Errorf("incoming: expected *ini.File, got %T", incoming)
	}

	// Iterate over all sections in incoming
	for _, srcSec := range src.Sections() {
		dstSec := dst.Section(srcSec.Name())

		// Iterate over all keys in the incoming section
		for _, srcKey := range srcSec.Keys() {
			if dstSec.HasKey(srcKey.Name()) {
				dstSec.Key(srcKey.Name()).SetValue(srcKey.Value())
			} else {
				dstSec.NewKey(srcKey.Name(), srcKey.Value())
			}
		}
	}

	return dst, nil
}

func (h *INIHandler) Write(path string, data any, perm os.FileMode) error {
	cfg, ok := data.(*ini.File)
	if !ok {
		return fmt.Errorf("expected *ini.File, got %T", data)
	}

	var buf bytes.Buffer
	if _, err := cfg.WriteTo(&buf); err != nil {
		return fmt.Errorf("marshal ini: %w", err)
	}

	return atomicWrite(path, buf.Bytes(), perm)
}
```

- [ ] **Step 5: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/handlers/ -v -run TestINI
```

Expected: all INI tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/handlers/ini.go internal/handlers/ini_test.go internal/handlers/testdata/existing.ini internal/handlers/testdata/incoming.ini internal/handlers/testdata/merged.ini go.mod go.sum
git commit -m "feat: add INI handler with line-replace merge"
```

---

### Task 9: Netrc Handler

**Files:**
- Create: `internal/handlers/netrc.go`
- Create: `internal/handlers/netrc_test.go`
- Create: `internal/handlers/testdata/existing.netrc`
- Create: `internal/handlers/testdata/merged.netrc`

- [ ] **Step 1: Create test fixtures**

Create `internal/handlers/testdata/existing.netrc`:

```
machine api.github.com
  login olduser
  password old-token

machine example.com
  login gary
  password existing-pass
```

Create `internal/handlers/testdata/merged.netrc`:

```
machine api.github.com
  login goodtune
  password ghx_proxyToken

machine example.com
  login gary
  password hunter2

machine newhost.com
  login newuser
  password newpass
```

- [ ] **Step 2: Write failing tests**

Create `internal/handlers/netrc_test.go`:

```go
package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetrcHandler_ReadExisting(t *testing.T) {
	h := &NetrcHandler{}
	data, err := h.Read("testdata/existing.netrc")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil")
	}
}

func TestNetrcHandler_ReadMissing(t *testing.T) {
	h := &NetrcHandler{}
	data, err := h.Read("testdata/nonexistent.netrc")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data == nil {
		t.Fatal("Read() returned nil for missing file")
	}
}

func TestNetrcHandler_MergeUpdatesExisting(t *testing.T) {
	h := &NetrcHandler{}

	existing, _ := h.Read("testdata/existing.netrc")

	// Vault data: each key is a machine name, value is JSON with login+password
	incoming := NetrcVaultData{
		"api.github.com": {Login: "goodtune", Password: "ghx_proxyToken"},
		"example.com":    {Login: "gary", Password: "hunter2"},
		"newhost.com":    {Login: "newuser", Password: "newpass"},
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "merged.netrc")
	if err := h.Write(outPath, merged, 0600); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Updated entries
	if !strings.Contains(s, "goodtune") {
		t.Errorf("missing updated login 'goodtune':\n%s", s)
	}
	if !strings.Contains(s, "ghx_proxyToken") {
		t.Errorf("missing updated password:\n%s", s)
	}
	if !strings.Contains(s, "hunter2") {
		t.Errorf("missing updated password 'hunter2':\n%s", s)
	}

	// New entry appended
	if !strings.Contains(s, "newhost.com") {
		t.Errorf("missing new machine 'newhost.com':\n%s", s)
	}

	// Old credentials gone
	if strings.Contains(s, "old-token") {
		t.Errorf("still contains old password:\n%s", s)
	}
}

func TestNetrcHandler_MergePreservesUnmanagedEntries(t *testing.T) {
	h := &NetrcHandler{}

	existing, _ := h.Read("testdata/existing.netrc")

	// Only update one machine — the other should remain untouched
	incoming := NetrcVaultData{
		"api.github.com": {Login: "updated", Password: "updated-pass"},
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.netrc")
	h.Write(outPath, merged, 0600)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	// Unmanaged entry preserved
	if !strings.Contains(s, "example.com") {
		t.Errorf("unmanaged machine 'example.com' was removed:\n%s", s)
	}
	if !strings.Contains(s, "existing-pass") {
		t.Errorf("unmanaged entry password was changed:\n%s", s)
	}
}

func TestNetrcHandler_WritePermissions(t *testing.T) {
	h := &NetrcHandler{}
	existing, _ := h.Read("testdata/existing.netrc")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.netrc")
	h.Write(outPath, existing, 0600)

	info, _ := os.Stat(outPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestNetrcHandler_MergeFromEmptyFile(t *testing.T) {
	h := &NetrcHandler{}

	existing, _ := h.Read("testdata/nonexistent.netrc")
	incoming := NetrcVaultData{
		"newhost.com": {Login: "user", Password: "pass"},
	}

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.netrc")
	h.Write(outPath, merged, 0600)

	got, _ := os.ReadFile(outPath)
	s := string(got)

	if !strings.Contains(s, "newhost.com") {
		t.Errorf("missing new machine:\n%s", s)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/handlers/ -run TestNetrc`
Expected: FAIL — `NetrcHandler` not defined.

- [ ] **Step 4: Implement netrc handler**

Create `internal/handlers/netrc.go`:

```go
package handlers

import (
	"fmt"
	"os"

	"github.com/jdx/go-netrc"
)

// NetrcHandler handles .netrc files with per-entry merge.
type NetrcHandler struct{}

// NetrcCredential represents login+password for a machine.
type NetrcCredential struct {
	Login    string
	Password string
}

// NetrcVaultData maps machine names to credentials.
// This is the expected "incoming" type for Merge.
type NetrcVaultData map[string]NetrcCredential

func (h *NetrcHandler) Read(path string) (any, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return netrc.New(path), nil
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	n, err := netrc.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("parse netrc %s: %w", path, err)
	}
	return n, nil
}

func (h *NetrcHandler) Merge(existing any, incoming any) (any, error) {
	n, ok := existing.(*netrc.Netrc)
	if !ok {
		return nil, fmt.Errorf("existing: expected *netrc.Netrc, got %T", existing)
	}
	vaultData, ok := incoming.(NetrcVaultData)
	if !ok {
		return nil, fmt.Errorf("incoming: expected NetrcVaultData, got %T", incoming)
	}

	for machine, cred := range vaultData {
		m := n.Machine(machine)
		if m != nil {
			// Update existing entry
			m.Set("login", cred.Login)
			m.Set("password", cred.Password)
		} else {
			// Add new entry
			n.AddMachine(machine, cred.Login, cred.Password)
		}
	}

	return n, nil
}

func (h *NetrcHandler) Write(path string, data any, perm os.FileMode) error {
	n, ok := data.(*netrc.Netrc)
	if !ok {
		return fmt.Errorf("expected *netrc.Netrc, got %T", data)
	}

	content := n.Render()
	return atomicWrite(path, []byte(content), perm)
}
```

- [ ] **Step 5: Fetch dependencies and run tests**

Run:
```bash
go mod tidy
go test ./internal/handlers/ -v -run TestNetrc
```

Expected: all Netrc tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/handlers/netrc.go internal/handlers/netrc_test.go internal/handlers/testdata/existing.netrc internal/handlers/testdata/merged.netrc go.mod go.sum
git commit -m "feat: add netrc handler using go-netrc with per-entry merge"
```

---

### Task 10: Full Handler Integration Test

**Files:**
- Create: `internal/handlers/handler_test.go`

- [ ] **Step 1: Write integration test for the factory and full round-trip**

Create `internal/handlers/handler_test.go`:

```go
package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHandlerFor(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"yaml", false},
		{"json", false},
		{"ini", false},
		{"netrc", false},
		{"xml", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			h, err := HandlerFor(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h == nil {
				t.Fatal("handler is nil")
			}
		})
	}
}

func TestYAMLRoundTrip(t *testing.T) {
	h, _ := HandlerFor("yaml")
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yml")

	// Write initial content
	yh := h.(*YAMLHandler)
	initial, _ := yh.Parse("key1: value1\nkey2: value2")
	h.Write(path, initial, 0644)

	// Read it back
	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	// Merge new data
	incoming, _ := yh.Parse("key2: updated\nkey3: added")
	merged, err := h.Merge(data, incoming)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	// Write merged
	h.Write(path, merged, 0644)

	// Verify final content
	got, _ := os.ReadFile(path)
	s := string(got)
	for _, want := range []string{"key1: value1", "key2: updated", "key3: added"} {
		if !containsStr(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	h, _ := HandlerFor("json")
	jh := h.(*JSONHandler)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")

	initial, _ := jh.Parse(`{"a": "1", "b": "2"}`)
	h.Write(path, initial, 0644)

	data, _ := h.Read(path)
	incoming, _ := jh.Parse(`{"b": "updated", "c": "added"}`)
	merged, _ := h.Merge(data, incoming)
	h.Write(path, merged, 0644)

	got, _ := os.ReadFile(path)
	s := string(got)
	for _, want := range []string{`"a": "1"`, `"b": "updated"`, `"c": "added"`} {
		if !containsStr(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}
```

- [ ] **Step 2: Run all tests**

Run: `go test ./internal/handlers/ -v`
Expected: all tests PASS.

- [ ] **Step 3: Run full test suite**

Run: `go test ./...`
Expected: all packages PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/handlers/handler_test.go
git commit -m "feat: add handler integration tests and round-trip verification"
```
