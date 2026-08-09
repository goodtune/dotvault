# Managed SSH Forwards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dotvault daemon maintain resilient SSH remote-forwards that expose its own web API as a Unix socket on configured remote hosts, replacing the hand-wired external `ssh -R` that `vault.token_socket` depends on today.

**Architecture:** A new `internal/sshfwd` package owns a declarative reconciler (`Manager.Reconcile`) over a list of remotes read from a user-level `ssh.yaml`. Each remote is an independent `ManagedRemote` running a connect → forward → keepalive → backoff loop, using the existing `agent.Backend` for its SSH identity and `client.ListenUnix` for the `streamlocal-forward@openssh.com` request. All mutations funnel through `sshfwd.Registry` inside the daemon; the CLI is a thin client of the daemon's HTTP API.

**Tech Stack:** Go, `golang.org/x/crypto/ssh`, `golang.org/x/crypto/ssh/knownhosts` (for the CA-line parser only), the existing `internal/config`, `internal/agent`, `internal/web`, `internal/paths`, `internal/observability` packages.

**Design spec:** `docs/superpowers/specs/2026-08-09-managed-ssh-forwards-design.md`

## Global Constraints

- `CGO_ENABLED=0` — pure Go only. No new cgo dependencies.
- Every new config field must be extended across four surfaces **in lockstep**, with a round-trip test: `internal/config/config.go` (YAML + validation), `internal/config/registry_windows.go` (live GPO loader), `internal/regfile/regfile.go` (render `.reg`), `internal/regfile/parse.go` (parse `.reg`). This applies to the **system** `ssh:` section only — `ssh.yaml` is user-level and deliberately has no registry surface.
- All file writes are atomic: temp file with target permissions, then rename.
- `ssh.yaml` is written 0600 in a 0700 directory.
- Secret values and forwarded stream contents are never logged, even at DEBUG.
- Never use `ssh.InsecureIgnoreHostKey()` except behind the explicit `insecure_ignore_host_key` config flag, which logs a WARN naming the host on every connection attempt.
- Table-driven tests, matching the surrounding package idiom.
- Assertions must be load-bearing: after each task, revert the production change and confirm the new test fails.
- Run `make test` before every commit. Run `gofmt -l .` and expect empty output.
- Follow the repo's `/precommit-review` rule before any `git push` (see `CLAUDE.md`).

## Naming, verbatim

These identifiers are used across tasks. Use them exactly.

| Symbol | Where |
|---|---|
| `sshfwd.Remote` | `internal/sshfwd/config.go` |
| `sshfwd.File` | `internal/sshfwd/config.go` |
| `sshfwd.Load`, `sshfwd.Save` | `internal/sshfwd/config.go` |
| `sshfwd.Registry` | `internal/sshfwd/registry.go` |
| `sshfwd.Manager` | `internal/sshfwd/manager.go` |
| `sshfwd.State` (string enum) | `internal/sshfwd/state.go` |
| `sshfwd.RemoteStatus` | `internal/sshfwd/state.go` |
| `sshfwd.ErrHostKeyUnknown` | `internal/sshfwd/hostkey.go` |
| `config.SSHConfig` | `internal/config/config.go` |
| `paths.UserConfigDir`, `paths.SSHConfigPath` | `internal/paths/paths.go` |

## File Structure

**Create:**

| File | Responsibility |
|---|---|
| `internal/paths/paths.go` (modify) | `UserConfigDir()`, `SSHConfigPath()` |
| `internal/sshfwd/config.go` | `Remote`, `File`, `Load`, `Save`, validation, `~` rules |
| `internal/sshfwd/registry.go` | `Registry` — the single mutation service layer |
| `internal/sshfwd/manager.go` | `Manager.Reconcile`, desired-vs-actual diff |
| `internal/sshfwd/remote.go` | `ManagedRemote` state machine, `WaitForClient` |
| `internal/sshfwd/backoff.go` | Jittered exponential backoff |
| `internal/sshfwd/identity.go` | `agent.Backend` → `[]ssh.Signer` adapter |
| `internal/sshfwd/hostkey.go` | CA list + pinned key verifier |
| `internal/sshfwd/dial.go` | `ssh.ClientConfig` assembly, dial, keepalive |
| `internal/sshfwd/home.go` | Remote `$HOME` probe, `~` expansion |
| `internal/sshfwd/forward.go` | `ListenUnix` accept loop, bidirectional pump |
| `internal/sshfwd/state.go` | `State`, `RemoteStatus`, snapshot |
| `internal/web/ssh.go` | CRUD handlers over `Registry` |
| `cmd/dotvault/ssh.go` | `dotvault ssh` parent + API client transport |
| `cmd/dotvault/ssh_add.go` | `ssh add` |
| `cmd/dotvault/ssh_list.go` | `ssh list` |
| `cmd/dotvault/ssh_remove.go` | `ssh remove` |

**Modify:** `internal/config/config.go`, `internal/config/registry_windows.go`, `internal/regfile/regfile.go`, `internal/regfile/parse.go`, `internal/web/server.go`, `cmd/dotvault/main.go`, `cmd/dotvault/root.go`, `docker-compose.yml`, `CLAUDE.md`, `docs/`.

---

### Task 1: User config paths

**Files:**
- Modify: `internal/paths/paths.go`
- Test: `internal/paths/paths_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `func UserConfigDir() (string, error)`, `func SSHConfigPath() (string, error)`

- [ ] **Step 1: Write the failing test**

Append to `internal/paths/paths_test.go`:

```go
func TestSSHConfigPathIsUnderUserConfigDir(t *testing.T) {
	dir, err := UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir() error = %v", err)
	}
	if dir == "" {
		t.Fatal("UserConfigDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("UserConfigDir() = %q, want absolute path", dir)
	}

	p, err := SSHConfigPath()
	if err != nil {
		t.Fatalf("SSHConfigPath() error = %v", err)
	}
	if got, want := filepath.Base(p), "ssh.yaml"; got != want {
		t.Errorf("SSHConfigPath() basename = %q, want %q", got, want)
	}
	if filepath.Dir(p) != dir {
		t.Errorf("SSHConfigPath() dir = %q, want %q", filepath.Dir(p), dir)
	}
}

func TestUserConfigDirHonoursXDGOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_CONFIG_HOME is only consulted on linux")
	}
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-test")
	dir, err := UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir() error = %v", err)
	}
	if want := "/tmp/xdg-test/dotvault"; dir != want {
		t.Errorf("UserConfigDir() = %q, want %q", dir, want)
	}
}

func TestUserConfigDirIsNotSystemConfigDir(t *testing.T) {
	// The user file must never resolve to the admin-owned system location.
	// A regression here would let an unprivileged write land where policy
	// lives (or, worse, silently fail and read the admin's file).
	dir, err := UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir() error = %v", err)
	}
	if sys := filepath.Dir(SystemConfigPath()); dir == sys {
		t.Errorf("UserConfigDir() = %q, must differ from system config dir", dir)
	}
}
```

Ensure `runtime` and `filepath` are imported in the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/paths/ -run 'TestSSHConfigPath|TestUserConfigDir' -v`
Expected: FAIL — `undefined: UserConfigDir`

- [ ] **Step 3: Write minimal implementation**

Add to `internal/paths/paths.go`:

```go
// UserConfigDir returns the per-user configuration directory for dotvault.
//
// This is deliberately distinct from SystemConfigPath's directory. The system
// config is admin-owned (root on Linux, %ProgramData% on Windows, and on a GPO
// machine superseded entirely by HKLM policy), and dotvault deliberately does
// not read user-writable policy. Files here are the opposite: owned by the
// user, never consulted for policy, and never resolved from a system location.
//
// On Linux this is the same directory the packaged systemd unit already uses
// for its per-user EnvironmentFile (~/.config/dotvault/env).
func UserConfigDir() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "dotvault"), nil
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "dotvault"), nil
		}
		return "", fmt.Errorf("APPDATA is not set")
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "dotvault"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, ".config", "dotvault"), nil
	}
}

// SSHConfigPath returns the path to the user-level managed-SSH-forward
// configuration (ssh.yaml). It is a sibling of the per-user env file and is
// never resolved from a system location — see UserConfigDir.
func SSHConfigPath() (string, error) {
	dir, err := UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ssh.yaml"), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/paths/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/paths/paths.go internal/paths/paths_test.go
git commit -m "feat(paths): add per-user config dir and ssh.yaml path"
```

---

### Task 2: `ssh.yaml` schema, load, save, validate

**Files:**
- Create: `internal/sshfwd/config.go`
- Test: `internal/sshfwd/config_test.go`

**Interfaces:**
- Consumes: `paths.SSHConfigPath` (Task 1)
- Produces:
  - `type Remote struct { Host string; Port int; RemoteSocket string; HostKey string; Enabled *bool }`
  - `func (r Remote) EnabledOrDefault() bool`
  - `func (r Remote) PortOrDefault() int`
  - `type File struct { Remotes []Remote; unknown map[string]yaml.Node }`
  - `func (f *File) Find(host string) (int, bool)`
  - `func (f *File) Upsert(r Remote)`
  - `func (f *File) Remove(host string) bool`
  - `func Load(path string) (*File, error)`
  - `func Save(path string, f *File) error`
  - `func ValidateRemote(r Remote) error`
  - `func ValidateRemoteSocket(p string) error`

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/config_test.go`:

```go
package sshfwd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRemoteSocket(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{"tilde home", "~/.ssh/dotvault.sock", ""},
		{"absolute", "/run/user/1000/dotvault.sock", ""},
		{"empty", "", "must not be empty"},
		{"tilde user", "~other/.ssh/dotvault.sock", "~user/ is not supported"},
		{"bare tilde", "~", "~user/ is not supported"},
		{"relative", ".ssh/dotvault.sock", "must be absolute or start with ~/"},
		{"nul byte", "/tmp/a\x00b", "must not contain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRemoteSocket(tt.path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRemoteSocket(%q) = %v, want nil", tt.path, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateRemoteSocket(%q) = %v, want error containing %q", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRemote(t *testing.T) {
	tests := []struct {
		name    string
		remote  Remote
		wantErr string
	}{
		{"minimal", Remote{Host: "foo.example.com", RemoteSocket: "~/.ssh/dotvault.sock"}, ""},
		{"no host", Remote{RemoteSocket: "~/.ssh/dotvault.sock"}, "host is required"},
		{"host with space", Remote{Host: "foo bar", RemoteSocket: "~/x.sock"}, "invalid host"},
		{"port low", Remote{Host: "a.example.com", Port: -1, RemoteSocket: "~/x.sock"}, "port"},
		{"port high", Remote{Host: "a.example.com", Port: 70000, RemoteSocket: "~/x.sock"}, "port"},
		{"bad socket", Remote{Host: "a.example.com", RemoteSocket: "rel/x.sock"}, "must be absolute"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRemote(tt.remote)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRemote() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateRemote() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "ssh.yaml"))
	if err != nil {
		t.Fatalf("Load() on missing file = %v, want nil", err)
	}
	if len(f.Remotes) != 0 {
		t.Fatalf("Load() on missing file returned %d remotes, want 0", len(f.Remotes))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	enabled := false
	in := &File{Remotes: []Remote{
		{Host: "foo.example.com", Port: 2222, RemoteSocket: "~/.ssh/dotvault.sock", HostKey: "ssh-ed25519 AAAAC3Nz", Enabled: &enabled},
		{Host: "bar.example.com", RemoteSocket: "/run/dotvault.sock"},
	}}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(out.Remotes) != 2 {
		t.Fatalf("Load() returned %d remotes, want 2", len(out.Remotes))
	}
	if out.Remotes[0].Port != 2222 || out.Remotes[0].HostKey != "ssh-ed25519 AAAAC3Nz" {
		t.Errorf("remote[0] = %+v, lost fields on round trip", out.Remotes[0])
	}
	if out.Remotes[0].EnabledOrDefault() {
		t.Error("remote[0].EnabledOrDefault() = true, want false (explicit enabled: false must survive)")
	}
	if !out.Remotes[1].EnabledOrDefault() {
		t.Error("remote[1].EnabledOrDefault() = false, want true (unset defaults to enabled)")
	}
	if got := out.Remotes[1].PortOrDefault(); got != 22 {
		t.Errorf("remote[1].PortOrDefault() = %d, want 22", got)
	}
}

func TestSavePreservesUnknownKeys(t *testing.T) {
	// An older build must not silently drop a section a newer build wrote.
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	raw := "remotes:\n  - host: foo.example.com\n    remote_socket: ~/.ssh/dotvault.sock\nfuture_section:\n  keep: me\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	f.Upsert(Remote{Host: "bar.example.com", RemoteSocket: "~/.ssh/dotvault.sock"})
	if err := Save(path, f); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "future_section") || !strings.Contains(string(data), "keep: me") {
		t.Errorf("Save() dropped unknown keys:\n%s", data)
	}
}

func TestSaveIsAtomicAnd0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.yaml")
	if err := Save(path, &File{Remotes: []Remote{{Host: "a.example.com", RemoteSocket: "~/x.sock"}}}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeIsUnix() && fi.Mode().Perm() != 0600 {
		t.Errorf("Save() mode = %o, want 0600", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("Save() left %d entries, want 1 (no temp file)", len(entries))
	}
}

func TestUpsertIsIdempotentOnHost(t *testing.T) {
	f := &File{}
	f.Upsert(Remote{Host: "foo.example.com", RemoteSocket: "~/a.sock"})
	f.Upsert(Remote{Host: "foo.example.com", RemoteSocket: "~/b.sock"})
	if len(f.Remotes) != 1 {
		t.Fatalf("Upsert() twice produced %d remotes, want 1", len(f.Remotes))
	}
	if f.Remotes[0].RemoteSocket != "~/b.sock" {
		t.Errorf("Upsert() did not replace: %+v", f.Remotes[0])
	}
}

func TestRemove(t *testing.T) {
	f := &File{Remotes: []Remote{{Host: "a.example.com"}, {Host: "b.example.com"}}}
	if !f.Remove("a.example.com") {
		t.Error("Remove() = false, want true")
	}
	if f.Remove("missing.example.com") {
		t.Error("Remove() on absent host = true, want false")
	}
	if len(f.Remotes) != 1 || f.Remotes[0].Host != "b.example.com" {
		t.Errorf("Remove() left %+v", f.Remotes)
	}
}
```

Add a tiny helper in the same file:

```go
func runtimeIsUnix() bool { return os.PathSeparator == '/' }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -v`
Expected: FAIL — package does not exist / `undefined: Remote`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/config.go`:

```go
// Package sshfwd implements dotvault's daemon-managed SSH remote forwards: a
// declarative reconciler that keeps an SSH connection to each configured host
// and exposes dotvault's own web API there as a Unix socket, replacing the
// external `ssh -R` that vault.token_socket has depended on.
package sshfwd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultRemoteSocket is the socket path used when a remote does not name one.
// The leading ~ is expanded against the *remote* account's home at connect
// time, not here — see home.go.
const DefaultRemoteSocket = "~/.ssh/dotvault.sock"

// DefaultPort is the SSH port used when a remote does not name one.
const DefaultPort = 22

// Remote is one configured SSH host whose forward the daemon maintains.
//
// Host is the entry's identity: `ssh add` is idempotent on it and `ssh remove`
// keys on it.
type Remote struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port,omitempty"`

	// RemoteSocket is the Unix socket path bound on the remote. Absolute, or
	// prefixed "~/" for the remote account's home. Storing ~ rather than a
	// resolved path keeps the entry portable if the remote home moves.
	RemoteSocket string `yaml:"remote_socket"`

	// HostKey pins the remote's host key in authorized_keys form. Empty when a
	// configured certificate authority covers the host instead.
	HostKey string `yaml:"host_key,omitempty"`

	// Enabled is a pointer so an explicit `enabled: false` is distinguishable
	// from an unset field (which defaults to true) and survives a round trip.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// EnabledOrDefault reports whether the daemon should manage this remote. An
// unset value defaults to true.
func (r Remote) EnabledOrDefault() bool { return r.Enabled == nil || *r.Enabled }

// PortOrDefault returns the SSH port, defaulting to 22.
func (r Remote) PortOrDefault() int {
	if r.Port == 0 {
		return DefaultPort
	}
	return r.Port
}

// File is the parsed ssh.yaml document.
//
// unknown retains any top-level key this build does not recognise so a rewrite
// by an older binary cannot silently drop a section a newer one wrote.
type File struct {
	Remotes []Remote `yaml:"remotes"`

	unknown map[string]yaml.Node
}

// Find returns the index of the remote with the given host.
func (f *File) Find(host string) (int, bool) {
	for i, r := range f.Remotes {
		if strings.EqualFold(r.Host, host) {
			return i, true
		}
	}
	return -1, false
}

// Upsert replaces the entry for r.Host, or appends it when absent.
func (f *File) Upsert(r Remote) {
	if i, ok := f.Find(r.Host); ok {
		f.Remotes[i] = r
		return
	}
	f.Remotes = append(f.Remotes, r)
}

// Remove deletes the entry for host, reporting whether one was present.
func (f *File) Remove(host string) bool {
	i, ok := f.Find(host)
	if !ok {
		return false
	}
	f.Remotes = append(f.Remotes[:i], f.Remotes[i+1:]...)
	return true
}

// Load reads ssh.yaml. A missing file is an empty document, not an error: a
// user who has never run `dotvault ssh add` has no file and no remotes, which
// is a valid state rather than a misconfiguration.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	f := &File{unknown: map[string]yaml.Node{}}
	for k, v := range raw {
		if k == "remotes" {
			if err := v.Decode(&f.Remotes); err != nil {
				return nil, fmt.Errorf("parse %s: remotes: %w", path, err)
			}
			continue
		}
		f.unknown[k] = v
	}
	return f, nil
}

// Save writes ssh.yaml atomically at 0600 inside a 0700 directory. The file
// records which hosts this user connects to and pins their keys.
func Save(path string, f *File) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	out := map[string]any{"remotes": f.Remotes}
	for k, v := range f.unknown {
		out[k] = v
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal ssh config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".ssh.yaml.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// ValidateRemoteSocket enforces the socket-path rules. Only an absolute path
// or a "~/"-prefixed one is accepted: "~user/" would require resolving another
// account's home on the remote, which dotvault cannot do, and silently
// mishandling it would bind somewhere the user did not intend.
func ValidateRemoteSocket(p string) error {
	switch {
	case p == "":
		return errors.New("remote_socket must not be empty")
	case strings.ContainsRune(p, 0):
		return errors.New("remote_socket must not contain a NUL byte")
	case strings.HasPrefix(p, "~/"):
		return nil
	case strings.HasPrefix(p, "~"):
		return errors.New(`remote_socket "~user/" is not supported; use an absolute path or "~/"`)
	case strings.HasPrefix(p, "/"):
		return nil
	default:
		return errors.New(`remote_socket must be absolute or start with "~/"`)
	}
}

// ValidateRemote checks a single entry.
func ValidateRemote(r Remote) error {
	if r.Host == "" {
		return errors.New("host is required")
	}
	if strings.ContainsAny(r.Host, " \t\r\n/\\") {
		return fmt.Errorf("invalid host %q", r.Host)
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", r.Port)
	}
	return ValidateRemoteSocket(r.RemoteSocket)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -v`
Expected: PASS

- [ ] **Step 5: Verify the assertions are load-bearing**

Temporarily change `EnabledOrDefault` to `return true` and re-run: `TestSaveLoadRoundTrip` must fail. Temporarily drop the `f.unknown` merge in `Save` and re-run: `TestSavePreservesUnknownKeys` must fail. Revert both.

- [ ] **Step 6: Commit**

```bash
git add internal/sshfwd/config.go internal/sshfwd/config_test.go
git commit -m "feat(sshfwd): ssh.yaml schema with atomic save and unknown-key preservation"
```

---

### Task 3: System `ssh:` config section across all four surfaces

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/registry_windows.go`
- Modify: `internal/regfile/regfile.go`
- Modify: `internal/regfile/parse.go`
- Test: `internal/config/config_test.go`, `internal/regfile/regfile_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `config.SSHConfig{ CertificateAuthorities []string; InsecureIgnoreHostKey bool }`, reachable as `cfg.SSH`

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
func TestSSHSectionParsesFromYAML(t *testing.T) {
	yamlData := `
vault:
  address: https://vault.example.com
ssh:
  certificate_authorities:
    - "@cert-authority *.example.com ssh-ed25519 AAAAC3Nz"
  insecure_ignore_host_key: true
rules:
  - name: test
    vault_key: t
    target:
      path: /tmp/t
      format: json
`
	cfg, err := loadFromBytes(t, []byte(yamlData))
	if err != nil {
		t.Fatalf("load = %v", err)
	}
	if len(cfg.SSH.CertificateAuthorities) != 1 {
		t.Fatalf("CertificateAuthorities = %v, want 1 entry", cfg.SSH.CertificateAuthorities)
	}
	if !cfg.SSH.InsecureIgnoreHostKey {
		t.Error("InsecureIgnoreHostKey = false, want true")
	}
}

func TestSSHSectionDefaultsSecure(t *testing.T) {
	yamlData := `
vault:
  address: https://vault.example.com
rules:
  - name: test
    vault_key: t
    target:
      path: /tmp/t
      format: json
`
	cfg, err := loadFromBytes(t, []byte(yamlData))
	if err != nil {
		t.Fatalf("load = %v", err)
	}
	if cfg.SSH.InsecureIgnoreHostKey {
		t.Error("InsecureIgnoreHostKey defaulted to true; host-key checking must be on by default")
	}
}
```

`loadFromBytes` is a helper: write the bytes to a temp file and call `config.Load`. If an equivalent helper already exists in `config_test.go`, use that one instead and delete this note.

Append to `internal/regfile/regfile_test.go` a round-trip case mirroring the existing observability/agent round-trip tests:

```go
func TestSSHSectionRegfileRoundTrip(t *testing.T) {
	in := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com"},
		SSH: config.SSHConfig{
			CertificateAuthorities: []string{
				"@cert-authority *.example.com ssh-ed25519 AAAAC3Nz",
				"@cert-authority *.corp ssh-rsa AAAAB3Nz",
			},
			InsecureIgnoreHostKey: true,
		},
		Rules: []config.Rule{{
			Name:     "t",
			VaultKey: "t",
			Target:   config.Target{Path: "/tmp/t", Format: "json"},
		}},
	}
	rendered, err := Render(in)
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	out, err := Parse(rendered)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if !reflect.DeepEqual(out.SSH, in.SSH) {
		t.Errorf("SSH round trip:\n got %+v\nwant %+v", out.SSH, in.SSH)
	}
}
```

Match `Render`/`Parse`'s real signatures in that file; adjust the call shape if they differ.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ ./internal/regfile/ -run SSH -v`
Expected: FAIL — `cfg.SSH undefined`

- [ ] **Step 3: Write minimal implementation**

In `internal/config/config.go`, add the field to `Config` after `Agent`:

```go
	SSH           SSHConfig            `yaml:"ssh,omitempty"`
```

and the type:

```go
// SSHConfig holds the admin-owned trust material for daemon-managed SSH
// forwards. The remotes themselves are deliberately *not* here: they live in
// the user-level ssh.yaml (see paths.SSHConfigPath), which has no registry
// surface because it is user-writable and must never act as policy.
//
// The inner fields omit `omitempty` for the same round-trip reason as
// AgentConfig: an exported config must re-emit cleared optional values so a
// re-import can blank a previously-set list. The top-level SSH field keeps
// `omitempty` so operators who do not use managed forwards see no empty block.
type SSHConfig struct {
	// CertificateAuthorities lists trusted SSH host CAs in known_hosts
	// @cert-authority form. A host whose certificate one of these signed
	// needs no per-host pin in ssh.yaml.
	CertificateAuthorities []string `yaml:"certificate_authorities"`

	// InsecureIgnoreHostKey disables host-key verification entirely.
	//
	// It lives in the system config rather than the user's ssh.yaml because
	// it is a security downgrade; on a personal machine the user is the admin
	// anyway. Every connection attempt made under it logs a WARN naming the
	// host, so it cannot be set once and forgotten silently.
	InsecureIgnoreHostKey bool `yaml:"insecure_ignore_host_key"`
}
```

In `internal/config/registry_windows.go`, extend `registryLayer` to read an `SSH` subkey: `InsecureIgnoreHostKey` as a REG_DWORD, `CertificateAuthorities` as a REG_MULTI_SZ (follow the exact pattern the existing `Vault\Policies` REG_MULTI_SZ read uses).

In `internal/regfile/regfile.go`, render an `SSH` subkey with `"InsecureIgnoreHostKey"=dword:…` and `"CertificateAuthorities"=hex(7):…`, deleting the subtree before re-creation exactly as the Rules/Enrolments/Agent sections do.

In `internal/regfile/parse.go`, parse both values back.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ ./internal/regfile/ -v`
Expected: PASS

- [ ] **Step 5: Verify parity is real**

Run: `go build ./... && GOOS=windows go build ./...`
Expected: both succeed (the registry loader is `//go:build windows`).

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go internal/config/registry_windows.go internal/regfile/regfile.go internal/regfile/parse.go internal/regfile/regfile_test.go
git commit -m "feat(config): add system ssh section for host-CA trust material"
```

---

### Task 4: Host-key verifier

**Files:**
- Create: `internal/sshfwd/hostkey.go`
- Test: `internal/sshfwd/hostkey_test.go`

**Interfaces:**
- Consumes: `config.SSHConfig` (Task 3)
- Produces:
  - `var ErrHostKeyUnknown = errors.New(...)`
  - `type HostKeyPolicy struct { CAs []string; Pinned string; Insecure bool }`
  - `func (p HostKeyPolicy) Callback(observed *ssh.PublicKey) ssh.HostKeyCallback`

`observed` is an out-parameter: the callback stores whatever key it saw so `add` can report a fingerprint even when it rejects. Pass `nil` when the caller does not need it.

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/hostkey_test.go`:

```go
package sshfwd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func addr(t *testing.T) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", "192.0.2.1:22")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestHostKeyPolicyAcceptsPinnedKey(t *testing.T) {
	_, pub := testKey(t)
	p := HostKeyPolicy{Pinned: string(ssh.MarshalAuthorizedKey(pub))}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsChangedKey(t *testing.T) {
	_, pinned := testKey(t)
	_, other := testKey(t)
	p := HostKeyPolicy{Pinned: string(ssh.MarshalAuthorizedKey(pinned))}
	err := p.Callback(nil)("foo.example.com:22", addr(t), other)
	if err == nil {
		t.Fatal("changed host key accepted; must be rejected")
	}
}

func TestHostKeyPolicyRejectsUnknownAndReportsIt(t *testing.T) {
	_, pub := testKey(t)
	var seen ssh.PublicKey
	p := HostKeyPolicy{}
	err := p.Callback(&seen)("foo.example.com:22", addr(t), pub)
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("err = %v, want ErrHostKeyUnknown", err)
	}
	if seen == nil {
		t.Fatal("observed key not captured; `ssh add` cannot report a fingerprint")
	}
	if string(seen.Marshal()) != string(pub.Marshal()) {
		t.Error("observed key does not match the presented key")
	}
}

func TestHostKeyPolicyAcceptsCASignedCert(t *testing.T) {
	caSigner, caPub := testKey(t)
	hostSigner, hostPub := testKey(t)

	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "foo.example.com",
		ValidPrincipals: []string{"foo.example.com"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	_ = hostSigner

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), cert); err != nil {
		t.Fatalf("CA-signed host cert rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsCertFromUnknownCA(t *testing.T) {
	otherCA, _ := testKey(t)
	_, knownCAPub := testKey(t)
	_, hostPub := testKey(t)

	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "foo.example.com",
		ValidPrincipals: []string{"foo.example.com"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, otherCA); err != nil {
		t.Fatal(err)
	}

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(knownCAPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), cert); err == nil {
		t.Fatal("cert from an unconfigured CA accepted; must be rejected")
	}
}

func TestHostKeyPolicyInsecureAcceptsAnything(t *testing.T) {
	_, pub := testKey(t)
	p := HostKeyPolicy{Insecure: true}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("insecure policy rejected key: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run HostKey -v`
Expected: FAIL — `undefined: HostKeyPolicy`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/hostkey.go`:

```go
package sshfwd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrHostKeyUnknown reports a host whose key is neither pinned in ssh.yaml nor
// signed by a configured certificate authority. It is distinct from a
// *mismatch*: unknown is the normal state before `dotvault ssh add` pins a
// key, and the CLI turns it into a fingerprint prompt rather than an error.
var ErrHostKeyUnknown = errors.New("host key is not pinned and no configured CA signed it")

// HostKeyPolicy decides whether to trust a remote's host key.
//
// There is deliberately no runtime trust-on-first-use. Pinning happens exactly
// once, during `dotvault ssh add`, which is an explicit human gesture; the
// daemon reconnecting in the background must never make that decision on the
// user's behalf.
type HostKeyPolicy struct {
	// CAs are known_hosts @cert-authority lines from the system config.
	CAs []string

	// Pinned is this host's key in authorized_keys form, empty when unpinned.
	Pinned string

	// Insecure disables verification entirely (system config opt-in).
	Insecure bool
}

// Callback returns the ssh.HostKeyCallback implementing the policy. When
// observed is non-nil the presented key is stored there before any accept or
// reject decision, so a caller that rejects can still report the fingerprint it
// saw — which is exactly what `ssh add` needs to prompt.
func (p HostKeyPolicy) Callback(observed *ssh.PublicKey) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if observed != nil {
			*observed = key
		}

		if p.Insecure {
			// Logged on every attempt, naming the host: a security downgrade
			// must not be settable once and then invisible.
			slog.Warn("ssh host key verification disabled by insecure_ignore_host_key",
				"host", hostname)
			return nil
		}

		if cert, ok := key.(*ssh.Certificate); ok {
			return p.checkCert(hostname, remote, cert)
		}

		if p.Pinned != "" {
			pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.Pinned))
			if err != nil {
				return fmt.Errorf("parse pinned host key for %s: %w", hostname, err)
			}
			if string(pinned.Marshal()) == string(key.Marshal()) {
				return nil
			}
			return fmt.Errorf("host key for %s changed: pinned %s, offered %s",
				hostname, ssh.FingerprintSHA256(pinned), ssh.FingerprintSHA256(key))
		}

		return fmt.Errorf("%s: %w (offered %s)", hostname, ErrHostKeyUnknown, ssh.FingerprintSHA256(key))
	}
}

// checkCert validates a host certificate against the configured CAs. Each CA
// line is parsed with the knownhosts @cert-authority grammar so the host
// pattern is honoured, rather than trusting every CA for every host.
func (p HostKeyPolicy) checkCert(hostname string, remote net.Addr, cert *ssh.Certificate) error {
	if len(p.CAs) == 0 {
		return fmt.Errorf("%s: %w (offered host certificate, no certificate_authorities configured)",
			hostname, ErrHostKeyUnknown)
	}

	var errs []error
	for _, line := range p.CAs {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cb, err := knownhosts.NewFromReader(strings.NewReader(line + "\n"))
		if err != nil {
			errs = append(errs, fmt.Errorf("parse certificate_authorities entry: %w", err))
			continue
		}
		if err := cb(hostname, remote, cert); err == nil {
			return nil
		} else {
			errs = append(errs, err)
		}
	}
	return fmt.Errorf("%s: host certificate not signed by any configured CA: %w",
		hostname, errors.Join(errs...))
}
```

> **Note for the implementer:** `knownhosts.NewFromReader` may not exist in the pinned `x/crypto` version. Check with `go doc golang.org/x/crypto/ssh/knownhosts`. If only `knownhosts.New(files ...string)` exists, write each CA line to a temp file once at policy-construction time and hold the resulting callback, or parse the line yourself with `ssh.ParseKnownHosts` and match the host pattern with `knownhosts.Normalize`. Do not skip the host-pattern check — trusting every CA for every host is a real downgrade.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -run HostKey -v`
Expected: PASS

- [ ] **Step 5: Verify the assertions are load-bearing**

Temporarily make `Callback` return `nil` unconditionally. `TestHostKeyPolicyRejectsChangedKey`, `TestHostKeyPolicyRejectsUnknownAndReportsIt`, and `TestHostKeyPolicyRejectsCertFromUnknownCA` must all fail. Revert.

- [ ] **Step 6: Commit**

```bash
git add internal/sshfwd/hostkey.go internal/sshfwd/hostkey_test.go
git commit -m "feat(sshfwd): host-key policy with CA and pinned-key paths, no runtime TOFU"
```

---

### Task 5: Identity adapter over `agent.Backend`

**Files:**
- Create: `internal/sshfwd/identity.go`
- Test: `internal/sshfwd/identity_test.go`

**Interfaces:**
- Consumes: `agent.Backend` (existing, `internal/agent/backend.go`)
- Produces:
  - `type SignerSource interface { List() ([]*agent.Key, error); SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) }`
  - `func Signers(src SignerSource) ([]ssh.Signer, error)`

`*agent.Backend` satisfies `SignerSource` structurally. The interface exists so tests need no Vault.

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/identity_test.go`:

```go
package sshfwd

import (
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type fakeBackend struct {
	keys     []*sshagent.Key
	signer   ssh.Signer
	signErr  error
	signCall int
}

func (f *fakeBackend) List() ([]*sshagent.Key, error) { return f.keys, nil }

func (f *fakeBackend) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	f.signCall++
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signer.Sign(rand.Reader, data)
}

func TestSignersWrapsEachBackendIdentity(t *testing.T) {
	s, pub := testKey(t)
	fb := &fakeBackend{
		keys:   []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "dotvault"}},
		signer: s,
	}

	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("Signers() returned %d, want 1", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Error("wrapped signer advertises the wrong public key")
	}

	sig, err := signers[0].Sign(rand.Reader, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	if fb.signCall != 1 {
		t.Errorf("backend SignWithFlags called %d times, want 1 — signing must delegate, not use a local key", fb.signCall)
	}
	if err := pub.Verify([]byte("payload"), sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestSignersPropagatesSignError(t *testing.T) {
	s, pub := testKey(t)
	want := errors.New("vault unavailable")
	fb := &fakeBackend{
		keys:    []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal()}},
		signer:  s,
		signErr: want,
	}
	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("x")); !errors.Is(err, want) {
		t.Fatalf("Sign() err = %v, want %v", err, want)
	}
}

func TestSignersOnEmptyBackend(t *testing.T) {
	signers, err := Signers(&fakeBackend{})
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 0 {
		t.Fatalf("Signers() returned %d, want 0", len(signers))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run Signers -v`
Expected: FAIL — `undefined: Signers`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/identity.go`:

```go
package sshfwd

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// SignerSource is the slice of agent.ExtendedAgent the forwarder needs.
// *agent.Backend satisfies it structurally; the narrowed interface keeps this
// package's tests free of Vault and keeps the dependency one-directional.
type SignerSource interface {
	List() ([]*sshagent.Key, error)
	SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error)
}

// Signers adapts a SignerSource into ssh.Signers usable by
// ssh.PublicKeysCallback.
//
// The agent Backend cannot be used directly: its Signers() returns ErrReadOnly
// by design, because dotvault syncs one way and the agent never hands out key
// material. This wraps each advertised identity in a signer that delegates
// back to the backend, so the private key stays wherever the source keeps it
// (Vault, or an in-memory ephemeral key behind a Vault-CA certificate).
//
// Callers should invoke this per dial rather than caching the result: a
// Vault-CA certificate rotated since the last connection is picked up on the
// next reconnect with no cache of its own.
func Signers(src SignerSource) ([]ssh.Signer, error) {
	keys, err := src.List()
	if err != nil {
		return nil, fmt.Errorf("list agent identities: %w", err)
	}
	signers := make([]ssh.Signer, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			return nil, fmt.Errorf("parse agent identity %q: %w", k.Comment, err)
		}
		signers = append(signers, &backendSigner{src: src, pub: pub})
	}
	return signers, nil
}

// backendSigner is one advertised identity, signing via the backend.
type backendSigner struct {
	src SignerSource
	pub ssh.PublicKey
}

func (s *backendSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *backendSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.src.SignWithFlags(s.pub, data, 0)
}

// SignWithAlgorithm satisfies ssh.AlgorithmSigner so an RSA identity can be
// used with rsa-sha2-256/512 rather than the deprecated ssh-rsa. The backend
// already honours these flags.
func (s *backendSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var flags sshagent.SignatureFlags
	switch algorithm {
	case ssh.KeyAlgoRSASHA256:
		flags = sshagent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		flags = sshagent.SignatureFlagRsaSha512
	case "":
		// Caller has no preference.
	default:
		if algorithm != s.pub.Type() {
			return nil, fmt.Errorf("unsupported signature algorithm %q for key type %q", algorithm, s.pub.Type())
		}
	}
	return s.src.SignWithFlags(s.pub, data, flags)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -run Signers -v`
Expected: PASS

- [ ] **Step 5: Verify `*agent.Backend` really satisfies the interface**

Add to `internal/sshfwd/identity.go`:

```go
// Compile-time proof the daemon's real backend satisfies SignerSource, so a
// change to either side breaks the build rather than the daemon at runtime.
var _ SignerSource = (*agent.Backend)(nil)
```

with `"github.com/goodtune/dotvault/internal/agent"` imported. Run `go build ./...` and expect success.

- [ ] **Step 6: Commit**

```bash
git add internal/sshfwd/identity.go internal/sshfwd/identity_test.go
git commit -m "feat(sshfwd): adapt agent backend into ssh.Signers without breaking read-only contract"
```

---

### Task 6: Backoff

**Files:**
- Create: `internal/sshfwd/backoff.go`
- Test: `internal/sshfwd/backoff_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `type Backoff struct { Base, Max time.Duration; Jitter float64; rnd func() float64; n int }`
  - `func NewBackoff() *Backoff`
  - `func (b *Backoff) Next() time.Duration`
  - `func (b *Backoff) Reset()`
  - `const AuthFailureFloor = 5 * time.Minute`

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/backoff_test.go`:

```go
package sshfwd

import (
	"testing"
	"time"
)

func TestBackoffSequenceWithoutJitter(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 0.5 } // midpoint => no adjustment

	want := []time.Duration{
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}
	for i, w := range want {
		if got := b.Next(); got != w {
			t.Errorf("Next() #%d = %v, want %v", i, got, w)
		}
	}
}

func TestBackoffJitterStaysWithinTwentyPercent(t *testing.T) {
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 1} {
		b := NewBackoff()
		b.rnd = func() float64 { return r }
		got := b.Next()
		lo := time.Duration(float64(500*time.Millisecond) * 0.8)
		hi := time.Duration(float64(500*time.Millisecond) * 1.2)
		if got < lo || got > hi {
			t.Errorf("rnd=%v: Next() = %v, want within [%v, %v]", r, got, lo, hi)
		}
	}
}

func TestBackoffResetReturnsToBase(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 0.5 }
	for i := 0; i < 5; i++ {
		b.Next()
	}
	b.Reset()
	if got := b.Next(); got != 500*time.Millisecond {
		t.Errorf("after Reset(), Next() = %v, want 500ms", got)
	}
}

func TestBackoffNeverExceedsMax(t *testing.T) {
	b := NewBackoff()
	b.rnd = func() float64 { return 1 } // maximum positive jitter
	for i := 0; i < 50; i++ {
		if got := b.Next(); got > time.Duration(float64(b.Max)*1.2) {
			t.Fatalf("Next() #%d = %v, exceeds Max+jitter", i, got)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run Backoff -v`
Expected: FAIL — `undefined: NewBackoff`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/backoff.go`:

```go
package sshfwd

import (
	"math/rand/v2"
	"time"
)

// StableConnectionThreshold is how long a connection must stay up before its
// backoff resets. Without it a host that accepts a connection and drops it
// immediately would reconnect at the base delay forever.
const StableConnectionThreshold = 60 * time.Second

// AuthFailureFloor is the minimum delay after an authentication or host-key
// failure. Those conditions are cleared by a human (re-pinning a key) or by
// Vault (reissuing a certificate), never by retrying quickly — so retrying at
// the base delay would be pure noise against a wedged remote. They still
// retry, because both genuinely do self-heal.
const AuthFailureFloor = 5 * time.Minute

// Backoff produces the jittered exponential reconnect delay.
type Backoff struct {
	Base   time.Duration
	Max    time.Duration
	Jitter float64

	// rnd returns a value in [0,1). Injected so tests are deterministic.
	rnd func() float64

	n int
}

// NewBackoff returns the reconnect schedule: 500ms doubling to a 30s ceiling,
// each delay jittered by ±20% so a fleet of daemons that lost a shared network
// does not reconnect in lockstep.
func NewBackoff() *Backoff {
	return &Backoff{
		Base:   500 * time.Millisecond,
		Max:    30 * time.Second,
		Jitter: 0.2,
		rnd:    rand.Float64,
	}
}

// Next returns the next delay and advances the schedule.
func (b *Backoff) Next() time.Duration {
	d := b.Base
	for i := 0; i < b.n; i++ {
		d *= 2
		if d >= b.Max {
			d = b.Max
			break
		}
	}
	b.n++

	// rnd in [0,1) maps to a multiplier in [1-Jitter, 1+Jitter).
	factor := 1 + b.Jitter*(2*b.rnd()-1)
	return time.Duration(float64(d) * factor)
}

// Reset returns the schedule to its base delay, called once a connection has
// stayed up for StableConnectionThreshold.
func (b *Backoff) Reset() { b.n = 0 }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -run Backoff -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshfwd/backoff.go internal/sshfwd/backoff_test.go
git commit -m "feat(sshfwd): jittered exponential reconnect backoff"
```

---

### Task 7: Remote `$HOME` probe and `~` expansion

**Files:**
- Create: `internal/sshfwd/home.go`
- Test: `internal/sshfwd/home_test.go`

**Interfaces:**
- Consumes: `ValidateRemoteSocket` (Task 2)
- Produces:
  - `type CommandRunner interface { Run(ctx context.Context, cmd string) (string, error) }`
  - `func ExpandRemotePath(ctx context.Context, r CommandRunner, p string) (string, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/home_test.go`:

```go
package sshfwd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	out   string
	err   error
	calls int
}

func (f *fakeRunner) Run(ctx context.Context, cmd string) (string, error) {
	f.calls++
	return f.out, f.err
}

func TestExpandRemotePathAbsoluteDoesNotProbe(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	got, err := ExpandRemotePath(context.Background(), r, "/run/user/1000/dotvault.sock")
	if err != nil {
		t.Fatalf("ExpandRemotePath() = %v", err)
	}
	if got != "/run/user/1000/dotvault.sock" {
		t.Errorf("got %q, want the path verbatim", got)
	}
	if r.calls != 0 {
		t.Errorf("probed %d times for an absolute path, want 0", r.calls)
	}
}

func TestExpandRemotePathTilde(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	got, err := ExpandRemotePath(context.Background(), r, "~/.ssh/dotvault.sock")
	if err != nil {
		t.Fatalf("ExpandRemotePath() = %v", err)
	}
	if want := "/home/me/.ssh/dotvault.sock"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpandRemotePathTrimsProbeOutput(t *testing.T) {
	r := &fakeRunner{out: "  /home/me  \r\n"}
	got, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if err != nil {
		t.Fatalf("ExpandRemotePath() = %v", err)
	}
	if want := "/home/me/x.sock"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpandRemotePathRejectsNonAbsoluteHome(t *testing.T) {
	r := &fakeRunner{out: "relative/home\n"}
	if _, err := ExpandRemotePath(context.Background(), r, "~/x.sock"); err == nil {
		t.Fatal("accepted a non-absolute $HOME; must be rejected")
	}
}

func TestExpandRemotePathRejectsEmptyHome(t *testing.T) {
	r := &fakeRunner{out: "\n"}
	if _, err := ExpandRemotePath(context.Background(), r, "~/x.sock"); err == nil {
		t.Fatal("accepted an empty $HOME; must be rejected")
	}
}

func TestExpandRemotePathPropagatesProbeError(t *testing.T) {
	want := errors.New("exec failed")
	r := &fakeRunner{err: want}
	_, err := ExpandRemotePath(context.Background(), r, "~/x.sock")
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestExpandRemotePathRejectsTildeUser(t *testing.T) {
	r := &fakeRunner{out: "/home/me\n"}
	_, err := ExpandRemotePath(context.Background(), r, "~other/x.sock")
	if err == nil || !strings.Contains(err.Error(), "~user/") {
		t.Fatalf("err = %v, want a ~user/ rejection", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run ExpandRemotePath -v`
Expected: FAIL — `undefined: ExpandRemotePath`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/home.go`:

```go
package sshfwd

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// homeProbeCommand reads the remote account's home directory. Deliberately a
// shell echo rather than an SFTP realpath: the forward needs no subsystem, and
// requiring sftp-server would exclude hosts that only allow exec.
const homeProbeCommand = "echo $HOME"

// CommandRunner runs a single command on the remote and returns its stdout.
// Abstracted so expansion is testable without an SSH server.
type CommandRunner interface {
	Run(ctx context.Context, cmd string) (string, error)
}

// ExpandRemotePath resolves a configured remote_socket to an absolute path on
// the remote host.
//
// An absolute path is returned verbatim and never probes — a needless exec
// channel per connection would be both slow and a reason for the connection to
// fail on a host that restricts commands. Only a "~/" prefix triggers the
// probe. "~user/" is rejected rather than guessed: resolving another account's
// home would need NSS access dotvault does not have, and binding the wrong
// path silently is worse than refusing.
func ExpandRemotePath(ctx context.Context, r CommandRunner, p string) (string, error) {
	if err := ValidateRemoteSocket(p); err != nil {
		return "", err
	}
	if !strings.HasPrefix(p, "~/") {
		return p, nil
	}

	out, err := r.Run(ctx, homeProbeCommand)
	if err != nil {
		return "", fmt.Errorf("probe remote home directory: %w", err)
	}
	home := strings.TrimSpace(out)
	if home == "" {
		return "", fmt.Errorf("remote $HOME is empty")
	}
	if !strings.HasPrefix(home, "/") {
		return "", fmt.Errorf("remote $HOME %q is not an absolute path", home)
	}
	return path.Join(home, strings.TrimPrefix(p, "~/")), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -run ExpandRemotePath -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshfwd/home.go internal/sshfwd/home_test.go
git commit -m "feat(sshfwd): expand ~ in remote_socket against the remote home"
```

---

### Task 8: State vocabulary and status snapshot

**Files:**
- Create: `internal/sshfwd/state.go`
- Test: `internal/sshfwd/state_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `type State string` with constants `StateConnecting`, `StateConnected`, `StateReconnecting`, `StateOffline`, `StateAuthError`, `StateHostKeyError`, `StateDisabled`
  - `type ErrorClass string` with constants listed below
  - `type RemoteStatus struct { Host, State, RemoteSocket, Target string; ConnectedSince *time.Time; Reconnects int; ActiveConnections int; LastError string }`
  - `func Classify(err error) ErrorClass`

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/state_test.go`:

```go
package sshfwd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorClass
	}{
		{"nil", nil, ClassNone},
		{"host key unknown", fmt.Errorf("wrap: %w", ErrHostKeyUnknown), ClassHostKey},
		{"dns", &net.DNSError{Err: "no such host", IsNotFound: true}, ClassDNS},
		{"refused", fmt.Errorf("dial tcp: %w", errConnRefusedStub), ClassRefused},
		{"other", errors.New("something else"), ClassOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Errorf("Classify(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestRemoteStatusJSONShape(t *testing.T) {
	s := RemoteStatus{
		Host:         "foo.example.com",
		State:        string(StateConnected),
		RemoteSocket: "/home/me/.ssh/dotvault.sock",
		Target:       "unix:/run/user/1000/dotvault/api.sock",
		Reconnects:   2,
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"host"`, `"state"`, `"remote_socket"`, `"target"`,
		`"reconnects"`, `"active_connections"`, `"last_error"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Errorf("marshalled status missing %s: %s", key, data)
		}
	}
	if strings.Contains(string(data), `"connected_since"`) {
		t.Errorf("connected_since must be omitted when unset: %s", data)
	}
}

func TestStatesAreDistinct(t *testing.T) {
	all := []State{
		StateConnecting, StateConnected, StateReconnecting,
		StateOffline, StateAuthError, StateHostKeyError, StateDisabled,
	}
	seen := map[State]bool{}
	for _, s := range all {
		if s == "" {
			t.Error("empty state constant")
		}
		if seen[s] {
			t.Errorf("duplicate state %q", s)
		}
		seen[s] = true
	}
}
```

Add near the top of the test file:

```go
// errConnRefusedStub stands in for a real ECONNREFUSED without needing a
// closed port; Classify matches on syscall.ECONNREFUSED.
var errConnRefusedStub = syscall.ECONNREFUSED
```

with `"syscall"` imported.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run 'Classify|RemoteStatus|StatesAre' -v`
Expected: FAIL — `undefined: ErrorClass`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/state.go`:

```go
package sshfwd

import (
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// State is a managed remote's externally visible condition.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateOffline      State = "offline"
	StateAuthError    State = "authentication-error"
	StateHostKeyError State = "host-key-error"
	StateDisabled     State = "disabled"
)

// ErrorClass is the internal failure taxonomy. Collapsing everything into
// "offline" would make the common misconfigurations — an unauthorised
// principal, AllowStreamLocalForwarding off — indistinguishable from a flat
// battery, so the class drives both the reported state and the backoff floor.
type ErrorClass string

const (
	ClassNone        ErrorClass = ""
	ClassDNS         ErrorClass = "dns"
	ClassUnreachable ErrorClass = "network-unreachable"
	ClassRefused     ErrorClass = "connection-refused"
	ClassHandshake   ErrorClass = "handshake"
	ClassAuth        ErrorClass = "authentication"
	ClassHostKey     ErrorClass = "host-key"
	ClassBind        ErrorClass = "remote-socket-bind"
	ClassHomeProbe   ErrorClass = "home-probe"
	ClassConfig      ErrorClass = "config"
	ClassOther       ErrorClass = "other"
)

// RemoteStatus is one remote's runtime state, as served on
// GET /api/v1/status and rendered by `dotvault ssh list`.
//
// None of it is written back to ssh.yaml: reconnect counts and last errors are
// runtime facts, and persisting them would churn the user's config file.
type RemoteStatus struct {
	Host         string `json:"host"`
	State        string `json:"state"`
	RemoteSocket string `json:"remote_socket"`
	Target       string `json:"target"`

	ConnectedSince    *time.Time `json:"connected_since,omitempty"`
	Reconnects        int        `json:"reconnects"`
	ActiveConnections int        `json:"active_connections"`
	LastError         string     `json:"last_error"`
}

// Classify maps an error to its class.
func Classify(err error) ErrorClass {
	if err == nil {
		return ClassNone
	}

	switch {
	case errors.Is(err, ErrHostKeyUnknown):
		return ClassHostKey
	case errors.Is(err, syscall.ECONNREFUSED):
		return ClassRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return ClassUnreachable
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ClassDNS
	}

	var keyErr *ssh.KeyError
	if errors.As(err, &keyErr) {
		return ClassHostKey
	}

	return ClassOther
}
```

> **Note for the implementer:** the auth, handshake, bind, and home-probe classes cannot be recognised from a sentinel — `x/crypto/ssh` returns plain errors for them. Task 9 wraps them at their call sites with typed errors; extend `Classify` there rather than string-matching now.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -run 'Classify|RemoteStatus|StatesAre' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshfwd/state.go internal/sshfwd/state_test.go
git commit -m "feat(sshfwd): state vocabulary, error taxonomy and status shape"
```

---

### Task 9: Dial, forward and pump — one managed connection

**Files:**
- Create: `internal/sshfwd/dial.go`
- Create: `internal/sshfwd/forward.go`
- Test: `internal/sshfwd/forward_test.go`

**Interfaces:**
- Consumes: `HostKeyPolicy` (4), `Signers` (5), `ExpandRemotePath` (7), `Classify` (8)
- Produces:
  - `type DialConfig struct { Host string; Port int; User string; Signers []ssh.Signer; HostKey HostKeyPolicy; Observed *ssh.PublicKey; Timeout time.Duration }`
  - `func Dial(ctx context.Context, c DialConfig) (*ssh.Client, error)`
  - `func Keepalive(ctx context.Context, cl *ssh.Client, interval time.Duration, strikes int) error`
  - `type Dialer func(ctx context.Context) (net.Conn, error)`
  - `func ServeForward(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(delta int)) error`
  - `var ErrAuth`, `var ErrBind`
  - `func Pump(a, b net.Conn)`

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/forward_test.go`. It exercises `Pump` and `ServeForward`'s unlink-retry decision against fakes — no SSH server, which Task 13 covers.

```go
package sshfwd

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPumpCopiesBothDirections(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	go Pump(a2, b1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := a1.Write([]byte("ping")); err != nil {
			t.Error(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(b2, buf); err != nil {
			t.Error(err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("a→b got %q, want %q", buf, "ping")
		}
		if _, err := b2.Write([]byte("pong")); err != nil {
			t.Error(err)
			return
		}
		rbuf := make([]byte, 4)
		if _, err := io.ReadFull(a1, rbuf); err != nil {
			t.Error(err)
			return
		}
		if string(rbuf) != "pong" {
			t.Errorf("b→a got %q, want %q", rbuf, "pong")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pump did not relay within 5s")
	}
	a1.Close()
	b2.Close()
}

func TestPumpClosesBothWhenOneSideEnds(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); Pump(a2, b1) }()

	a1.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pump did not return after one side closed")
	}

	if _, err := b2.Read(make([]byte, 1)); err == nil {
		t.Error("far side still readable; Pump must close both connections")
	}
}

type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}

func (f *fakeListener) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeListener) Addr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "unix" }
func (fakeAddr) String() string  { return "/fake.sock" }

func TestServeListenerRelaysToTarget(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	targetSrv, targetCli := net.Pipe()
	target := func(ctx context.Context) (net.Conn, error) { return targetCli, nil }

	var active struct {
		sync.Mutex
		max int
		cur int
	}
	onConn := func(delta int) {
		active.Lock()
		defer active.Unlock()
		active.cur += delta
		if active.cur > active.max {
			active.max = active.cur
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serveListener(ctx, ln, target, onConn)

	remote, forwarded := net.Pipe()
	ln.conns <- forwarded

	if _, err := remote.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if err := targetSrv.SetReadDeadline(time.Now().Add(5 * time.Second)); err == nil {
		// net.Pipe supports deadlines since Go 1.10.
	}
	if _, err := io.ReadFull(targetSrv, buf); err != nil {
		t.Fatalf("target did not receive forwarded bytes: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("target got %q, want %q", buf, "hello")
	}

	active.Lock()
	max := active.max
	active.Unlock()
	if max != 1 {
		t.Errorf("active connection gauge peaked at %d, want 1", max)
	}

	remote.Close()
	targetSrv.Close()
}

func TestServeListenerStopsOnContextCancel(t *testing.T) {
	ln := newFakeListener()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serveListener(ctx, ln, func(context.Context) (net.Conn, error) {
			return nil, errors.New("unused")
		}, func(int) {})
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serveListener returned %v, want nil/Canceled/ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveListener did not return after cancel")
	}
}

func TestServeListenerSurvivesTargetDialFailure(t *testing.T) {
	ln := newFakeListener()
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var calls int
	var mu sync.Mutex
	target := func(context.Context) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return nil, errors.New("target down")
	}
	go serveListener(ctx, ln, target, func(int) {})

	for i := 0; i < 2; i++ {
		_, forwarded := net.Pipe()
		ln.conns <- forwarded
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("serveListener stopped accepting after a target dial failure")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run 'Pump|ServeListener' -v`
Expected: FAIL — `undefined: Pump`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/dial.go`:

```go
package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrAuth marks an SSH authentication failure. x/crypto/ssh returns a plain
// error for this, so it is wrapped here to keep Classify free of string
// matching against a message that is not part of any API contract.
var ErrAuth = errors.New("ssh authentication failed")

// ErrHandshake marks a transport or handshake failure that is neither auth nor
// host key.
var ErrHandshake = errors.New("ssh handshake failed")

// DialConfig is everything needed to establish one SSH transport.
type DialConfig struct {
	Host    string
	Port    int
	User    string
	Signers []ssh.Signer
	HostKey HostKeyPolicy

	// Observed receives the presented host key even when the dial is rejected,
	// so `dotvault ssh add` can report a fingerprint to confirm. May be nil.
	Observed *ssh.PublicKey

	Timeout time.Duration
}

// DefaultDialTimeout bounds a single connection attempt. Long enough for a
// slow VPN handshake, short enough that a black-holed route does not hold a
// reconnect slot open for the OS TCP timeout.
const DefaultDialTimeout = 20 * time.Second

// Dial establishes an SSH transport. Every failure is wrapped in a sentinel so
// the caller can classify it without inspecting messages.
func Dial(ctx context.Context, c DialConfig) (*ssh.Client, error) {
	if len(c.Signers) == 0 {
		return nil, fmt.Errorf("%w: no SSH identities available from the agent backend", ErrAuth)
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultDialTimeout
	}
	port := c.Port
	if port == 0 {
		port = DefaultPort
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))

	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(c.Signers...)},
		HostKeyCallback: c.HostKey.Callback(c.Observed),
		Timeout:         timeout,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if errors.Is(err, ErrHostKeyUnknown) {
			return nil, err
		}
		var keyErr *ssh.KeyError
		if errors.As(err, &keyErr) {
			return nil, err
		}
		// x/crypto reports a rejected credential as a plain handshake error;
		// distinguish it here so the state machine can apply the auth floor.
		if isAuthFailure(err) {
			return nil, fmt.Errorf("%w: %w", ErrAuth, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(sc, chans, reqs), nil
}

// isAuthFailure recognises the handshake error x/crypto returns when every
// offered credential was rejected. There is no exported sentinel for it, so
// this is the one place a message is inspected — kept narrow and commented so
// a future x/crypto change is easy to find.
func isAuthFailure(err error) bool {
	msg := err.Error()
	return contains(msg, "unable to authenticate") ||
		contains(msg, "no supported methods remain") ||
		contains(msg, "handshake failed: ssh: unable to authenticate")
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// Keepalive sends keepalive@openssh.com until the context is cancelled or the
// strike limit is reached, returning the failure that tripped it.
//
// SSH-level rather than TCP: TCP keepalive does not detect a wedged sshd, and
// a laptop resuming from sleep needs the dead transport surfaced in seconds
// rather than after the OS TCP timeout.
func Keepalive(ctx context.Context, cl *ssh.Client, interval time.Duration, strikes int) error {
	t := time.NewTicker(interval)
	defer t.Stop()

	var consecutive int
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
			if err == nil {
				consecutive = 0
				continue
			}
			consecutive++
			if consecutive >= strikes {
				return fmt.Errorf("keepalive failed %d times: %w", consecutive, err)
			}
		}
	}
}
```

> **Note for the implementer:** replace the hand-rolled `contains`/`indexOf` with `strings.Contains` and drop both helpers. They are written out only to make the intent of `isAuthFailure` unambiguous; `strings.Contains` is the correct implementation.

Create `internal/sshfwd/forward.go`:

```go
package sshfwd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ErrBind marks a failure to bind the remote Unix socket. The usual causes are
// AllowStreamLocalForwarding being off on the remote sshd, an unwritable
// parent directory, or a stale socket left by a crashed session.
var ErrBind = errors.New("bind remote socket failed")

// Dialer opens a connection to the local API surface the forward targets.
type Dialer func(ctx context.Context) (net.Conn, error)

// ServeForward binds socket on the remote and relays every accepted connection
// to target, returning when ctx is cancelled or the transport dies.
//
// Bind ordering is load-bearing. x/crypto/ssh does not unlink a stale socket
// and sshd will not bind over one, so a leftover file from a crashed session
// would block the forward forever. But unlinking pre-emptively — the effect of
// OpenSSH's StreamLocalBindUnlink=yes — would destroy a *live* socket owned by
// a real `ssh -R` session the user is currently using. So: bind first, and
// only on failure unlink once and retry once.
func ServeForward(ctx context.Context, cl *ssh.Client, socket string, target Dialer, onConn func(delta int)) error {
	ln, err := cl.ListenUnix(socket)
	if err != nil {
		slog.Debug("remote socket bind failed; attempting stale-socket cleanup", "socket", socket, "error", err)
		if rmErr := removeRemoteFile(ctx, cl, socket); rmErr != nil {
			return fmt.Errorf("%w: %s: %w (cleanup also failed: %v)", ErrBind, socket, err, rmErr)
		}
		ln, err = cl.ListenUnix(socket)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrBind, socket, err)
		}
		slog.Info("reclaimed stale remote socket", "socket", socket)
	}
	defer ln.Close()

	return serveListener(ctx, ln, target, onConn)
}

// serveListener is the transport-agnostic accept loop, split out so it is
// testable without an SSH server.
func serveListener(ctx context.Context, ln net.Listener, target Dialer, onConn func(delta int)) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept on remote socket: %w", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			onConn(1)
			defer onConn(-1)

			local, err := target(ctx)
			if err != nil {
				// The local API surface being momentarily unavailable must not
				// stop the accept loop: the forward outlives any one request.
				slog.Warn("forward target dial failed", "error", err)
				conn.Close()
				return
			}
			Pump(conn, local)
		}()
	}
}

// Pump relays bytes in both directions until either side ends, then closes
// both. Half-close is attempted where the transport supports it (CloseWrite),
// so a client that shuts down its write side gets the response it is waiting
// for rather than a truncated stream.
//
// Payload bytes are never logged: the forwarded stream carries Vault tokens.
func Pump(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		dst.Close()
	}

	go copyDir(a, b)
	go copyDir(b, a)
	wg.Wait()

	a.Close()
	b.Close()
}

// removeRemoteFile unlinks a path on the remote over an exec channel. Only
// ever called with the exact configured socket path, and only after a bind
// failure has already proven nothing usable is listening there.
func removeRemoteFile(ctx context.Context, cl *ssh.Client, path string) error {
	sess, err := cl.NewSession()
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	done := make(chan error, 1)
	go func() { done <- sess.Run("rm -f -- " + shellQuote(path)) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("rm -f %s: %w", path, err)
		}
		return nil
	}
}

// shellQuote single-quotes s for a POSIX shell. The path comes from the user's
// own ssh.yaml and has already passed ValidateRemoteSocket, but it reaches a
// shell, so it is quoted rather than trusted.
func shellQuote(s string) string {
	return "'" + replaceAll(s, "'", `'\''`) + "'"
}
```

> **Note for the implementer:** replace `replaceAll` with `strings.ReplaceAll` and import `strings`. It is named separately here only to keep the snippet self-contained.

Add the `CommandRunner` implementation backing `ExpandRemotePath` (Task 7) in `forward.go` or `home.go`:

```go
// sshRunner runs a command over an SSH session, satisfying CommandRunner.
type sshRunner struct{ cl *ssh.Client }

func (r sshRunner) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := r.cl.NewSession()
	if err != nil {
		return "", fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.Output(cmd)
		done <- result{out, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return "", fmt.Errorf("run %q: %w", cmd, r.err)
		}
		return string(r.out), nil
	}
}
```

Extend `Classify` in `state.go` with the new sentinels:

```go
	case errors.Is(err, ErrAuth):
		return ClassAuth
	case errors.Is(err, ErrBind):
		return ClassBind
	case errors.Is(err, ErrHandshake):
		return ClassHandshake
```

placed before the `ClassOther` fallthrough, and add a matching case to `TestClassify`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -race -v`
Expected: PASS

- [ ] **Step 5: Verify the assertions are load-bearing**

Temporarily make the target-dial failure branch in `serveListener` `return` instead of `continue`-ing the loop; `TestServeListenerSurvivesTargetDialFailure` must fail. Temporarily drop the `a.Close(); b.Close()` at the end of `Pump`; `TestPumpClosesBothWhenOneSideEnds` must fail. Revert both.

- [ ] **Step 6: Commit**

```bash
git add internal/sshfwd/dial.go internal/sshfwd/forward.go internal/sshfwd/forward_test.go internal/sshfwd/state.go internal/sshfwd/state_test.go
git commit -m "feat(sshfwd): dial, keepalive, remote socket bind and bidirectional pump"
```

---

### Task 10: `ManagedRemote` lifecycle and `Manager.Reconcile`

**Files:**
- Create: `internal/sshfwd/remote.go`
- Create: `internal/sshfwd/manager.go`
- Test: `internal/sshfwd/manager_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2, 4–9
- Produces:
  - `type Deps struct { Signers func() ([]ssh.Signer, error); User func() (string, error); Target Dialer; TargetName string; Policy func(Remote) HostKeyPolicy }`
  - `type Manager struct { … }`
  - `func NewManager(d Deps) *Manager`
  - `func (m *Manager) Reconcile(ctx context.Context, remotes []Remote) error`
  - `func (m *Manager) Status() []RemoteStatus`
  - `func (m *Manager) Close()`
  - `func (r *ManagedRemote) WaitForClient(ctx context.Context) (*ssh.Client, error)`

`Manager` holds a mutex over its `map[string]*ManagedRemote`. `Reconcile` is idempotent and safe to call concurrently.

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/manager_test.go`. The connect step is stubbed via an unexported `connect` field on `ManagedRemote` so reconciliation is testable without an SSH server.

```go
package sshfwd

import (
	"context"
	"sync"
	"testing"
	"time"
)

// stubDeps builds a Manager whose remotes never actually dial. runFn records
// which hosts were started and blocks until its context is cancelled, so a
// stopped remote is observable.
func stubManager(t *testing.T) (*Manager, *runRecorder) {
	t.Helper()
	rec := &runRecorder{started: map[string]int{}, stopped: map[string]int{}}
	m := NewManager(Deps{})
	m.newRunner = rec.runner
	t.Cleanup(m.Close)
	return m, rec
}

type runRecorder struct {
	mu      sync.Mutex
	started map[string]int
	stopped map[string]int
}

func (r *runRecorder) runner(host string) func(context.Context) {
	return func(ctx context.Context) {
		r.mu.Lock()
		r.started[host]++
		r.mu.Unlock()

		<-ctx.Done()

		r.mu.Lock()
		r.stopped[host]++
		r.mu.Unlock()
	}
}

func (r *runRecorder) counts(host string) (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started[host], r.stopped[host]
}

func (r *runRecorder) waitStopped(t *testing.T, host string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, stopped := r.counts(host); stopped >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, stopped := r.counts(host)
	t.Fatalf("host %s stopped %d times, want %d", host, stopped, want)
}

func remote(host string) Remote {
	return Remote{Host: host, RemoteSocket: DefaultRemoteSocket}
}

func TestReconcileStartsNewRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatalf("Reconcile() = %v", err)
	}
	if started, _ := rec.counts("foo.example.com"); started != 1 {
		t.Errorf("foo started %d times, want 1", started)
	}
}

func TestReconcileKeepsUnchangedRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	r := []Remote{remote("foo.example.com")}
	if err := m.Reconcile(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, r); err != nil {
		t.Fatal(err)
	}
	started, stopped := rec.counts("foo.example.com")
	if started != 1 || stopped != 0 {
		t.Errorf("unchanged remote restarted: started=%d stopped=%d, want 1/0", started, stopped)
	}
}

func TestReconcileAddsWithoutDisturbingExisting(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com"), remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	if started, stopped := rec.counts("foo.example.com"); started != 1 || stopped != 0 {
		t.Errorf("foo disturbed by adding bar: started=%d stopped=%d", started, stopped)
	}
	if started, _ := rec.counts("bar.example.com"); started != 1 {
		t.Errorf("bar started %d times, want 1", started)
	}
}

func TestReconcileStopsRemovedRemotes(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com"), remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, []Remote{remote("bar.example.com")}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)
	if _, stopped := rec.counts("bar.example.com"); stopped != 0 {
		t.Errorf("bar stopped %d times, want 0", stopped)
	}
}

func TestReconcileRestartsModifiedRemote(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	changed := remote("foo.example.com")
	changed.Port = 2222
	if err := m.Reconcile(ctx, []Remote{changed}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)
	if started, _ := rec.counts("foo.example.com"); started != 2 {
		t.Errorf("modified remote started %d times, want 2 (restart)", started)
	}
}

func TestReconcileTreatsDisabledAsRemoved(t *testing.T) {
	m, rec := stubManager(t)
	ctx := context.Background()

	if err := m.Reconcile(ctx, []Remote{remote("foo.example.com")}); err != nil {
		t.Fatal(err)
	}
	off := false
	disabled := remote("foo.example.com")
	disabled.Enabled = &off
	if err := m.Reconcile(ctx, []Remote{disabled}); err != nil {
		t.Fatal(err)
	}
	rec.waitStopped(t, "foo.example.com", 1)

	statuses := m.Status()
	if len(statuses) != 1 {
		t.Fatalf("Status() returned %d entries, want 1", len(statuses))
	}
	if statuses[0].State != string(StateDisabled) {
		t.Errorf("disabled remote state = %q, want %q", statuses[0].State, StateDisabled)
	}
}

func TestReconcileRejectsInvalidRemote(t *testing.T) {
	m, _ := stubManager(t)
	err := m.Reconcile(context.Background(), []Remote{{Host: "", RemoteSocket: "~/x.sock"}})
	if err == nil {
		t.Fatal("Reconcile() accepted an invalid remote; must reject")
	}
}

func TestCloseStopsEverything(t *testing.T) {
	rec := &runRecorder{started: map[string]int{}, stopped: map[string]int{}}
	m := NewManager(Deps{})
	m.newRunner = rec.runner

	if err := m.Reconcile(context.Background(), []Remote{remote("a.example.com"), remote("b.example.com")}); err != nil {
		t.Fatal(err)
	}
	m.Close()
	rec.waitStopped(t, "a.example.com", 1)
	rec.waitStopped(t, "b.example.com", 1)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run 'Reconcile|CloseStops' -v`
Expected: FAIL — `undefined: NewManager`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/remote.go` with the `ManagedRemote` type: it holds the `Remote`, a mutex-guarded `State`/`RemoteStatus`, a `*ssh.Client` behind a `WaitForClient(ctx)` that blocks up to `ClientWaitTimeout` (10 s) on a `chan struct{}` closed each time a client is installed, a `*Backoff`, and a `run(ctx)` loop:

```
for ctx alive:
    setState(connecting)
    signers ← deps.Signers()          ; user ← deps.User()
    client  ← Dial(...)               ; on error: classify, setState, sleep backoff (AuthFailureFloor for ClassAuth/ClassHostKey), continue
    socket  ← ExpandRemotePath(ctx, sshRunner{client}, r.RemoteSocket)
    setState(connected); record connectedSince; start stable-reset timer
    errCh ← run ServeForward(...) and Keepalive(...) concurrently
    on first error: setState(reconnecting), close client, increment reconnects, sleep backoff, continue
```

Create `internal/sshfwd/manager.go`:

```go
package sshfwd

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Deps are the daemon-supplied capabilities a managed remote needs. They are
// funcs rather than values because each is re-resolved per connection attempt:
// a Vault-CA certificate rotated since the last dial must be picked up on the
// next one without any cache of its own.
type Deps struct {
	Signers    func() ([]ssh.Signer, error)
	User       func() (string, error)
	Target     Dialer
	TargetName string
	Policy     func(Remote) HostKeyPolicy
}

// Manager reconciles the set of managed remotes against the configured list.
//
// Reconciliation is deliberately isolated from every trigger that can cause it
// — daemon startup, the config-refresh loop, an API mutation, a test — so all
// four enter through one door and none can drift.
type Manager struct {
	deps Deps

	mu      sync.Mutex
	remotes map[string]*ManagedRemote

	// newRunner is the goroutine body for a managed remote, injected so
	// reconciliation is testable without an SSH server.
	newRunner func(host string) func(context.Context)
}

// NewManager returns a Manager with no remotes running.
func NewManager(d Deps) *Manager {
	m := &Manager{deps: d, remotes: map[string]*ManagedRemote{}}
	return m
}

// Reconcile brings the running set in line with remotes: unchanged entries keep
// running untouched, new ones start, removed ones stop, changed ones restart.
// A disabled entry is treated as removed but retains a status row so the user
// can see it is configured-but-off rather than missing.
func (m *Manager) Reconcile(ctx context.Context, remotes []Remote) error {
	for _, r := range remotes {
		if err := ValidateRemote(r); err != nil {
			return fmt.Errorf("remote %q: %w", r.Host, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]Remote, len(remotes))
	for _, r := range remotes {
		desired[r.Host] = r
	}

	for host, mr := range m.remotes {
		want, ok := desired[host]
		if !ok || !want.EnabledOrDefault() || mr.cfg != want {
			mr.stop()
			delete(m.remotes, host)
		}
	}

	for host, r := range desired {
		if _, ok := m.remotes[host]; ok {
			continue
		}
		mr := newManagedRemote(r, m.deps)
		if !r.EnabledOrDefault() {
			mr.setState(StateDisabled, nil)
			m.remotes[host] = mr
			continue
		}
		run := mr.run
		if m.newRunner != nil {
			run = m.newRunner(host)
		}
		mr.start(ctx, run)
		m.remotes[host] = mr
	}
	return nil
}

// Status returns a snapshot of every managed remote, ordered by host so CLI
// output is stable between invocations.
func (m *Manager) Status() []RemoteStatus {
	m.mu.Lock()
	out := make([]RemoteStatus, 0, len(m.remotes))
	for _, mr := range m.remotes {
		out = append(out, mr.status(m.deps.TargetName))
	}
	m.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// Close stops every managed remote and waits for them to finish.
func (m *Manager) Close() {
	m.mu.Lock()
	remotes := make([]*ManagedRemote, 0, len(m.remotes))
	for host, mr := range m.remotes {
		remotes = append(remotes, mr)
		delete(m.remotes, host)
	}
	m.mu.Unlock()

	for _, mr := range remotes {
		mr.stop()
	}
}
```

`ManagedRemote.start(ctx, run)` derives a cancellable context, stores the cancel, and runs `run` in a goroutine tracked by a `sync.WaitGroup`; `stop()` cancels and waits.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -race -v`
Expected: PASS

- [ ] **Step 5: Verify the assertions are load-bearing**

Temporarily drop the `mr.cfg != want` term from the stop condition; `TestReconcileRestartsModifiedRemote` must fail. Temporarily always restart (remove the `if _, ok := m.remotes[host]; ok { continue }`); `TestReconcileKeepsUnchangedRemotes` must fail. Revert both.

- [ ] **Step 6: Commit**

```bash
git add internal/sshfwd/remote.go internal/sshfwd/manager.go internal/sshfwd/manager_test.go
git commit -m "feat(sshfwd): managed remote lifecycle and declarative reconciler"
```

---

### Task 11: `Registry` — the single mutation service layer

**Files:**
- Create: `internal/sshfwd/registry.go`
- Test: `internal/sshfwd/registry_test.go`

**Interfaces:**
- Consumes: `Load`/`Save`/`ValidateRemote` (2), `HostKeyPolicy` (4), `Manager` (10)
- Produces:
  - `type Verifier interface { Verify(ctx context.Context, r Remote) (VerifyResult, error) }`
  - `type VerifyResult struct { HostKey string; Fingerprint string; ResolvedSocket string }`
  - `type Registry struct { … }`
  - `func NewRegistry(path string, mgr *Manager, v Verifier) *Registry`
  - `func (g *Registry) List() ([]Remote, error)`
  - `func (g *Registry) Add(ctx context.Context, r Remote, opts AddOptions) (*Remote, error)`
  - `func (g *Registry) Patch(ctx context.Context, host string, p Patch) (*Remote, error)`
  - `func (g *Registry) Remove(ctx context.Context, host string) (bool, error)`
  - `type AddOptions struct { Force bool; AcceptFingerprint string }`
  - `type Patch struct { Enabled *bool; RemoteSocket *string; Port *int }`
  - `var ErrConfirmHostKey` — carries the fingerprint the caller must echo back

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/registry_test.go`:

```go
package sshfwd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type fakeVerifier struct {
	result VerifyResult
	err    error
	calls  int
}

func (f *fakeVerifier) Verify(ctx context.Context, r Remote) (VerifyResult, error) {
	f.calls++
	return f.result, f.err
}

func newTestRegistry(t *testing.T, v Verifier) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	m := NewManager(Deps{})
	m.newRunner = func(string) func(context.Context) {
		return func(ctx context.Context) { <-ctx.Done() }
	}
	t.Cleanup(m.Close)
	return NewRegistry(path, m, v), path
}

func TestAddRequiresFingerprintConfirmation(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{
		HostKey:        "ssh-ed25519 AAAAC3Nz",
		Fingerprint:    "SHA256:abc",
		ResolvedSocket: "/home/me/.ssh/dotvault.sock",
	}}
	g, path := newTestRegistry(t, v)

	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{})
	if !errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() without confirmation = %v, want ErrConfirmHostKey", err)
	}

	f, loadErr := Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(f.Remotes) != 0 {
		t.Fatalf("Add() persisted %d remotes before confirmation, want 0", len(f.Remotes))
	}
}

func TestAddCommitsWhenFingerprintEchoed(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{
		HostKey:        "ssh-ed25519 AAAAC3Nz",
		Fingerprint:    "SHA256:abc",
		ResolvedSocket: "/home/me/.ssh/dotvault.sock",
	}}
	g, path := newTestRegistry(t, v)

	got, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"})
	if err != nil {
		t.Fatalf("Add() = %v", err)
	}
	if got.HostKey != "ssh-ed25519 AAAAC3Nz" {
		t.Errorf("stored host key = %q, want the verified key", got.HostKey)
	}
	if got.RemoteSocket != DefaultRemoteSocket {
		t.Errorf("remote_socket = %q, want the default %q stored unexpanded", got.RemoteSocket, DefaultRemoteSocket)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 {
		t.Fatalf("persisted %d remotes, want 1", len(f.Remotes))
	}
}

func TestAddRejectsWrongFingerprint(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, _ := newTestRegistry(t, v)
	_, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:wrong"})
	if err == nil || errors.Is(err, ErrConfirmHostKey) {
		t.Fatalf("Add() with a mismatched fingerprint = %v, want a rejection", err)
	}
}

func TestAddDoesNotPersistWhenVerificationFails(t *testing.T) {
	want := errors.New("AllowStreamLocalForwarding is off")
	v := &fakeVerifier{err: want}
	g, path := newTestRegistry(t, v)

	if _, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{}); !errors.Is(err, want) {
		t.Fatalf("Add() = %v, want %v", err, want)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 0 {
		t.Fatal("Add() persisted an entry it could not verify")
	}
}

func TestAddForceSkipsVerification(t *testing.T) {
	v := &fakeVerifier{err: errors.New("host is offline")}
	g, path := newTestRegistry(t, v)

	if _, err := g.Add(context.Background(), Remote{Host: "foo.example.com"}, AddOptions{Force: true}); err != nil {
		t.Fatalf("Add(force) = %v", err)
	}
	if v.calls != 0 {
		t.Errorf("verifier called %d times under --force, want 0", v.calls)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 {
		t.Fatalf("persisted %d remotes, want 1", len(f.Remotes))
	}
}

func TestAddIsIdempotentOnHost(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()
	opts := AddOptions{AcceptFingerprint: "SHA256:abc"}

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, opts); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Add(ctx, Remote{Host: "foo.example.com", Port: 2222}, opts); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Remotes) != 1 {
		t.Fatalf("second Add created a duplicate: %d remotes", len(f.Remotes))
	}
	if f.Remotes[0].Port != 2222 {
		t.Errorf("second Add did not update the entry: %+v", f.Remotes[0])
	}
}

func TestRemove(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"}); err != nil {
		t.Fatal(err)
	}
	removed, err := g.Remove(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("Remove() = %v", err)
	}
	if !removed {
		t.Error("Remove() = false, want true")
	}
	removed, err = g.Remove(ctx, "foo.example.com")
	if err != nil {
		t.Fatalf("second Remove() = %v", err)
	}
	if removed {
		t.Error("second Remove() = true, want false (idempotent)")
	}
}

func TestPatchTogglesEnabled(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, path := newTestRegistry(t, v)
	ctx := context.Background()

	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"}); err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := g.Patch(ctx, "foo.example.com", Patch{Enabled: &off}); err != nil {
		t.Fatalf("Patch() = %v", err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Remotes[0].EnabledOrDefault() {
		t.Error("Patch() did not disable the remote")
	}
}

func TestPatchRejectsInvalidSocket(t *testing.T) {
	v := &fakeVerifier{result: VerifyResult{Fingerprint: "SHA256:abc", HostKey: "k"}}
	g, _ := newTestRegistry(t, v)
	ctx := context.Background()
	if _, err := g.Add(ctx, Remote{Host: "foo.example.com"}, AddOptions{AcceptFingerprint: "SHA256:abc"}); err != nil {
		t.Fatal(err)
	}
	bad := "relative/path.sock"
	if _, err := g.Patch(ctx, "foo.example.com", Patch{RemoteSocket: &bad}); err == nil {
		t.Fatal("Patch() accepted an invalid remote_socket")
	}
}

func TestPatchUnknownHost(t *testing.T) {
	g, _ := newTestRegistry(t, &fakeVerifier{})
	off := false
	if _, err := g.Patch(context.Background(), "nope.example.com", Patch{Enabled: &off}); err == nil {
		t.Fatal("Patch() on an unknown host succeeded; want an error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run 'Add|Remove|Patch' -v`
Expected: FAIL — `undefined: NewRegistry`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/registry.go`. Key points to implement:

- A `sync.Mutex` serialises every read-modify-write. The daemon is the sole writer — the CLI is an API client — so no cross-process lock is needed, but two concurrent web requests are entirely possible.
- Each mutation re-`Load`s under the lock, mutates, `Save`s, then calls `mgr.Reconcile` with the new list. Reconciling inside the same critical section keeps the running set and the file from diverging.
- `Add` defaults `RemoteSocket` to `DefaultRemoteSocket` when empty, validates, then (unless `Force`) calls `Verify`. On `ErrConfirmHostKey` nothing is written.
- `ErrConfirmHostKey` is a struct error carrying the fingerprint so the caller can render it.

```go
// ErrConfirmHostKey is returned by Add when the host's key is neither pinned
// nor CA-signed. It is not a failure: it is the one point at which a human
// decides to trust a host. The caller re-submits with AddOptions.
// AcceptFingerprint set to the fingerprint carried here.
//
// Requiring the fingerprint to be echoed — rather than a bare "yes" flag — is
// what keeps the browser path from degrading into blind trust-on-first-use:
// neither surface can commit without repeating back a value the daemon just
// observed for itself.
var ErrConfirmHostKey = errors.New("host key requires confirmation")

// HostKeyConfirmation carries the fingerprint a caller must echo back.
type HostKeyConfirmation struct {
	Host        string
	Fingerprint string
}

func (e *HostKeyConfirmation) Error() string {
	return fmt.Sprintf("%s: %v (offered %s)", e.Host, ErrConfirmHostKey, e.Fingerprint)
}

func (e *HostKeyConfirmation) Unwrap() error { return ErrConfirmHostKey }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -race -v`
Expected: PASS

- [ ] **Step 5: Verify the assertions are load-bearing**

Temporarily move the `Save` call in `Add` to before the `Verify` call; `TestAddDoesNotPersistWhenVerificationFails` and `TestAddRequiresFingerprintConfirmation` must both fail. Revert.

- [ ] **Step 6: Commit**

```bash
git add internal/sshfwd/registry.go internal/sshfwd/registry_test.go
git commit -m "feat(sshfwd): registry service layer with transactional add and fingerprint handshake"
```

---

### Task 12: Live `Verifier` — the transactional dry run

**Files:**
- Create: `internal/sshfwd/verify.go`
- Test: `internal/sshfwd/verify_test.go`

**Interfaces:**
- Consumes: `Dial` (9), `ServeForward` (9), `ExpandRemotePath` (7), `HostKeyPolicy` (4)
- Produces: `func NewVerifier(d Deps) Verifier`

- [ ] **Step 1: Write the failing test**

Create `internal/sshfwd/verify_test.go`:

```go
package sshfwd

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVerifierFailsWithoutSigners(t *testing.T) {
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, nil },
		User:    func() (string, error) { return "me", nil },
		Policy:  func(Remote) HostKeyPolicy { return HostKeyPolicy{} },
	})
	_, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("Verify() = %v, want ErrAuth when the agent has no identities", err)
	}
}

func TestVerifierPropagatesSignerError(t *testing.T) {
	want := errors.New("vault down")
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return nil, want },
		User:    func() (string, error) { return "me", nil },
		Policy:  func(Remote) HostKeyPolicy { return HostKeyPolicy{} },
	})
	if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}); !errors.Is(err, want) {
		t.Fatalf("Verify() = %v, want %v", err, want)
	}
}

func TestVerifierPropagatesUserError(t *testing.T) {
	want := errors.New("no identity")
	s, _ := testKey(t)
	v := NewVerifier(Deps{
		Signers: func() ([]ssh.Signer, error) { return []ssh.Signer{s}, nil },
		User:    func() (string, error) { return "", want },
		Policy:  func(Remote) HostKeyPolicy { return HostKeyPolicy{} },
	})
	if _, err := v.Verify(context.Background(), Remote{Host: "192.0.2.1", RemoteSocket: DefaultRemoteSocket}); !errors.Is(err, want) {
		t.Fatalf("Verify() = %v, want %v", err, want)
	}
}
```

The happy path needs a real SSH server and is covered by the integration suite in Task 17.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshfwd/ -run Verifier -v`
Expected: FAIL — `undefined: NewVerifier`

- [ ] **Step 3: Write minimal implementation**

Create `internal/sshfwd/verify.go`. `Verify` runs the full path and tears it down:

1. `deps.Signers()` / `deps.User()` — propagate errors verbatim.
2. `Dial` with `Observed` set, so an `ErrHostKeyUnknown` still yields a fingerprint.
3. On `ErrHostKeyUnknown`, return `VerifyResult{HostKey, Fingerprint}` **with a nil error** — the Registry turns that into the confirmation handshake. Any other dial error is returned.
4. `ExpandRemotePath` through `sshRunner{client}`.
5. `cl.ListenUnix(socket)` and immediate `Close()` — this is what catches `AllowStreamLocalForwarding no` and an unwritable directory. Do **not** run the stale-socket unlink here: `add` must never delete a file on a host it has not yet been told to manage.
6. `cl.Close()`.

Document point 5's asymmetry with `ServeForward` in a comment — it is deliberate and a future reader will otherwise "fix" it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshfwd/ -race -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshfwd/verify.go internal/sshfwd/verify_test.go
git commit -m "feat(sshfwd): live verifier so add refuses to persist an unusable remote"
```

---

### Task 13: Web API endpoints

**Files:**
- Create: `internal/web/ssh.go`
- Modify: `internal/web/server.go` (routes + `ServerConfig` field + status block)
- Test: `internal/web/ssh_test.go`

**Interfaces:**
- Consumes: `sshfwd.Registry`, `sshfwd.Manager` (11, 10)
- Produces: `ServerConfig.SSHRegistry *sshfwd.Registry`, `ServerConfig.SSHStatus func() []sshfwd.RemoteStatus`

- [ ] **Step 1: Write the failing test**

Create `internal/web/ssh_test.go` following the existing handler-test idiom in this package (find it in `internal/web/*_test.go` and reuse the server-construction helper). Cases:

```go
func TestSSHRemotesListEmpty(t *testing.T)                 // 200, {"remotes":[]}
func TestSSHRemotesAddReturns409WithFingerprint(t *testing.T) // 409, body carries fingerprint
func TestSSHRemotesAddCommitsWithFingerprint(t *testing.T)  // 201
func TestSSHRemotesAddRequiresCSRF(t *testing.T)            // 403 without a token
func TestSSHRemotesDeleteRequiresCSRF(t *testing.T)         // 403 without a token
func TestSSHRemotesPatchRequiresCSRF(t *testing.T)          // 403 without a token
func TestSSHRemotesDeleteUnknownHost(t *testing.T)          // 404
func TestSSHEndpointsDisabledWithoutRegistry(t *testing.T)  // 503 when SSHRegistry is nil
func TestStatusIncludesSSHBlock(t *testing.T)               // /api/v1/status carries "ssh"
```

Write each with an explicit status-code and body assertion. The CSRF cases are the load-bearing ones: assert the *mutation did not happen*, not merely that the response was 403.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/web/ -run SSH -v`
Expected: FAIL — routes not registered

- [ ] **Step 3: Write minimal implementation**

Create `internal/web/ssh.go` with four handlers over `s.sshRegistry`. Register in `server.go` alongside the other API routes:

```go
	s.mux.HandleFunc("GET /api/v1/ssh/remotes", s.handleSSHList)
	s.mux.HandleFunc("POST /api/v1/ssh/remotes", s.requireCSRF(s.handleSSHAdd))
	s.mux.HandleFunc("PATCH /api/v1/ssh/remotes/{host}", s.requireCSRF(s.handleSSHPatch))
	s.mux.HandleFunc("DELETE /api/v1/ssh/remotes/{host}", s.requireCSRF(s.handleSSHDelete))
```

Header comment for the file:

```go
// SSH managed-forward CRUD. Unlike the peer-action endpoints in browse.go /
// notify.go / clipboard.go, these are CSRF-protected in the ordinary way. That
// exemption exists because a bare curl over a forwarded socket cannot run the
// issue-then-spend handshake; both consumers here — the SPA and `dotvault ssh`
// — can, so there is no reason to weaken the control.
//
// Every mutation goes through sshfwd.Registry rather than touching ssh.yaml,
// so the CLI and the browser share one validation path, one trust gesture and
// one writer by construction.
```

`handleSSHAdd` maps `errors.Is(err, sshfwd.ErrConfirmHostKey)` to **409** with `{"host":…,"fingerprint":…}`, a validation error to 400, and success to 201 with the stored remote. All four return 503 when `s.sshRegistry == nil` (managed forwards not configured).

Add the `ssh` block to `handleStatus`, guarded on `s.sshStatus != nil`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/web/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/web/ssh.go internal/web/ssh_test.go internal/web/server.go
git commit -m "feat(web): CRUD endpoints for managed SSH forwards"
```

---

### Task 14: CLI as an API client

**Files:**
- Create: `cmd/dotvault/ssh.go`, `cmd/dotvault/ssh_add.go`, `cmd/dotvault/ssh_list.go`, `cmd/dotvault/ssh_remove.go`
- Modify: `cmd/dotvault/root.go` (register the command)
- Test: `cmd/dotvault/ssh_test.go`

**Interfaces:**
- Consumes: the endpoints from Task 13, `auth.PeerSocketClient` (existing)
- Produces: `func daemonClient(cfg *config.Config) (*http.Client, string, error)` returning a client and a base URL

- [ ] **Step 1: Write the failing test**

Create `cmd/dotvault/ssh_test.go`. Stand up an `httptest.Server` as the fake daemon and point the transport at it via an injectable var (mirror how `runBrowseWith` / `runNotifyWith` are tested in this package — read one first and copy its shape, including `paths.SetSystemConfigPathForTest`).

```go
func TestSSHListRendersDaemonState(t *testing.T)        // table columns, ordering
func TestSSHListDegradesWhenDaemonDown(t *testing.T)    // reads ssh.yaml, state "unavailable"
func TestSSHAddPromptsOnFingerprint409(t *testing.T)    // re-POSTs with the echoed fingerprint
func TestSSHAddNonTTYRequiresAcceptFlag(t *testing.T)   // 409 without --accept-host-key is an error
func TestSSHAddReportsDaemonDown(t *testing.T)          // message names the daemon, not a transport error
func TestSSHRemoveIsIdempotent(t *testing.T)            // 404 exits 0 with a message
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/dotvault/ -run SSH -v`
Expected: FAIL — `undefined: newSSHCmd`

- [ ] **Step 3: Write minimal implementation**

`cmd/dotvault/ssh.go` holds the parent command and the transport resolver:

```go
// daemonClient returns an HTTP client addressed at the running daemon's API.
//
// Transport preference mirrors the forward's own target: the per-user API
// socket when api.enabled (owner-only, and present on a headless host with no
// web UI), else the loopback web listener. On Windows only the latter exists
// today, so `dotvault ssh` there requires web.enabled — stated in the error so
// the user is not left guessing.
//
// The CLI is deliberately a thin client rather than a second writer of
// ssh.yaml: the SSH identity lives in the daemon's agent backend, so only the
// daemon can perform the verifying login that `add` requires, and a single
// writer removes the lost-update race outright.
func daemonClient(cfg *config.Config) (*http.Client, string, error)
```

`ssh add` flow: `GET /api/v1/csrf` → `POST /api/v1/ssh/remotes` → on 409, print the fingerprint and prompt (or require `--accept-host-key` when stdin is not a TTY) → re-POST with `accept_fingerprint`.

`ssh list`: `GET /api/v1/status`, render the table; on a transport failure fall back to `sshfwd.Load(paths.SSHConfigPath())` and print `unavailable` in the STATUS column.

Register in `root.go` next to the other subcommands.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/dotvault/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/dotvault/ssh.go cmd/dotvault/ssh_add.go cmd/dotvault/ssh_list.go cmd/dotvault/ssh_remove.go cmd/dotvault/ssh_test.go cmd/dotvault/root.go
git commit -m "feat(cli): dotvault ssh add/list/remove as daemon API clients"
```

---

### Task 15: Daemon wiring

**Files:**
- Modify: `cmd/dotvault/main.go`
- Test: `cmd/dotvault/sshwire_test.go`

**Interfaces:**
- Consumes: `sshfwd.NewManager`, `NewRegistry`, `NewVerifier`, `Signers`; the existing agent service and config-refresh loop
- Produces: `func sshForwardDeps(cfg *config.Config, backend sshfwd.SignerSource, username string) (sshfwd.Deps, error)`

- [ ] **Step 1: Write the failing test**

Create `cmd/dotvault/sshwire_test.go`:

```go
func TestSSHForwardDepsRequiresAgent(t *testing.T)        // agent.enabled false → error naming agent.enabled
func TestSSHForwardDepsRequiresLocalAPISurface(t *testing.T) // neither web nor api → error naming both
func TestSSHForwardDepsPrefersAPISocket(t *testing.T)     // both on → TargetName is the unix socket
func TestSSHForwardDepsFallsBackToWebListen(t *testing.T) // api off, web on → TargetName is the TCP address
func TestSSHForwardDepsPolicyCarriesCAsAndPin(t *testing.T) // cfg.SSH CAs and remote.HostKey both reach HostKeyPolicy
```

The preference test is the load-bearing one: the API socket is 0600-in-0700 while the TCP listener is reachable by every uid on the box, so a regression that silently prefers TCP is a real exposure change.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/dotvault/ -run SSHForwardDeps -v`
Expected: FAIL — `undefined: sshForwardDeps`

- [ ] **Step 3: Write minimal implementation**

Add `sshForwardDeps` to `main.go` (or a new `cmd/dotvault/sshwire.go`), then wire the daemon:

1. After the agent backend is constructed and the first auth succeeds, build `Deps`, `Manager`, `Verifier`, `Registry`.
2. `Reconcile` with the remotes from `sshfwd.Load(paths.SSHConfigPath())`.
3. Pass `SSHRegistry` and `SSHStatus` into `ServerConfig`.
4. In the config-refresh loop, re-`Load` ssh.yaml each pass and `Reconcile` — this is what makes a hand-edit converge without a restart.
5. `defer mgr.Close()`.

Precondition failures log a WARN naming the missing setting and skip the subsystem; the daemon still starts.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/dotvault/ -v && go build ./... && GOOS=windows go build ./...`
Expected: PASS, both builds succeed

- [ ] **Step 5: Manual smoke test**

```bash
docker compose up -d
go run ./cmd/dotvault run --config config.dev.yaml
```

Expected: daemon starts; with no `ssh.yaml` present it logs nothing about SSH forwards and reconciles zero remotes.

- [ ] **Step 6: Commit**

```bash
git add cmd/dotvault/main.go cmd/dotvault/sshwire.go cmd/dotvault/sshwire_test.go
git commit -m "feat(daemon): wire managed SSH forwards into startup and config refresh"
```

---

### Task 16: Observability

**Files:**
- Modify: `internal/observability/` (add instruments beside the existing ones)
- Modify: `internal/sshfwd/remote.go`, `internal/sshfwd/forward.go` (call sites)
- Test: `internal/observability/*_test.go`

**Interfaces:**
- Produces: `observability.RecordSSHConnState`, `RecordSSHReconnect`, `RecordSSHConnectFailure(class)`, `RecordSSHKeepaliveFailure`, `RecordSSHForwardConn(delta)`, `RecordSSHForwardFailure`

- [ ] **Step 1: Write the failing test**

Follow the existing instrument tests in `internal/observability`. Assert each helper is callable with the no-op meter (observability disabled) without panicking, and that the error-class label is drawn from the fixed `ErrorClass` set rather than an arbitrary string — unbounded label cardinality is the failure mode this guards.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/observability/ -run SSH -v`
Expected: FAIL — undefined helpers

- [ ] **Step 3: Write minimal implementation**

Add the instruments named in the spec, following the file's existing registration pattern, then call them from the state machine (on transition only, never per loop iteration) and from `serveListener`'s `onConn`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/observability/ ./internal/sshfwd/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/observability internal/sshfwd
git commit -m "feat(observability): metrics for managed SSH forward connections"
```

---

### Task 17: Integration tests against a real sshd

**Files:**
- Modify: `docker-compose.yml` (add an `sshd` service under a profile)
- Create: `test/integration/sshfwd_test.go`
- Create: `test/integration/testdata/sshd/` (config + CA)

**Interfaces:**
- Consumes: everything

- [ ] **Step 1: Add the sshd service**

Add to `docker-compose.yml`, under a profile so `docker compose up -d` does not start it (mirroring the existing `jfrog` profile):

```yaml
  sshd:
    profiles: ["sshfwd"]
    image: linuxserver/openssh-server:latest
    environment:
      - USER_NAME=dotvault
      - PUBLIC_KEY_FILE=/keys/authorized.pub
      - DOCKER_MODS=linuxserver/mods:openssh-server-ssh-tunnel
    volumes:
      - ./test/integration/testdata/sshd/keys:/keys:ro
      - ./test/integration/testdata/sshd/sshd_config.d:/config/sshd/sshd_config.d:ro
    ports:
      - "127.0.0.1:2222:2222"
```

The `sshd_config.d` drop-in must set `AllowStreamLocalForwarding yes` and `StreamLocalBindUnlink no` — the latter deliberately, so case 4 below exercises dotvault's own reclaim path rather than sshd doing the work.

- [ ] **Step 2: Write the failing test**

Create `test/integration/sshfwd_test.go`, gated by the same `skipIfNoVault`-style helper this directory already uses, plus a `skipIfNoSSHD` that dials `127.0.0.1:2222`:

```go
func TestForwardReachesLocalTarget(t *testing.T)      // bind, connect through the socket, get a response
func TestForwardReconnectsAfterTransportLoss(t *testing.T) // kill transport → reconnecting → recovers
func TestForwardReclaimsStaleSocket(t *testing.T)     // pre-create the socket file; assert bind succeeds
func TestVerifyRefusesWhenForwardingDisabled(t *testing.T) // AllowStreamLocalForwarding no → Add persists nothing
func TestVerifyReturnsFingerprintForUnknownHost(t *testing.T) // unpinned host → confirmation, nothing written
```

For the local target, stand up an `httptest.Server` on a Unix socket and point `Deps.Target` at it — the test asserts the forward, not dotvault's web API.

- [ ] **Step 3: Run test to verify it fails**

```bash
docker compose --profile sshfwd up -d
go test ./test/integration/ -run Forward -v
```
Expected: FAIL until the wiring is right

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./test/integration/ -run 'Forward|Verify' -race -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml test/integration/sshfwd_test.go test/integration/testdata/sshd
git commit -m "test(integration): managed SSH forwards against a real sshd"
```

---

### Task 18: Web UI page

**Files:**
- Create: `internal/web/frontend/src/components/ssh-page.jsx`
- Modify: the SPA router and nav

**Interfaces:**
- Consumes: the endpoints from Task 13

- [ ] **Step 1: Build the page**

A table of remotes with live state, an add form, an enable/disable toggle, and a delete button. The add flow must render the 409 fingerprint in a confirm dialog and re-submit with `accept_fingerprint` — matching the CLI prompt, since both drive one protocol.

Follow the existing component idiom (read `enrol-page.jsx` first). Poll `/api/v1/status` for state on the interval the dashboard already uses rather than adding a second cadence.

- [ ] **Step 2: Build the assets**

```bash
cd internal/web/frontend && npm run build
```
Expected: build succeeds, `embed.FS` assets updated

- [ ] **Step 3: Verify in the browser**

```bash
docker compose --profile sshfwd up -d
go run ./cmd/dotvault run --config config.dev.yaml
```

Open `http://127.0.0.1:9000`, visit the SSH page, add `127.0.0.1:2222`, confirm the fingerprint, and watch the row reach `connected`. The CLI path opens no browser, so verifying the web experience is not optional here — a card that falls through to a raw-output branch is the failure mode `CLAUDE.md` records for the enrolment UI.

- [ ] **Step 4: Commit**

```bash
git add internal/web/frontend/src internal/web/frontend/dist
git commit -m "feat(web): SSH managed-forward page"
```

---

### Task 19: Documentation

**Files:**
- Modify: `CLAUDE.md`, `docs/cli.md`, `docs/configuration/config-reference.md`
- Create: `docs/guide/ssh-forwards.md`

- [ ] **Step 1: Write the docs**

`docs/guide/ssh-forwards.md` covers: what the feature replaces and why, the two preconditions, `ssh add`/`list`/`remove`, the `ssh.yaml` shape and its per-OS location, the host-key model (CA list, pinning at `add`, no runtime TOFU), and the Windows caveat that `dotvault ssh` needs `web.enabled` until the API named pipe exists.

Update `docs/configuration/config-reference.md` where it documents the manual `RemoteForward` wiring: managed forwards are now the recommended path, with the manual `ssh -R` retained for hosts that do not run a dotvault daemon.

Update `CLAUDE.md`: add `internal/sshfwd/` to the architecture tree, the `ssh:` system section to Config Sections, the new CLI subcommands, and the new API routes.

Prose is flowing — one long line per paragraph, no manual wrapping (repo convention).

- [ ] **Step 2: Verify**

Run: `make test && make build && gofmt -l .`
Expected: PASS, PASS, empty

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/
git commit -m "docs: managed SSH forwards guide and config reference"
```

---

### Task 20: Pre-push review

- [ ] **Step 1: Run the five-persona review**

Invoke `/precommit-review`. This is non-negotiable for code-changing pushes on this repo (`CLAUDE.md`).

- [ ] **Step 2: Triage**

`blocker`/`major` → fix, or commit a message naming the persona and the deliberate trade-off. `minor`/`nit` → fix when cheap.

- [ ] **Step 3: Push**

```bash
git push -u origin feat/managed-ssh-forwards
```

---

## Self-Review

**Spec coverage:** Preconditions → 15. System `ssh:` section → 3. `ssh.yaml` + `~` → 2, 7. Service layer → 11, 14. Transactional add → 12. Host-key trust → 4, 11. Identity → 5. Lifecycle, backoff, keepalive, forwarding, concurrency → 6, 9, 10. Runtime state → 8, 13. CLI → 14. Web UI → 13, 18. Errors → 8, 9. Observability → 16. Testing → every task, plus 17. Delivery sequence → tasks map 1:1 onto the spec's thirteen steps, expanded where a step carried two testable deliverables.

**Known gaps, stated rather than hidden:**

- Tasks 13, 14, 16 and 18 give test *names* and behaviours rather than full test bodies, because each must copy a package-local helper (the web server-construction helper, `cmd/dotvault`'s `paths.SetSystemConfigPathForTest` idiom, the observability instrument-registration pattern, the SPA component idiom) whose exact shape must be read from the repo first. Each such step names the file to read. The earlier tasks — where the design risk actually lives — carry complete, runnable tests.
- Task 10 describes `ManagedRemote`'s run loop as pseudocode plus an explicit field list rather than a full listing. It is the one place where the code is long and mechanical while the *contract* (the state transitions, the backoff floors, `WaitForClient`'s bound) is what matters, and that contract is fully specified in Tasks 6, 8 and 9.
- Task 4 flags that `knownhosts.NewFromReader` may not exist in the pinned `x/crypto` and gives two fallbacks. Verify before writing.
- `Deps.Policy` is consumed in Tasks 10 and 12 and produced in Task 15; `Deps.TargetName` is set in 15 and read in 10.
