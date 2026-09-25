# Peer Socket Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop two workstations racing over `~/.ssh/dotvault.sock` on a shared remote by naming each forward after its workstation, letting borrowers glob a pool of sockets, and migrating old-default forwards automatically.

**Architecture:** A new `internal/peer` package owns the peer-socket transport (moved out of `internal/auth`) and a `Pool` that resolves literal/glob patterns, orders members by last-seen, evicts on transport failure, and readmits via inotify/inode-change/probe-window. `vault.token_socket` becomes a string-or-list `SocketList`. The forwarder's default `remote_socket` becomes `~/.ssh/dotvault.{{HOSTNAME}}.sock`, expanded at connect time. A daemon-only migration PATCHes a peer's old-default forward to the template through the peer's own API.

**Tech Stack:** Go 1.2x, `gopkg.in/yaml.v3`, `golang.org/x/sys/unix` (inotify), `net/http` over Unix sockets, `go.opentelemetry.io/otel/metric`.

**Spec:** `docs/superpowers/specs/2026-09-24-peer-socket-pool-design.md`

## Global Constraints

- `CGO_ENABLED=0`; every new file must build on linux/darwin/windows (`make build-all`). inotify code stays under `//go:build linux`.
- Commit messages: subject ≤ ~50 chars, body in flowing prose (no hard wraps inside a paragraph).
- Use `git add <path>` for exact files — never `git add -A`.
- Never log secret material. Socket *paths* and *patterns* are fine to log; tokens and clipboard text are not.
- Default borrow patterns when `token_socket` is absent: `~/.ssh/dotvault.sock`, `~/.ssh/dotvault.*.sock` (in that order).
- New forwarder default: `~/.ssh/dotvault.{{HOSTNAME}}.sock`. Only the exact token `{{HOSTNAME}}` is a template; any other `{{`/`}}` is rejected.
- Eviction re-probe window: `EvictProbeInterval = 5 * time.Minute`.
- Migration gate: peer `version` ≥ `0.34.0` (`remoteSocketTemplateSince`); empty/unparseable is treated as new.
- Run `gofmt -l .` and `go vet ./...` before every commit; `go test ./...` must pass.
- Every pre-1.0 compatibility site carries a `// TODO(pre-1.0, #<issue>)` comment referencing the sunset issue created in Task 11.

---

## File structure

**Create**
- `internal/peer/transport.go` — `Client`, `FetchToken`, `PostForm`, `ErrPeerUnreachable`, `StatusError` (moved from `internal/auth/socket.go` + `peerpost.go`).
- `internal/peer/transport_test.go` — moved tests.
- `internal/peer/pool.go` — `Pool`, `Member`, `Borrower`, `NewPool`, `Resolve`, `Borrow`, `Broadcast`, `Watch`, `Status`, `ErrNoPeers`, `EvictProbeInterval`.
- `internal/peer/pool_test.go`.
- `internal/tokenwatch/match_linux.go` / `match_other.go` — `NewMatch`.
- `internal/tokenwatch/match_linux_test.go`.
- `cmd/dotvault/peermigrate.go` — old-default forward migration.
- `cmd/dotvault/peermigrate_test.go`.
- `docs/superpowers/plans/…` (this file).

**Modify**
- `internal/config/config.go` — `SocketList` type + `TokenSockets` field + validation.
- `internal/config/api.go` — `TokenBorrowSockets`, new `PeerActionSockets`, `DefaultPeerSocketPatterns`.
- `internal/config/config_test.go`, `internal/config/api_test.go`.
- `internal/config/registry_windows.go` — `TokenSockets` REG_MULTI_SZ + REG_SZ fallback.
- `internal/regfile/regfile.go`, `internal/regfile/parse.go`, tests.
- `internal/auth/auth.go`, `internal/auth/lifecycle.go` (+ tests) — `Borrower` seam; delete `socket.go`, `peerpost.go`, their tests.
- `internal/observability/observability.go` — `RecordPeerPool`.
- `cmd/dotvault/apisocket.go`, `main.go`, `browse.go`, `notify.go`, `clipboard.go`, `ssh.go` (+ tests).
- `client/config.go`, `client/client.go`, `client/remote.go` (+ tests), `client/README.md`.
- `internal/web/api.go`, `internal/web/server.go` — `peer_sockets` status block.
- `internal/sshfwd/config.go`, `home.go` (+ tests) — `{{HOSTNAME}}`.
- `cmd/dotvault/ssh_add.go`, `ssh_edit.go` — help text.
- `docs/configuration/config-reference.md`, `docs/guide/ssh-forwards.md`, `CLAUDE.md`.

---

### Task 1: `SocketList` config type, validation, defaults

**Files:**
- Modify: `internal/config/config.go:460-475` (the `TokenSocket` field), `internal/config/config.go:1242` (validate chain)
- Modify: `internal/config/api.go:52-80`
- Test: `internal/config/socketlist_test.go` (new), `internal/config/api_test.go`

**Interfaces:**
- Produces: `type SocketList []string` with `UnmarshalYAML(*yaml.Node) error`; `Config.Vault.TokenSockets SocketList` (yaml `token_socket`); `func ValidateSocketPattern(p string) error`; `var DefaultPeerSocketPatterns = []string{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}`; `func (c *Config) PeerActionSockets() []string`; `func (c *Config) TokenBorrowSockets() []string` (unchanged signature, new semantics).

- [ ] **Step 1: Write the failing tests**

Create `internal/config/socketlist_test.go`:

```go
package config

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSocketListUnmarshalScalar(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: ~/.ssh/dotvault.sock\n"), &v); err != nil {
		t.Fatal(err)
	}
	if want := SocketList{"~/.ssh/dotvault.sock"}; !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

func TestSocketListUnmarshalSequence(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	in := "token_socket:\n  - ~/.ssh/dotvault.sock\n  - ~/.ssh/dotvault.*.sock\n"
	if err := yaml.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	if want := SocketList{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}; !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

// An empty scalar and an empty sequence both mean "explicitly disabled":
// non-nil and empty, distinguishable from an absent key (nil).
func TestSocketListUnmarshalEmptyForms(t *testing.T) {
	for _, in := range []string{"token_socket: \"\"\n", "token_socket: []\n"} {
		var v struct {
			S SocketList `yaml:"token_socket"`
		}
		if err := yaml.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if v.S == nil || len(v.S) != 0 {
			t.Errorf("%q: got %#v, want non-nil empty", in, v.S)
		}
	}
	var absent struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("other: 1\n"), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.S != nil {
		t.Errorf("absent key: got %#v, want nil", absent.S)
	}
}

func TestSocketListUnmarshalRejectsMapping(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: {a: b}\n"), &v); err == nil {
		t.Fatal("expected error for mapping")
	}
}

func TestValidateSocketPattern(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"~/.ssh/dotvault.sock", ""},
		{"~/.ssh/dotvault.*.sock", ""},
		{"/run/user/1000/dotvault/api.sock", ""},
		{"/tmp/dotvault-?.sock", ""},
		{"", "must not be empty"},
		{"relative/dotvault.sock", "must be an absolute path"},
		{"~user/dotvault.sock", "must be an absolute path"},
		{"~/*/dotvault.sock", "only in the final path segment"},
		{"/tmp/*/dotvault.sock", "only in the final path segment"},
		{"/tmp/dotvault\x00.sock", "NUL"},
	}
	for _, c := range cases {
		err := ValidateSocketPattern(c.in)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%q: unexpected error %v", c.in, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: got %v, want error containing %q", c.in, err, c.wantErr)
		}
	}
}

func TestValidateRejectsBadTokenSocketEntry(t *testing.T) {
	cfg := minimalValidConfig()
	cfg.Vault.TokenSockets = SocketList{"relative.sock"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "vault.token_socket") {
		t.Fatalf("got %v, want vault.token_socket validation error", err)
	}
}
```

Check whether `minimalValidConfig()` exists in `internal/config/config_test.go` (`grep -n "func minimalValidConfig" internal/config/*_test.go`). If not, add to `socketlist_test.go`:

```go
func minimalValidConfig() *Config {
	return &Config{
		Vault: VaultConfig{Address: "http://127.0.0.1:8200", AuthMethod: "token"},
		Rules: []Rule{{Name: "r", VaultKey: "k", Target: Target{Path: "/tmp/x", Format: "text"}}},
	}
}
```

(Adjust field names to match the real `Rule`/`Target` structs — read `internal/config/config.go` around the `Rule` definition first.)

Append to `internal/config/api_test.go`:

```go
func TestTokenBorrowSocketsDefaultsPeerPatterns(t *testing.T) {
	cfg := &Config{}
	got := cfg.TokenBorrowSockets()
	if !reflect.DeepEqual(got, DefaultPeerSocketPatterns) {
		t.Errorf("absent token_socket: got %v, want defaults %v", got, DefaultPeerSocketPatterns)
	}
}

func TestTokenBorrowSocketsExplicitEmptyDisables(t *testing.T) {
	cfg := &Config{Vault: VaultConfig{TokenSockets: SocketList{}}}
	if got := cfg.TokenBorrowSockets(); len(got) != 0 {
		t.Errorf("explicit empty list: got %v, want none", got)
	}
}

func TestTokenBorrowSocketsLocalFirstThenPeers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no local API socket on windows")
	}
	cfg := &Config{
		API:   APIConfig{Enabled: true, Unix: APIUnixConfig{Path: "/run/dotvault/api.sock"}},
		Vault: VaultConfig{TokenSockets: SocketList{"~/.ssh/a.sock", "~/.ssh/b.*.sock"}},
	}
	want := []string{"/run/dotvault/api.sock", "~/.ssh/a.sock", "~/.ssh/b.*.sock"}
	if got := cfg.TokenBorrowSockets(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPeerActionSocketsExcludesLocalAPISocket(t *testing.T) {
	cfg := &Config{
		API:   APIConfig{Enabled: true, Unix: APIUnixConfig{Path: "/run/dotvault/api.sock"}},
		Vault: VaultConfig{TokenSockets: SocketList{"~/.ssh/a.sock"}},
	}
	if got := cfg.PeerActionSockets(); !reflect.DeepEqual(got, []string{"~/.ssh/a.sock"}) {
		t.Errorf("got %v, want peers only", got)
	}
	if got := (&Config{}).PeerActionSockets(); !reflect.DeepEqual(got, DefaultPeerSocketPatterns) {
		t.Errorf("absent: got %v, want defaults", got)
	}
}
```

Add `"runtime"` to that test file's imports if missing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'SocketList|ValidateSocketPattern|TokenBorrowSockets|PeerActionSockets|BadTokenSocket' -v`
Expected: compile errors (`SocketList`, `TokenSockets`, `ValidateSocketPattern`, `PeerActionSockets`, `DefaultPeerSocketPatterns` undefined).

- [ ] **Step 3: Implement `SocketList` and validation**

Create `internal/config/socketlist.go`:

```go
package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// SocketList is the value of vault.token_socket: an ordered list of peer
// dotvault socket patterns. It decodes from either a YAML scalar (the pre-list
// spelling, one path) or a sequence, so an existing config keeps loading.
//
// The nil/empty distinction is load-bearing: a nil list means the key was
// absent and the defaults apply (see DefaultPeerSocketPatterns); a non-nil
// empty list — `token_socket: []` or `token_socket: ""` — means the operator
// explicitly disabled peer sockets.
//
// TODO(pre-1.0, #ISSUE): drop the scalar form.
type SocketList []string

// UnmarshalYAML accepts a scalar or a sequence of scalars.
func (s *SocketList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v string
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v == "" {
			*s = SocketList{}
			return nil
		}
		*s = SocketList{v}
		return nil
	case yaml.SequenceNode:
		var v []string
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v == nil {
			v = []string{}
		}
		*s = SocketList(v)
		return nil
	default:
		return fmt.Errorf("token_socket: expected a string or a list of strings, got %s", nodeKindName(n.Kind))
	}
}

func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "an unsupported node"
	}
}

// ValidateSocketPattern checks one vault.token_socket entry. A pattern must be
// absolute or ~/-relative (the api.unix.path rule — a relative path resolves
// against the working directory and two processes would disagree about it),
// and glob metacharacters are permitted only in the final path segment. That
// restriction gives every pattern exactly one parent directory to watch and
// keeps a pattern from walking the filesystem.
func ValidateSocketPattern(p string) error {
	switch {
	case p == "":
		return errors.New("must not be empty")
	case strings.ContainsRune(p, 0):
		return errors.New("must not contain a NUL byte")
	case strings.HasPrefix(p, "~/"), p == "~":
		// ~-relative; expanded at resolve time.
	case strings.HasPrefix(p, "~"):
		return errors.New("must be an absolute path (or ~/-relative); ~user/ is not supported")
	case !filepath.IsAbs(p):
		return errors.New("must be an absolute path (or ~/-relative)")
	}
	dir := p[:strings.LastIndex(p, "/")+1]
	if strings.ContainsAny(dir, "*?[") {
		return errors.New("glob metacharacters are allowed only in the final path segment")
	}
	return nil
}

// DefaultPeerSocketPatterns is the vault.token_socket value applied when the
// key is absent: the pre-list default path, so a workstation that has not
// been upgraded keeps working, plus the per-hostname pattern every upgraded
// workstation's managed forward binds (see sshfwd.DefaultRemoteSocket).
//
// TODO(pre-1.0, #ISSUE): drop ~/.ssh/dotvault.sock from the defaults.
var DefaultPeerSocketPatterns = []string{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}

// peerSocketPatterns returns the configured peer patterns with the default
// applied for an absent key. Defaulting happens here rather than at load so
// an exported config round-trips "absent" as absent.
func (c *Config) peerSocketPatterns() []string {
	if c.Vault.TokenSockets == nil {
		return append([]string(nil), DefaultPeerSocketPatterns...)
	}
	return append([]string(nil), c.Vault.TokenSockets...)
}

// PeerActionSockets returns the peer socket patterns the peer actions
// (browse / notify / clipboard) fan out to. Deliberately without the local
// API socket: those actions must reach the workstation where a human is
// looking, and posting them to the local daemon would open a browser on the
// headless host nobody is sitting at.
func (c *Config) PeerActionSockets() []string {
	return c.peerSocketPatterns()
}

// validateTokenSockets checks every vault.token_socket entry.
func (c *Config) validateTokenSockets() error {
	for i, p := range c.Vault.TokenSockets {
		if err := ValidateSocketPattern(p); err != nil {
			return fmt.Errorf("vault.token_socket[%d] %q: %w", i, p, err)
		}
	}
	return nil
}
```

In `internal/config/config.go`, replace the `TokenSocket string \`yaml:"token_socket"\`` field (keep and reword its doc comment) with:

```go
	// TokenSockets lists peer dotvault web-API Unix socket patterns to borrow
	// a live Vault token from — `GET http://localhost/api/v1/token` over the
	// socket — before falling back to this host's own authentication, and to
	// fan the peer actions (browse/notify/clipboard) out to. Each entry is a
	// literal path or a glob whose metacharacters sit in the final segment
	// (`~/.ssh/dotvault.*.sock`), so one workstation per socket can forward
	// to this host without the last forward to connect stealing a shared
	// path. Accepts a single string for compatibility. A nil (absent) value
	// applies DefaultPeerSocketPatterns; an explicit empty list disables
	// peer sockets. Borrowing is best-effort and never fatal.
	TokenSockets SocketList `yaml:"token_socket"`
```

In `validate()` right after the `validateAPI()` call (line ~1242), add:

```go
	// Peer socket patterns. Validated unconditionally, like the API socket:
	// a relative pattern or a directory glob is a mistake worth naming.
	if err := c.validateTokenSockets(); err != nil {
		return err
	}
```

In `internal/config/api.go`, replace the body of `TokenBorrowSockets` (keep the doc comment, append the sentence "Peer entries are patterns — literal paths or final-segment globs — resolved by internal/peer.Pool; the default set applies when vault.token_socket is absent."):

```go
func (c *Config) TokenBorrowSockets() []string {
	var out []string
	if p := c.apiSocketCandidate(); p != "" {
		out = append(out, p)
	}
	return append(out, c.peerSocketPatterns()...)
}
```

- [ ] **Step 4: Fix the compile fallout in `internal/config` only**

`registry_windows.go` still references `cfg.Vault.TokenSocket` (lines 254, 372, 570-572). Change:
- field `VaultTokenSocket string` → `VaultTokenSockets []string`
- line 372: `layer.VaultTokenSockets = readRegMultiString(vk, "TokenSockets")` followed by
  ```go
  		// TODO(pre-1.0, #ISSUE): drop the REG_SZ fallback.
  		if layer.VaultTokenSockets == nil {
  			if legacy, ok := readRegString(vk, "TokenSocket"); ok && legacy != "" {
  				layer.VaultTokenSockets = []string{legacy}
  			}
  		}
  ```
  (check `readRegString`'s return shape — it returns `(string, bool)`; adapt if not.)
- lines 570-572: `if layer.VaultTokenSockets != nil { cfg.Vault.TokenSockets = SocketList(layer.VaultTokenSockets) }`

Add to `internal/config/registry_windows_test.go` (it is `//go:build windows`; find the file's existing helper that seeds a temporary policy key — `grep -n "func withTestRegistry\|func setupRegistry\|registry.CreateKey" internal/config/registry_windows_test.go` — and use it):

```go
func TestRegistryTokenSocketsMultiSZ(t *testing.T) {
	k := newTestPolicyKey(t) // the file's helper: creates and cleans up a scratch policy root
	vk, _, err := registry.CreateKey(k, "Vault", registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer vk.Close()
	_ = vk.SetStringValue("Address", "http://127.0.0.1:8200")
	_ = vk.SetStringsValue("TokenSockets", []string{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"})

	cfg := loadFromTestRegistry(t) // the file's helper that runs the registry loader against the scratch root
	want := SocketList{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}
	if !reflect.DeepEqual(cfg.Vault.TokenSockets, want) {
		t.Errorf("got %v, want %v", cfg.Vault.TokenSockets, want)
	}
}

// TODO(pre-1.0, #ISSUE): delete with the REG_SZ fallback.
func TestRegistryLegacyTokenSocketREGSZ(t *testing.T) {
	k := newTestPolicyKey(t)
	vk, _, err := registry.CreateKey(k, "Vault", registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer vk.Close()
	_ = vk.SetStringValue("Address", "http://127.0.0.1:8200")
	_ = vk.SetStringValue("TokenSocket", "~/.ssh/dotvault.sock")

	cfg := loadFromTestRegistry(t)
	if want := (SocketList{"~/.ssh/dotvault.sock"}); !reflect.DeepEqual(cfg.Vault.TokenSockets, want) {
		t.Errorf("got %v, want %v", cfg.Vault.TokenSockets, want)
	}
}
```

If the file has no such helpers, model them on how its existing tests seed values (read the first test in the file) rather than inventing a new fixture style.

Run: `go build ./internal/config/ && GOOS=windows go vet ./internal/config/`
Expected: both succeed (the Windows tests compile; they run in the Windows CI job). Other packages will not compile yet — that's Tasks 2–7.

- [ ] **Step 5: Run the config tests**

Run: `go test ./internal/config/`
Expected: PASS. Fix any existing test that used `TokenSocket:` by changing it to `TokenSockets: SocketList{...}`.

- [ ] **Step 6: Commit**

```bash
gofmt -l internal/config && go vet ./internal/config/
git add internal/config/socketlist.go internal/config/socketlist_test.go internal/config/config.go internal/config/api.go internal/config/api_test.go internal/config/registry_windows.go internal/config/registry_windows_test.go
git commit -m "feat(config): token_socket accepts a list of patterns"
```

Body: "vault.token_socket now decodes from a scalar or a sequence into a SocketList, with globs permitted in the final path segment only. An absent key applies the default pair of patterns (the old single path plus the per-hostname glob); an explicit empty list disables peer sockets. The Windows loader reads the new TokenSockets REG_MULTI_SZ and falls back to the old TokenSocket REG_SZ."

---

### Task 2: regfile render/parse for `TokenSockets`

**Files:**
- Modify: `internal/regfile/regfile.go:112`, `internal/regfile/parse.go:661`
- Test: `internal/regfile/regfile_test.go`, `internal/regfile/parse_test.go`

**Interfaces:**
- Consumes: `config.SocketList`, `config.VaultConfig.TokenSockets`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/regfile/regfile_test.go` (use the file's existing round-trip helper — find it with `grep -n "func roundTrip\|func renderAndParse" internal/regfile/*_test.go`; if the helper is named differently, use that name):

```go
func TestTokenSocketsRoundTripsAsMultiSZ(t *testing.T) {
	cfg := minimalConfig() // whatever helper the file already uses to build a valid config
	cfg.Vault.TokenSockets = config.SocketList{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}

	var buf bytes.Buffer
	if err := Render(&buf, cfg, false); err != nil { // match the real Render signature
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"TokenSockets"=hex(7):`) {
		t.Errorf("expected a REG_MULTI_SZ TokenSockets value, got:\n%s", out)
	}
	if strings.Contains(out, `"TokenSocket"=`) {
		t.Errorf("legacy TokenSocket REG_SZ must not be emitted:\n%s", out)
	}

	back, err := Parse(strings.NewReader(out)) // match the real Parse signature
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Vault.TokenSockets, cfg.Vault.TokenSockets) {
		t.Errorf("got %v, want %v", back.Vault.TokenSockets, cfg.Vault.TokenSockets)
	}
}

// An explicit empty list is emitted (as an empty REG_MULTI_SZ) so re-import
// clears a stale value; an absent list emits nothing.
func TestTokenSocketsEmptyVersusAbsent(t *testing.T) {
	cfg := minimalConfig()
	cfg.Vault.TokenSockets = config.SocketList{}
	var buf bytes.Buffer
	if err := Render(&buf, cfg, false); err != nil {
		t.Fatal(err)
	}
	back, err := Parse(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	if back.Vault.TokenSockets == nil || len(back.Vault.TokenSockets) != 0 {
		t.Errorf("explicit empty: got %#v, want non-nil empty", back.Vault.TokenSockets)
	}

	cfg.Vault.TokenSockets = nil
	buf.Reset()
	if err := Render(&buf, cfg, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "TokenSockets") {
		t.Errorf("absent list must not be emitted:\n%s", buf.String())
	}
}
```

Append to `internal/regfile/parse_test.go`:

```go
// TODO(pre-1.0, #ISSUE): delete with the REG_SZ fallback.
func TestParseLegacyTokenSocketREGSZ(t *testing.T) {
	in := "Windows Registry Editor Version 5.00\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault]\r\n\r\n" +
		"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\goodtune\\dotvault\\Vault]\r\n" +
		"\"Address\"=\"http://127.0.0.1:8200\"\r\n" +
		"\"AuthMethod\"=\"token\"\r\n" +
		"\"TokenSocket\"=\"~/.ssh/dotvault.sock\"\r\n\r\n" +
		// plus whatever minimal Rules block the parser needs to validate — copy
		// from an existing parse test in this file.
		""
	cfg, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if want := config.SocketList{"~/.ssh/dotvault.sock"}; !reflect.DeepEqual(cfg.Vault.TokenSockets, want) {
		t.Errorf("got %v, want %v", cfg.Vault.TokenSockets, want)
	}
}
```

Adapt helper names and the minimal `.reg` body to the conventions already in those test files — read them first.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/regfile/ -run 'TokenSocket' -v`
Expected: compile failure on `TokenSocket` / FAIL.

- [ ] **Step 3: Implement**

`internal/regfile/regfile.go` line 112 — replace `e.writeString("TokenSocket", v.TokenSocket)` with:

```go
	// Emit TokenSockets whenever non-nil so an explicit empty list round-trips
	// as an empty REG_MULTI_SZ, matching Policies; nil (absent) emits nothing.
	if v.TokenSockets != nil {
		e.writeMultiString("TokenSockets", v.TokenSockets)
	}
```

`internal/regfile/parse.go` line 661 — replace the `TokenSocket` apply func with:

```go
		func() error {
			v, ok, err := getMultiString(vaultKey, "TokenSockets")
			if err != nil {
				return err
			}
			if ok {
				cfg.Vault.TokenSockets = config.SocketList(v)
				return nil
			}
			// TODO(pre-1.0, #ISSUE): drop the REG_SZ fallback.
			var legacy string
			if err := apply(&legacy, vaultKey, "TokenSocket"); err != nil {
				return err
			}
			if legacy != "" {
				cfg.Vault.TokenSockets = config.SocketList{legacy}
			}
			return nil
		},
```

Also update `internal/regfile/yaml.go` if it names `TokenSocket` (`grep -n TokenSocket internal/regfile/yaml.go`); the YAML emitter should marshal the `SocketList` as a sequence naturally — verify with the round-trip test.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/regfile/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/regfile/regfile.go internal/regfile/parse.go internal/regfile/regfile_test.go internal/regfile/parse_test.go
git commit -m "feat(regfile): round-trip TokenSockets as REG_MULTI_SZ"
```

---

### Task 3: `internal/peer` transport (move from `internal/auth`)

**Files:**
- Create: `internal/peer/transport.go`, `internal/peer/transport_test.go`
- Delete: `internal/auth/socket.go`, `internal/auth/peerpost.go`, `internal/auth/socket_test.go`, `internal/auth/peerpost_test.go` (if present)
- Modify: callers — `internal/auth/auth.go:103`, `internal/auth/lifecycle.go:544`, `cmd/dotvault/ssh.go:94`, `cmd/dotvault/browse.go:93`, `cmd/dotvault/notify.go:112`, `cmd/dotvault/clipboard.go:138`, `client/client.go:272`, `client/remote.go:104`

**Interfaces:**
- Produces (package `peer`):
  - `func Client(socketPath string) (*http.Client, string, error)`
  - `func FetchToken(ctx context.Context, socketPath string) (string, error)`
  - `func PostForm(ctx context.Context, socketPath, apiPath string, form url.Values) error`
  - `var ErrPeerUnreachable = errors.New("peer socket unreachable")`
  - `type StatusError struct{ Status int; Message string }` with `Error()`.
  - constants `FetchTimeout = 3 * time.Second`, `PostTimeout = 10 * time.Second` (exported so the pool reuses them).
- The old multi-socket `FetchTokenFromSockets` is **not** moved; the pool replaces it in Task 5. Until Task 6 rewires auth, keep a temporary exported shim in a new file `internal/auth/peer_shim.go` (exported because `cmd/dotvault/main.go` calls it too until Task 7):

```go
// BorrowFromSockets is a transitional shim, deleted once callers borrow
// through peer.Borrower (Task 6/7).
func BorrowFromSockets(ctx context.Context, socketPaths []string) (string, string) {
	for _, p := range socketPaths {
		if p == "" {
			continue
		}
		if token, _ := peer.FetchToken(ctx, p); token != "" {
			return token, p
		}
	}
	return "", ""
}
```

- [ ] **Step 1: Move the files**

```bash
mkdir -p internal/peer
git mv internal/auth/socket.go internal/peer/transport.go
git mv internal/auth/socket_test.go internal/peer/transport_test.go
```

Then fold `internal/auth/peerpost.go` into `internal/peer/transport.go` (copy its contents below the fetch code; `git rm internal/auth/peerpost.go`). If `internal/auth/peerpost_test.go` exists, append its tests to `transport_test.go` and `git rm` it.

- [ ] **Step 2: Rename within the package**

In `internal/peer/transport.go`:
- `package auth` → `package peer`
- `PeerSocketClient` → `Client`; `FetchTokenFromSocket` → `FetchToken`; `PostFormToPeer` → `PostForm`; `PeerStatusError` → `StatusError`; `socketFetchTimeout` → `FetchTimeout`; `peerPostTimeout` → `PostTimeout`.
- Delete the `FetchTokenFromSockets` function and its doc paragraph (the pool owns ordering now).
- Rewrite the package doc at the top:

```go
// Package peer speaks to another dotvault daemon's web API over a Unix-domain
// socket: the token borrow (GET /api/v1/token) and the peer actions
// (POST /api/v1/remote/{browse,notify,clipboard}). It owns the transport
// (Client, FetchToken, PostForm) and the Pool that resolves a list of socket
// patterns into live members, orders them, and evicts the unreachable.
//
// It sits below internal/auth: auth borrows through the Borrower interface
// and never sees a path or a glob.
package peer
```

- Update the `PostForm` doc comment's "It lives in internal/auth for cohesion…" paragraph to: "It lives here with Client and FetchToken because all three speak the peer's web API over one unix transport."

In `internal/peer/transport_test.go`: `package auth` → `package peer`, rename call sites, drop the `internal/vault` import if now unused, and delete tests of `FetchTokenFromSockets` (the pool tests cover ordering).

- [ ] **Step 3: Update the callers**

- `internal/auth/peer_shim.go`: create it with the shim above (imports `context` and `internal/peer`).
- `internal/auth/auth.go:103`: `FetchTokenFromSockets(ctx, m.TokenSockets)` → `BorrowFromSockets(ctx, m.TokenSockets)`.
- `internal/auth/lifecycle.go:544`: `FetchTokenFromSockets` → `BorrowFromSockets`.
- `cmd/dotvault/ssh.go:94`: `auth.PeerSocketClient(sock)` → `peer.Client(sock)`.
- `cmd/dotvault/browse.go:93`, `notify.go:112`, `clipboard.go:138`: `auth.PostFormToPeer` → `peer.PostForm`.
- `client/client.go:272`: `auth.FetchTokenFromSocket` → `peer.FetchToken`.
- `client/remote.go:104-108`: `auth.PostFormToPeer` → `peer.PostForm`; `*auth.PeerStatusError` → `*peer.StatusError`.
- `cmd/dotvault/main.go:1001,1754,3070`: `auth.FetchTokenFromSockets` → `auth.BorrowFromSockets` (replaced by the pool in Task 7).
- Fix each file's imports (`goimports -w` if available, else by hand).
- Any test files referencing the old names (`cmd/dotvault/browse_test.go`, `client/remote_test.go`, `client/client_test.go`): rename accordingly.

- [ ] **Step 4: Build and test everything**

Run: `go build ./... && go vet ./... && go test ./internal/peer/ ./internal/auth/ ./client/ ./cmd/...`
Expected: all PASS. (`cmd/dotvault` tests referencing `TokenSocket:` in config literals: change to `TokenSockets: config.SocketList{...}` — `apisocket_test.go:19`, `browse_test.go`, etc.)

- [ ] **Step 5: Commit**

```bash
git add internal/peer internal/auth cmd/dotvault client
git commit -m "refactor(peer): promote the peer-socket transport"
```

Body: "Move PeerSocketClient, FetchTokenFromSocket and PostFormToPeer out of internal/auth into a new internal/peer package, as the note on PostFormToPeer said a further peer-action surface should trigger. Names lose their Peer prefix inside the package. A transitional auth.BorrowFromSockets shim keeps the multi-socket callers compiling until the pool replaces it."

---

### Task 4: `tokenwatch.NewMatch` (directory watch with a name predicate)

**Files:**
- Create: `internal/tokenwatch/match_linux.go`, `internal/tokenwatch/match_other.go`, `internal/tokenwatch/match_linux_test.go`
- Modify: `internal/tokenwatch/tokenwatch_linux.go` (share the event decoding)

**Interfaces:**
- Produces: `func NewMatch(dir string, match func(name string) bool, onChange func(name string)) (*Watcher, error)` on every platform; on Linux the Watcher's `Run` delivers each matching event name; on other platforms `Run` blocks until ctx is done.

- [ ] **Step 1: Write the failing test**

Create `internal/tokenwatch/match_linux_test.go`:

```go
//go:build linux

package tokenwatch

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewMatchReportsMatchingNames(t *testing.T) {
	dir := t.TempDir()
	seen := make(chan string, 8)
	w, err := NewMatch(dir, func(name string) bool {
		return strings.HasPrefix(name, "dotvault.") && strings.HasSuffix(name, ".sock")
	}, func(name string) { seen <- name })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { defer w.Close(); _ = w.Run(ctx) }()

	// A non-matching entry must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A matching socket creation must be reported by name.
	ln, err := net.Listen("unix", filepath.Join(dir, "dotvault.laptop.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	select {
	case got := <-seen:
		if got != "dotvault.laptop.sock" {
			t.Fatalf("got %q, want dotvault.laptop.sock", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event for matching socket")
	}
	select {
	case got := <-seen:
		t.Fatalf("unexpected extra event %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/tokenwatch/ -run TestNewMatch -v`
Expected: compile error, `NewMatch` undefined.

- [ ] **Step 3: Implement**

Refactor `internal/tokenwatch/tokenwatch_linux.go` so `Watcher` carries a predicate and a name-aware callback:

```go
type Watcher struct {
	fd       int
	match    func(name string) bool
	onChange func(name string)
}
```

`New(path, onChange func())` becomes:

```go
func New(path string, onChange func()) (*Watcher, error) {
	name := filepath.Base(path)
	return NewMatch(filepath.Dir(path), func(n string) bool { return n == name }, func(string) { onChange() })
}
```

Create `internal/tokenwatch/match_linux.go`:

```go
//go:build linux

package tokenwatch

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
)

// NewMatch registers an inotify watch on dir and returns a Watcher whose Run
// calls onChange(name) for every create / close-write / moved-to event whose
// entry name satisfies match. It generalises New — which watches one literal
// name — for the peer socket pool, where one directory holds many sockets
// selected by a glob. Registration is synchronous, as for New.
func NewMatch(dir string, match func(name string) bool, onChange func(name string)) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	if _, err := unix.InotifyAddWatch(fd, dir, watchMask); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Watcher{fd: fd, match: match, onChange: onChange}, nil
}

// matchedNames returns the entry names in buf, in order, that satisfy match.
// Duplicates are preserved: a burst of events for one socket is harmless to
// the callers (both are idempotent) and collapsing them here would hide the
// count from a test.
func matchedNames(buf []byte, match func(string) bool) []string {
	var out []string
	offset := 0
	for offset+unix.SizeofInotifyEvent <= len(buf) {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(raw.Len)
		start := offset + unix.SizeofInotifyEvent
		end := start + nameLen
		if nameLen > 0 && end <= len(buf) {
			evName := buf[start:end]
			if i := bytes.IndexByte(evName, 0); i >= 0 {
				evName = evName[:i]
			}
			if n := string(evName); match(n) {
				out = append(out, n)
			}
		}
		offset = end
	}
	return out
}
```

In `tokenwatch_linux.go`'s `Run`, replace `if nameMatched(buf[:nread], w.name) { w.onChange() }` with:

```go
		for _, name := range matchedNames(buf[:nread], w.match) {
			w.onChange(name)
		}
```

Delete `nameMatched` (its existing tests, if any in `tokenwatch_linux_test.go`, should be rewritten against `matchedNames` with a literal-equality predicate — keep the same event-buffer fixtures).

Create `internal/tokenwatch/match_other.go`:

```go
//go:build !linux

package tokenwatch

// NewMatch returns a no-op Watcher on platforms without inotify; Run blocks
// until ctx is cancelled and onChange is never invoked. Callers re-resolve
// on demand instead — see internal/peer.Pool.
func NewMatch(dir string, match func(name string) bool, onChange func(name string)) (*Watcher, error) {
	return &Watcher{}, nil
}
```

and drop the `onChange` field from the non-Linux `Watcher` if now unused (`New` on that platform just returns `&Watcher{}`).

- [ ] **Step 4: Run tests on Linux and cross-build**

Run: `go test ./internal/tokenwatch/ -v && GOOS=darwin go build ./internal/tokenwatch/ && GOOS=windows go build ./internal/tokenwatch/`
Expected: PASS; both cross-builds succeed. If the host is macOS, run the Linux test via `GOOS=linux go vet ./internal/tokenwatch/` for compile coverage and note that the behaviour test runs in CI.

- [ ] **Step 5: Commit**

```bash
git add internal/tokenwatch
git commit -m "feat(tokenwatch): NewMatch watches a directory by predicate"
```

---

### Task 5: `peer.Pool`

**Files:**
- Create: `internal/peer/pool.go`, `internal/peer/pool_test.go`
- Modify: `internal/observability/observability.go` (counter)

**Interfaces:**
- Produces:

```go
type Borrower interface {
	Borrow(ctx context.Context) (token, source string)
}

type Member struct {
	Path      string    `json:"path"`
	LastSeen  time.Time `json:"last_seen"`
	Evicted   bool      `json:"evicted"`
	EvictedAt time.Time `json:"evicted_at,omitempty"`
}

type Status struct {
	Patterns []string `json:"patterns"`
	Members  []Member `json:"members"`
}

var ErrNoPeers = fmt.Errorf("no active peer sockets: %w", ErrPeerUnreachable)
const EvictProbeInterval = 5 * time.Minute

func NewPool(patterns []string, opts ...Option) *Pool
func WithClock(func() time.Time) Option
func WithOnChange(func()) Option
func (p *Pool) Patterns() []string
func (p *Pool) Resolve() []Member          // active, ordered
func (p *Pool) Borrow(ctx context.Context) (token, source string)
func (p *Pool) Broadcast(ctx context.Context, apiPath string, form url.Values) error
func (p *Pool) Watch(ctx context.Context) error   // blocks; nil-safe
func (p *Pool) Status() Status
```

  Also `observability.RecordPeerPool(ctx, event string)` with events `admitted|evicted|readmitted`.

- [ ] **Step 1: Add the observability counter**

In `internal/observability/observability.go`: add `peerPool metric.Int64Counter` beside `tokenDenylist` (line ~776); in `rebindInstruments` after the `tokenDenylist` block:

```go
	peerPool, _ = meter.Int64Counter(
		"dotvault.peer.pool",
		metric.WithDescription("Peer socket pool membership events: admitted, evicted, readmitted"),
	)
```

and after `RecordTokenDenylist`:

```go
// RecordPeerPool records a peer socket pool membership event: "admitted" (a
// socket matched a pattern for the first time), "evicted" (a transport
// failure took it out of rotation), "readmitted" (it came back — recreated,
// watched, or past the probe window). A rising evicted/readmitted pair on one
// host is a flapping SSH forward.
func RecordPeerPool(ctx context.Context, event string) {
	instrMu.RLock()
	c := peerPool
	instrMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(ctx, 1, metric.WithAttributes(attribute.String("event", event)))
}
```

Run: `go build ./internal/observability/` — expected OK.

- [ ] **Step 2: Write the failing pool tests**

Create `internal/peer/pool_test.go`:

```go
package peer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// tokenServer serves GET /api/v1/token returning token (401 when empty) and
// POST /api/v1/remote/* answering postStatus, on a Unix socket at path.
func tokenServer(t *testing.T, path, token string, postStatus int) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/token", func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"` + token + `"}`))
	})
	mux.HandleFunc("POST /api/v1/remote/", func(w http.ResponseWriter, r *http.Request) {
		if postStatus == 400 {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"bad input"}`))
			return
		}
		w.WriteHeader(postStatus)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// hangingServer accepts connections and never answers — the shape of an SSH
// forward whose far end has gone away while sshd still holds the socket.
func hangingServer(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-time.After(time.Hour); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func setMtime(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestPoolResolveOrdersByLastSeen(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "dotvault.desktop.sock")
	fresh := filepath.Join(dir, "dotvault.laptop.sock")
	tokenServer(t, old, "hvs.desktop", 200)
	tokenServer(t, fresh, "hvs.laptop", 200)
	now := time.Now()
	setMtime(t, old, now.Add(-time.Hour))
	setMtime(t, fresh, now)

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	got := p.Resolve()
	if len(got) != 2 || got[0].Path != fresh || got[1].Path != old {
		t.Fatalf("order = %+v, want laptop first", got)
	}
	tok, src := p.Borrow(context.Background())
	if tok != "hvs.laptop" || src != fresh {
		t.Errorf("Borrow = (%q, %q), want laptop", tok, src)
	}
}

func TestPoolLiteralBeforeGlobOnTie(t *testing.T) {
	dir := t.TempDir()
	lit := filepath.Join(dir, "dotvault.sock")
	glob := filepath.Join(dir, "dotvault.x.sock")
	tokenServer(t, lit, "a", 200)
	tokenServer(t, glob, "b", 200)
	at := time.Now()
	setMtime(t, lit, at)
	setMtime(t, glob, at)
	p := NewPool([]string{lit, filepath.Join(dir, "dotvault.*.sock")})
	got := p.Resolve()
	if len(got) != 2 || got[0].Path != lit {
		t.Fatalf("order = %+v, want literal first on tie", got)
	}
}

func TestPoolBorrowSkipsUnauthenticatedPeerWithoutEvicting(t *testing.T) {
	dir := t.TempDir()
	noTok := filepath.Join(dir, "dotvault.a.sock")
	hasTok := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, noTok, "", 200)
	tokenServer(t, hasTok, "hvs.b", 200)
	setMtime(t, noTok, time.Now())
	setMtime(t, hasTok, time.Now().Add(-time.Minute))

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	tok, src := p.Borrow(context.Background())
	if tok != "hvs.b" || src != hasTok {
		t.Fatalf("Borrow = (%q, %q)", tok, src)
	}
	for _, m := range p.Status().Members {
		if m.Evicted {
			t.Errorf("%s evicted after a 401; a live peer with no token must stay", m.Path)
		}
	}
}

func TestPoolEvictsOnTransportFailureAndReadmitsOnRecreate(t *testing.T) {
	dir := t.TempDir()
	hung := filepath.Join(dir, "dotvault.laptop.sock")
	good := filepath.Join(dir, "dotvault.desktop.sock")
	hangingServer(t, hung)
	tokenServer(t, good, "hvs.desktop", 200)
	setMtime(t, hung, time.Now())
	setMtime(t, good, time.Now().Add(-time.Minute))

	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}, withFetchTimeout(300*time.Millisecond))
	ctx := context.Background()
	if tok, _ := p.Borrow(ctx); tok != "hvs.desktop" {
		t.Fatalf("first borrow = %q", tok)
	}
	if !memberEvicted(p, hung) {
		t.Fatal("hung socket should be evicted after a timeout")
	}
	// Evicted members are not dialled: the borrow is now fast.
	start := time.Now()
	if tok, _ := p.Borrow(ctx); tok != "hvs.desktop" {
		t.Fatalf("second borrow = %q", tok)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Errorf("second borrow dialled the evicted socket (took %v)", time.Since(start))
	}

	// Recreate the socket (new inode) with a healthy server: readmitted.
	if err := os.Remove(hung); err != nil {
		t.Fatal(err)
	}
	tokenServer(t, hung, "hvs.laptop", 200)
	setMtime(t, hung, time.Now())
	if tok, src := p.Borrow(ctx); tok != "hvs.laptop" || src != hung {
		t.Fatalf("after recreate Borrow = (%q, %q), want laptop", tok, src)
	}
}

func TestPoolReadmitsAfterProbeWindow(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dotvault.sock")
	hangingServer(t, sock)
	now := time.Now()
	clock := func() time.Time { return now }
	p := NewPool([]string{sock}, WithClock(clock), withFetchTimeout(300*time.Millisecond))
	p.Borrow(context.Background())
	if !memberEvicted(p, sock) {
		t.Fatal("expected eviction")
	}
	now = now.Add(EvictProbeInterval + time.Second)
	if got := p.Resolve(); len(got) != 1 {
		t.Fatalf("after probe window, active = %+v, want the socket back", got)
	}
}

func TestPoolBroadcastAnySuccess(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "dotvault.a.sock")
	bad := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, ok, "", 200)
	tokenServer(t, bad, "", 503)
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	if err := p.Broadcast(context.Background(), "/api/v1/remote/notify", url.Values{"title": {"x"}}); err != nil {
		t.Fatalf("Broadcast = %v, want nil when one peer accepted", err)
	}
}

func TestPoolBroadcast4xxWins(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "dotvault.a.sock")
	bad := filepath.Join(dir, "dotvault.b.sock")
	tokenServer(t, ok, "", 200)
	tokenServer(t, bad, "", 400)
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	err := p.Broadcast(context.Background(), "/api/v1/remote/notify", url.Values{"title": {"x"}})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("Broadcast = %v, want *StatusError 400", err)
	}
}

func TestPoolBroadcastNoPeers(t *testing.T) {
	p := NewPool([]string{filepath.Join(t.TempDir(), "dotvault.*.sock")})
	err := p.Broadcast(context.Background(), "/api/v1/remote/notify", nil)
	if !errors.Is(err, ErrNoPeers) || !errors.Is(err, ErrPeerUnreachable) {
		t.Fatalf("Broadcast = %v, want ErrNoPeers wrapping ErrPeerUnreachable", err)
	}
}

func TestPoolBroadcastAllFailedWrapsUnreachable(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dotvault.sock")
	hangingServer(t, sock)
	p := NewPool([]string{sock}, withPostTimeout(300*time.Millisecond))
	err := p.Broadcast(context.Background(), "/api/v1/remote/notify", nil)
	if !errors.Is(err, ErrPeerUnreachable) || errors.Is(err, ErrNoPeers) {
		t.Fatalf("Broadcast = %v, want ErrPeerUnreachable (not ErrNoPeers)", err)
	}
	if !memberEvicted(p, sock) {
		t.Error("hung socket should be evicted by Broadcast too")
	}
}

func TestPoolNilReceiver(t *testing.T) {
	var p *Pool
	if tok, src := p.Borrow(context.Background()); tok != "" || src != "" {
		t.Error("nil pool must borrow nothing")
	}
	if err := p.Broadcast(context.Background(), "/x", nil); !errors.Is(err, ErrNoPeers) {
		t.Errorf("nil pool Broadcast = %v, want ErrNoPeers", err)
	}
	if err := p.Watch(context.Background()); err != nil {
		t.Errorf("nil pool Watch = %v", err)
	}
	if s := p.Status(); len(s.Members) != 0 {
		t.Error("nil pool Status must be empty")
	}
}

func TestPoolWatchOnChangeFires(t *testing.T) {
	if !watchSupported() {
		t.Skip("no inotify on this platform")
	}
	dir := t.TempDir()
	var fired atomic.Int32
	p := NewPool([]string{filepath.Join(dir, "dotvault.*.sock")}, WithOnChange(func() { fired.Add(1) }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Watch(ctx) }()
	time.Sleep(50 * time.Millisecond) // let the watch register
	tokenServer(t, filepath.Join(dir, "dotvault.laptop.sock"), "t", 200)
	deadline := time.Now().Add(2 * time.Second)
	for fired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if fired.Load() == 0 {
		t.Fatal("OnChange did not fire on socket creation")
	}
	m := p.Status().Members
	if len(m) != 1 || m[0].LastSeen.Before(time.Now().Add(-time.Second)) {
		t.Errorf("member not admitted with a fresh LastSeen: %+v", m)
	}
}

func memberEvicted(p *Pool, path string) bool {
	for _, m := range p.Status().Members {
		if m.Path == path {
			return m.Evicted
		}
	}
	return false
}
```

Add to the bottom of `pool.go` (test-visible helpers, unexported): `withFetchTimeout(d) Option`, `withPostTimeout(d) Option`, and `watchSupported() bool` (returns `runtime.GOOS == "linux"`).

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/peer/ -run Pool -v`
Expected: compile errors — `Pool`, `NewPool`, etc. undefined.

- [ ] **Step 4: Implement `pool.go`**

```go
package peer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/tokenwatch"
)

// Borrower is the seam internal/auth borrows through. *Pool satisfies it;
// tests fake it.
type Borrower interface {
	// Borrow returns the first token any active peer yields and the socket
	// path it came from, or ("", "") when no peer produced one. Best-effort:
	// it never returns an error.
	Borrow(ctx context.Context) (token, source string)
}

// ErrNoPeers is returned by Broadcast when the pool has no active member.
// It wraps ErrPeerUnreachable so callers that only care about "could not
// reach a peer" need one errors.Is.
var ErrNoPeers = fmt.Errorf("no active peer sockets: %w", ErrPeerUnreachable)

// EvictProbeInterval is how long an evicted member stays out of rotation
// before it is probed again. Eviction is a re-probe window, not a verdict —
// the same reasoning as auth.DenyProbeInterval. A forward whose TCP side
// stalled and then recovered keeps its inode, so without this it would stay
// dark until the process restarted.
const EvictProbeInterval = 5 * time.Minute

// Member is one resolved socket, as reported by Status.
type Member struct {
	Path      string    `json:"path"`
	LastSeen  time.Time `json:"last_seen"`
	Evicted   bool      `json:"evicted"`
	EvictedAt time.Time `json:"evicted_at,omitempty"`
}

// Status is the pool's externally visible state (GET /api/v1/status
// "peer_sockets", `dotvault status`).
type Status struct {
	Patterns []string `json:"patterns"`
	Members  []Member `json:"members"`
}

// identity is what tells a recreated socket from the same one: device and
// inode. Zero on platforms where the stat does not expose them.
type identity struct {
	dev uint64
	ino uint64
}

type member struct {
	path      string
	pattern   int // index into patterns, for tie-breaking
	id        identity
	lastSeen  time.Time
	evictedAt time.Time // zero when active
}

// Pool resolves a list of socket patterns into live peers, orders them
// most-recently-seen first, evicts the unreachable and readmits them when
// they come back. Every method is nil-receiver safe.
type Pool struct {
	patterns []string // expanded (~ resolved), original order
	raw      []string // as configured, for Status

	clock        func() time.Time
	fetchTimeout time.Duration
	postTimeout  time.Duration
	onChange     func()

	mu      sync.Mutex
	members map[string]*member
}

// Option configures a Pool.
type Option func(*Pool)

// WithClock overrides the wall clock (tests).
func WithClock(now func() time.Time) Option { return func(p *Pool) { p.clock = now } }

// WithOnChange registers a hook fired from Watch whenever a matching socket
// is created or written. The daemon wires its "re-borrow now" nudges here.
func WithOnChange(fn func()) Option { return func(p *Pool) { p.onChange = fn } }

func withFetchTimeout(d time.Duration) Option { return func(p *Pool) { p.fetchTimeout = d } }
func withPostTimeout(d time.Duration) Option  { return func(p *Pool) { p.postTimeout = d } }

func watchSupported() bool { return runtime.GOOS == "linux" }

// NewPool builds a pool over patterns (literal paths or final-segment globs,
// ~-relative allowed). Patterns that cannot be expanded are dropped with a
// debug log; an all-empty list yields a pool that never borrows.
func NewPool(patterns []string, opts ...Option) *Pool {
	p := &Pool{
		raw:          append([]string(nil), patterns...),
		clock:        func() time.Time { return time.Now().Round(0) },
		fetchTimeout: FetchTimeout,
		postTimeout:  PostTimeout,
		members:      make(map[string]*member),
	}
	for _, o := range opts {
		o(p)
	}
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		expanded, err := paths.ExpandHome(pat)
		if err != nil {
			slog.Debug("peer socket pattern unusable; skipping", "pattern", pat, "error", err)
			continue
		}
		p.patterns = append(p.patterns, expanded)
	}
	return p
}

// Patterns returns the expanded patterns in order.
func (p *Pool) Patterns() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.patterns...)
}

// resolveLocked globs every pattern, admits new matches, refreshes identity
// and readmits recreated or probe-expired members, and drops vanished ones.
// Caller holds p.mu.
func (p *Pool) resolveLocked(ctx context.Context) {
	now := p.clock()
	seen := make(map[string]bool)
	for i, pat := range p.patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			slog.Debug("peer socket pattern is malformed; skipping", "pattern", pat, "error", err)
			continue
		}
		for _, path := range matches {
			if seen[path] {
				continue
			}
			fi, err := os.Stat(path)
			if err != nil || fi.Mode()&os.ModeSocket == 0 {
				continue // vanished between glob and stat, or not a socket
			}
			seen[path] = true
			id := statIdentity(fi)
			m, ok := p.members[path]
			if !ok {
				p.members[path] = &member{path: path, pattern: i, id: id, lastSeen: fi.ModTime()}
				observability.RecordPeerPool(ctx, "admitted")
				continue
			}
			if m.id != id {
				// Recreated: a new socket behind the same name.
				m.id = id
				if fi.ModTime().After(m.lastSeen) {
					m.lastSeen = fi.ModTime()
				}
				if !m.evictedAt.IsZero() {
					m.evictedAt = time.Time{}
					observability.RecordPeerPool(ctx, "readmitted")
				}
				continue
			}
			if !m.evictedAt.IsZero() && now.Sub(m.evictedAt) >= EvictProbeInterval {
				m.evictedAt = time.Time{}
				observability.RecordPeerPool(ctx, "readmitted")
			}
		}
	}
	for path := range p.members {
		if !seen[path] {
			delete(p.members, path)
		}
	}
}

// activeLocked returns the active members, ordered. Caller holds p.mu.
func (p *Pool) activeLocked() []*member {
	out := make([]*member, 0, len(p.members))
	for _, m := range p.members {
		if m.evictedAt.IsZero() {
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].lastSeen.Equal(out[j].lastSeen) {
			return out[i].lastSeen.After(out[j].lastSeen)
		}
		if out[i].pattern != out[j].pattern {
			return out[i].pattern < out[j].pattern
		}
		return out[i].path < out[j].path
	})
	return out
}

// Resolve re-globs the patterns and returns the active members in borrow
// order.
func (p *Pool) Resolve() []Member {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolveLocked(context.Background())
	act := p.activeLocked()
	out := make([]Member, len(act))
	for i, m := range act {
		out[i] = Member{Path: m.path, LastSeen: m.lastSeen}
	}
	return out
}

// evict takes path out of rotation after a transport failure. Idempotent.
func (p *Pool) evict(ctx context.Context, path string, cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m, ok := p.members[path]
	if !ok || !m.evictedAt.IsZero() {
		return
	}
	m.evictedAt = p.clock()
	observability.RecordPeerPool(ctx, "evicted")
	slog.Debug("peer socket evicted from pool", "socket", path, "error", cause)
}

// Borrow implements Borrower: active members most-recently-seen first, the
// first token wins. A transport failure evicts the member; an HTTP non-200
// (the peer holds no token) does not.
func (p *Pool) Borrow(ctx context.Context) (string, string) {
	if p == nil {
		return "", ""
	}
	p.mu.Lock()
	p.resolveLocked(ctx)
	act := p.activeLocked()
	p.mu.Unlock()

	for _, m := range act {
		fctx, cancel := context.WithTimeout(ctx, p.fetchTimeout)
		token, err := fetchTokenDetailed(fctx, m.path)
		cancel()
		if err != nil {
			p.evict(ctx, m.path, err)
			continue
		}
		if token != "" {
			return token, m.path
		}
	}
	return "", ""
}

// Broadcast posts form to every active member concurrently. Any 200 → nil.
// Any 4xx → that *StatusError, since bad input is bad everywhere. No active
// member → ErrNoPeers. Everything failed → a joined error wrapping
// ErrPeerUnreachable. Transport failures evict.
func (p *Pool) Broadcast(ctx context.Context, apiPath string, form url.Values) error {
	if p == nil {
		return ErrNoPeers
	}
	p.mu.Lock()
	p.resolveLocked(ctx)
	act := p.activeLocked()
	p.mu.Unlock()
	if len(act) == 0 {
		return ErrNoPeers
	}

	type result struct {
		path string
		err  error
	}
	results := make(chan result, len(act))
	for _, m := range act {
		go func(path string) {
			pctx, cancel := context.WithTimeout(ctx, p.postTimeout)
			defer cancel()
			results <- result{path, PostForm(pctx, path, apiPath, form)}
		}(m.path)
	}

	var (
		accepted bool
		rejected *StatusError
		failures []error
	)
	for range act {
		r := <-results
		switch {
		case r.err == nil:
			accepted = true
		case errors.Is(r.err, ErrPeerUnreachable):
			p.evict(ctx, r.path, r.err)
			failures = append(failures, fmt.Errorf("%s: %w", r.path, r.err))
		default:
			var se *StatusError
			if errors.As(r.err, &se) && se.Status >= 400 && se.Status < 500 {
				if rejected == nil {
					rejected = se
				}
			}
			failures = append(failures, fmt.Errorf("%s: %w", r.path, r.err))
		}
	}
	if rejected != nil {
		return rejected
	}
	if accepted {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPeerUnreachable, errors.Join(failures...))
}

// Watch blocks until ctx is done, watching every pattern's parent directory
// for matching sockets being created or written. On an event the member's
// lastSeen is bumped, its eviction cleared, and the OnChange hook fired.
// A no-op on platforms without inotify (the on-demand re-resolve covers
// them); an unwatchable directory degrades to that too.
func (p *Pool) Watch(ctx context.Context) error {
	if p == nil || len(p.patterns) == 0 {
		return nil
	}
	dirs := make(map[string][]string) // dir -> patterns
	for _, pat := range p.patterns {
		dirs[filepath.Dir(pat)] = append(dirs[filepath.Dir(pat)], filepath.Base(pat))
	}
	var wg sync.WaitGroup
	for dir, names := range dirs {
		dir, names := dir, names
		match := func(name string) bool {
			for _, n := range names {
				if ok, _ := filepath.Match(n, name); ok {
					return true
				}
			}
			return false
		}
		w, err := tokenwatch.NewMatch(dir, match, func(name string) {
			p.noteSeen(ctx, filepath.Join(dir, name))
			if p.onChange != nil {
				p.onChange()
			}
		})
		if err != nil {
			slog.Debug("peer socket directory not watchable; relying on re-resolve", "dir", dir, "error", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer w.Close()
			if err := w.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Debug("peer socket watcher stopped", "dir", dir, "error", err)
			}
		}()
	}
	wg.Wait()
	return nil
}

// noteSeen records a watch event for path: admit or refresh the member with
// lastSeen = now and clear any eviction.
func (p *Pool) noteSeen(ctx context.Context, path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return
	}
	m, ok := p.members[path]
	if !ok {
		idx := 0
		for i, pat := range p.patterns {
			if ok, _ := filepath.Match(pat, path); ok {
				idx = i
				break
			}
		}
		p.members[path] = &member{path: path, pattern: idx, id: statIdentity(fi), lastSeen: now}
		observability.RecordPeerPool(ctx, "admitted")
		return
	}
	m.id = statIdentity(fi)
	m.lastSeen = now
	if !m.evictedAt.IsZero() {
		m.evictedAt = time.Time{}
		observability.RecordPeerPool(ctx, "readmitted")
	}
}

// Status reports the pool for diagnostics; evicted members are included.
func (p *Pool) Status() Status {
	if p == nil {
		return Status{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolveLocked(context.Background())
	out := Status{Patterns: append([]string(nil), p.raw...)}
	for _, m := range p.members {
		out.Members = append(out.Members, Member{
			Path: m.path, LastSeen: m.lastSeen,
			Evicted: !m.evictedAt.IsZero(), EvictedAt: m.evictedAt,
		})
	}
	sort.Slice(out.Members, func(i, j int) bool { return out.Members[i].Path < out.Members[j].Path })
	return out
}

func statIdentity(fi os.FileInfo) identity {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return identity{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	}
	return identity{}
}
```

`syscall.Stat_t` does not exist on Windows. Split `statIdentity` into `identity_unix.go` (`//go:build !windows`, the body above) and `identity_windows.go` (`//go:build windows`, returns `identity{}`). Note `st.Dev` is `int32` on darwin and `uint64` on linux — the `uint64(...)` conversion covers both.

`fetchTokenDetailed` is a new unexported variant of `FetchToken` in `transport.go` that returns the transport error instead of swallowing it. Refactor: rename the existing body to `fetchTokenDetailed(ctx, socketPath) (string, error)` returning `("", err)` for a `Client` failure or a `client.Do` failure (both are "could not reach the peer"), `("", nil)` for a non-200 or a malformed body, and keep `FetchToken` as the public best-effort wrapper that calls it and maps every error to `("", nil)` with the existing debug logs. Note `Client`'s `fs.ErrNotExist` case must also be returned as an error here (the member vanished; `resolveLocked` drops it next pass, and evicting a vanished path is harmless).

- [ ] **Step 5: Run the pool tests**

Run: `go test ./internal/peer/ -v -race`
Expected: PASS. If `TestPoolResolveOrdersByLastSeen` is flaky on a filesystem with coarse mtime, the `setMtime` calls with a one-hour gap make it deterministic; keep them.

- [ ] **Step 6: Cross-build**

Run: `GOOS=windows go build ./internal/peer/ && GOOS=darwin go build ./internal/peer/`
Expected: OK.

- [ ] **Step 7: Commit**

```bash
git add internal/peer internal/observability/observability.go
git commit -m "feat(peer): socket pool with eviction and readmission"
```

Body: "peer.Pool resolves literal and glob socket patterns, orders members most-recently-seen first, evicts a member on any transport failure and readmits it on an inotify event, on a new inode, or after EvictProbeInterval. Borrow returns the first token; Broadcast posts to every active member and succeeds if any accepts, surfacing a 4xx over a success because bad input is bad everywhere. A dotvault.peer.pool counter records admitted/evicted/readmitted."

---

### Task 6: `Borrower` seam in `internal/auth`

**Files:**
- Modify: `internal/auth/auth.go:35-41,103`, `internal/auth/lifecycle.go:53-59,195-201,509,543-546`
- Delete: `internal/auth/peer_shim.go`
- Test: `internal/auth/lifecycle_test.go`, `internal/auth/auth_test.go` (whichever reference `TokenSockets`)

**Interfaces:**
- Produces: `auth.Manager.Borrower peer.Borrower` (replaces `TokenSockets []string`); `func (lm *LifecycleManager) SetBorrower(b peer.Borrower)` (replaces `SetTokenSockets`).

- [ ] **Step 1: Write a fake borrower and update tests**

Add to `internal/auth/lifecycle_test.go`:

```go
// fakeBorrower is a peer.Borrower returning a fixed token.
type fakeBorrower struct {
	token, source string
	calls         int
}

func (f *fakeBorrower) Borrow(ctx context.Context) (string, string) {
	f.calls++
	return f.token, f.source
}
```

Find every test that set `TokenSockets:` or called `SetTokenSockets` (`grep -n "TokenSockets\|SetTokenSockets" internal/auth/*_test.go`). Each stood up a Unix socket server; replace with `Borrower: &fakeBorrower{token: "hvs.peer", source: "/tmp/peer.sock"}` / `lm.SetBorrower(&fakeBorrower{...})`, and keep the assertions on what the manager did with the token. A test that asserted "socket missing → falls through" becomes `&fakeBorrower{}` (empty token).

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/auth/ 2>&1 | head`
Expected: compile errors on `Borrower`/`SetBorrower`.

- [ ] **Step 3: Implement**

`internal/auth/auth.go`: replace the `TokenSockets []string` field and its comment with:

```go
	// Borrower, when non-nil, is tried first by Login: a live token borrowed
	// from a peer dotvault (dotvault-to-dotvault sharing) means no browser,
	// TTY or TPM is needed. Callers pass a *peer.Pool built from
	// config.TokenBorrowSockets. Best-effort; a nil Borrower is skipped.
	Borrower peer.Borrower
```

Line 103: `if token, source := FetchTokenFromSockets(ctx, m.TokenSockets); token != "" {` → `if token, source := borrow(ctx, m.Borrower); token != "" {` with a helper in `auth.go`:

```go
// borrow is a nil-safe Borrow.
func borrow(ctx context.Context, b peer.Borrower) (string, string) {
	if b == nil {
		return "", ""
	}
	return b.Borrow(ctx)
}
```

`internal/auth/lifecycle.go`: field `tokenSockets []string` → `borrower peer.Borrower` (reword the comment: "borrower, when non-nil, is consulted last by tryReload so the recovery path can borrow a peer's live token before declaring re-auth necessary."); `SetTokenSockets` → 

```go
// SetBorrower wires the peer socket pool so the recovery path can borrow a
// peer's live token before declaring re-auth necessary. Nil disables it.
func (lm *LifecycleManager) SetBorrower(b peer.Borrower) {
	lm.borrower = b
}
```

Line 509: `if lm.tokenFilePath == "" && len(lm.tokenSockets) == 0 {` → `if lm.tokenFilePath == "" && lm.borrower == nil {`. Lines 543-546:

```go
	if lm.borrower != nil {
		sockToken, _ := lm.borrower.Borrow(ctx)
		addCandidate(sockToken)
	}
```

Delete `internal/auth/peer_shim.go` (`cmd/dotvault/main.go`'s three `auth.BorrowFromSockets` calls go in Task 7). `cmd/dotvault` and `client/` will not compile until Task 7 — that is expected; this task's gate is `go test ./internal/auth/`.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/auth/ -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth
git commit -m "refactor(auth): borrow through a peer.Borrower"
```

---

### Task 7: Wire the pool into `cmd/dotvault` and `client/`

**Files:**
- Modify: `cmd/dotvault/apisocket.go`, `cmd/dotvault/main.go` (lines 989-1010, 1105, 1178, 1199, 1228, 1280, 1355-1405, 1751-1780, 1932, 2271, 2507, 2942-3080), `cmd/dotvault/browse.go:66-85`, `notify.go:79-95`, `clipboard.go:76-95`
- Modify: `client/config.go:136-171,244`, `client/client.go:270-283,410`, `client/remote.go:84-110`, `client/README.md`
- Test: `cmd/dotvault/apisocket_test.go`, `cmd/dotvault/browse_test.go`, `client/client_test.go`, `client/remote_test.go`

**Interfaces:**
- Consumes: `peer.NewPool`, `peer.Pool.Borrow/Broadcast/Watch/Status`, `peer.WithOnChange`, `config.PeerActionSockets`, `auth.Manager.Borrower`, `lm.SetBorrower`.
- Produces: `client.VaultConfig.TokenSockets []string` (replaces `TokenSocket string`); `waitForHeadlessToken(ctx, vc, tokenPath, pool *peer.Pool, denyList)` (signature change).

- [ ] **Step 1: Update `cmd/dotvault` tests first**

`apisocket_test.go`: `TokenSocket: "/home/u/.ssh/dotvault.sock"` → `TokenSockets: config.SocketList{"/home/u/.ssh/dotvault.sock"}` throughout; expectations unchanged (helpers still return `[]string`).

`browse_test.go` (and any notify/clipboard tests): where a test set a single `TokenSocket` and expected `postBrowseToSocket(ctx, socket, url)`, the new shape is `postBrowseToPeers(ctx, pool, url)`. Rewrite one test to build two Unix-socket servers in a temp dir, a pool over `dir/dotvault.*.sock`, and assert both received the POST:

```go
func TestBrowseFansOutToEveryPeer(t *testing.T) {
	dir := t.TempDir()
	var hits atomic.Int32
	for _, name := range []string{"dotvault.a.sock", "dotvault.b.sock"} {
		ln, err := net.Listen("unix", filepath.Join(dir, name))
		if err != nil {
			t.Skipf("unix sockets unavailable: %v", err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/v1/remote/browse", func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
		})
		srv := httptest.NewUnstartedServer(mux)
		srv.Listener = ln
		srv.Start()
		t.Cleanup(srv.Close)
	}
	pool := peer.NewPool([]string{filepath.Join(dir, "dotvault.*.sock")})
	if err := postBrowseToPeers(context.Background(), pool, "https://example.com/"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2", hits.Load())
	}
}
```

- [ ] **Step 2: Rewire `cmd/dotvault`**

`apisocket.go`: helpers keep returning `[]string` pattern lists (no change to logic). Add:

```go
// newPeerPool builds a transient pool — resolve on demand, no watcher — for
// one-shot commands and the daemon's startup.
func newPeerPool(patterns []string, opts ...peer.Option) *peer.Pool {
	if len(patterns) == 0 {
		return nil
	}
	return peer.NewPool(patterns, opts...)
}
```

`main.go` daemon (`runDaemon`):
- After line 989 `borrowSockets := daemonBorrowSockets(cfg, apiSocket)`, build the pool. The `OnChange` hook must reach two things that do not exist yet (the headless wake channel and `lm`), so use an indirection:

```go
	// One pool for the daemon's lifetime: startup borrow, headless idle,
	// auth.Manager, and the lifecycle recovery path all share it, and its
	// watcher replaces the per-socket tokenwatch loops that used to live
	// here and in waitForHeadlessToken.
	var peerChanged atomic.Pointer[func()]
	peerPool := newPeerPool(borrowSockets, peer.WithOnChange(func() {
		if fn := peerChanged.Load(); fn != nil {
			(*fn)()
		}
	}))
	go func() {
		if err := peerPool.Watch(ctx); err != nil {
			slog.Debug("peer socket watch ended", "error", err)
		}
	}()
```
  (`peerPool.Watch` on a nil pool returns immediately.)
- Line 1001: `auth.FetchTokenFromSockets(ctx, borrowSockets)` → `peerPool.Borrow(ctx)` (nil-safe).
- Lines 1105, 1199, 1280: `TokenSockets: borrowSockets,` → `Borrower: peerPool,`.
- Line 1178: `waitForHeadlessToken(ctx, vc, headlessTokenPath(...), borrowSockets, denyList)` → `waitForHeadlessToken(ctx, vc, headlessTokenPath(...), peerPool, &peerChanged, denyList)`.
- Line 1228: `lm.SetTokenSockets(borrowSockets)` → `lm.SetBorrower(peerPool)`.
- Lines 1371-1405 (the `for _, configured := range borrowSockets { tokenwatch.New ... }` block): delete entirely and replace with:

```go
	// The pool's watcher nudges the lifecycle manager when a peer socket is
	// created or replaced — *only when the daemon actually needs a token*.
	// tryReload adopts any different valid candidate, so an unconditional
	// nudge would demote a healthy token to a borrowed one every time a
	// forwarder flapped.
	reborrow := func() {
		if !lm.NeedsReauth() {
			return
		}
		slog.Debug("peer socket changed and re-auth is pending, re-borrowing")
		lm.Reload()
	}
	peerChanged.Store(&reborrow)
```
  Keep the paragraph of rationale from the deleted comment that explains the `NeedsReauth` gate.
- `waitForHeadlessToken` (line 2942): signature becomes `(ctx, vc, tokenPath string, pool *peer.Pool, peerChanged *atomic.Pointer[func()], denyList)`. Delete the `for _, socketPath := range socketPaths { tokenwatch.New ... }` block (lines ~2982-3000) and instead, right after `notify` is defined, do `peerChanged.Store(&notify)` and `defer peerChanged.Store(nil)`. Line 3070: `auth.FetchTokenFromSockets(ctx, socketPaths)` → `pool.Borrow(ctx)`. Update the doc comment: "…or borrowable from pool (nil disables the borrow)…" and drop the sentence about registering socket watches (the pool's watcher, started in runDaemon, fires peerChanged).
- `runStatus` (lines 1751-1780): `borrowSockets := cfg.TokenBorrowSockets()`; `pool := newPeerPool(borrowSockets)`; `peerToken, source := pool.Borrow(ctx)`. Replace the `token == "" && len(borrowSockets) > 0` branch body with the pool's status:

```go
	case token == "" && len(borrowSockets) > 0:
		fmt.Println("Auth: not authenticated (no local token; no peer socket holds a token)")
		printPeerPoolStatus(pool.Status())
```
  and add a `printPeerPoolStatus` helper (also called in the `default` branch when `borrowedFrom != ""` after the source line):

```go
// printPeerPoolStatus renders the peer socket pool for `dotvault status`.
func printPeerPoolStatus(st peer.Status) {
	for _, p := range st.Patterns {
		fmt.Printf("  token socket pattern: %s\n", p)
	}
	if len(st.Members) == 0 {
		fmt.Println("  peer sockets: none present")
		return
	}
	for _, m := range st.Members {
		state := "active"
		if m.Evicted {
			state = "evicted " + m.EvictedAt.Format("15:04:05")
		}
		fmt.Printf("  peer socket: %s (%s, last seen %s)\n", m.Path, state, m.LastSeen.Format("2006-01-02 15:04:05"))
	}
}
```
- Lines 1932, 2271, 2507: `TokenSockets: freshLoginBorrowSockets(cfg)` → `Borrower: newPeerPool(freshLoginBorrowSockets(cfg))`; `TokenSockets: cfg.TokenBorrowSockets()` → `Borrower: newPeerPool(cfg.TokenBorrowSockets())`.
- `browse.go`: replace lines 66-85 with

```go
	var pool *peer.Pool
	if cfg, _, err := loadConfigLocalOnly(); err != nil {
		slog.Warn("could not load config; opening locally", "error", err)
	} else {
		pool = newPeerPool(cfg.PeerActionSockets())
	}
	if pool != nil {
		err := postBrowseToPeers(cmd.Context(), pool, target)
		if err == nil {
			return nil
		}
		slog.Debug("peer browse unavailable; opening locally", "error", err)
	}
```
  and `postBrowseToSocket` → `func postBrowseToPeers(ctx context.Context, pool *peer.Pool, target string) error { return pool.Broadcast(ctx, "/api/v1/remote/browse", url.Values{"url": {target}}) }`. Update its doc: "…posts the URL to every active peer; the caller falls back to the local browser on any error."
- `notify.go` and `clipboard.go`: the same shape (`postNotifyToPeers`, `postClipboardToPeers`). In `clipboard.go` keep the `strings.ReplaceAll(err.Error(), text, "<text>")` scrub — a joined error may echo several peers' bodies.
- Remove now-unused imports (`tokenwatch`, `paths` where only the deleted loops used them).

- [ ] **Step 3: Rewire `client/`**

`client/config.go`: `TokenSocket string` → `TokenSockets []string` with doc: "TokenSockets lists peer dotvault socket patterns — literal paths or final-segment globs (`~/.ssh/dotvault.*.sock`) — mirroring vault.token_socket with its default applied. An interactive Login and AuthenticateCached borrow from the most recently seen live peer first; Browse/Notify/Clipboard fan out to every live peer. Missing or stale sockets are skipped." `borrowSockets()` → `return append(out, v.TokenSockets...)`. Line 244: `TokenSockets: cfg.PeerActionSockets(),` (the facade gets the default applied, since it has no other way to learn it). Add `func (v VaultConfig) borrowPool() *peer.Pool { return peer.NewPool(v.borrowSockets()) }` and `func (v VaultConfig) peerPool() *peer.Pool { if len(v.TokenSockets) == 0 { return nil }; return peer.NewPool(v.TokenSockets) }`.

`client/client.go:270-283`: replace the per-socket loop with

```go
	// Candidate 3: borrow from the peer pool — local API socket first (see
	// VaultConfig.APISocket), then peers most-recently-seen first. One
	// token is returned; re-validating an identical value would be a wasted
	// round trip.
	if borrowed, _ := c.cfg.Vault.borrowPool().Borrow(ctx); borrowed != "" && !seen[borrowed] {
		seen[borrowed] = true
		if ok, unreachable := tryCandidate(borrowed); ok {
			return nil
		} else if unreachable != nil {
			return unreachable
		}
		cachedRejected = true
	}
```
  Line 410: `TokenSockets: c.cfg.Vault.borrowSockets(),` → `Borrower: c.cfg.Vault.borrowPool(),`.

`client/remote.go:99-110`:

```go
func (c *Client) peerAction(ctx context.Context, action, apiPath string, form url.Values) error {
	pool := c.cfg.Vault.peerPool()
	if pool == nil {
		return fmt.Errorf("%w: no peer socket configured (set vault.token_socket)", ErrPeerUnavailable)
	}
	err := pool.Broadcast(ctx, apiPath, form)
	if err == nil {
		return nil
	}
	var se *peer.StatusError
	if errors.As(err, &se) && se.Status < 500 {
		return fmt.Errorf("dotvault: peer rejected %s request: %s", action, se.Message)
	}
	return fmt.Errorf("%w: %s: %w", ErrPeerUnavailable, action, err)
}
```
  Update the doc comment ("named by the configured TokenSocket" → "every live peer in TokenSockets"). `client/errors.go:77` comment: `TokenSocket` → `TokenSockets`.

`client/README.md`: rename `TokenSocket` → `TokenSockets` in the table rows at lines 58, 65, 83 and note the fan-out ("posts to every live peer; succeeds if any accepts").

Tests in `client/`: `TokenSocket: x` → `TokenSockets: []string{x}`; `remote_test.go` fake servers stay valid since a literal path is a pattern.

- [ ] **Step 4: Build, vet, test**

Run: `go build ./... && go vet ./... && go test ./cmd/... ./client/... ./internal/... -race`
Expected: PASS. `make build-all` must also succeed (Windows has no `syscall.Stat_t`; Task 5's split file covers it).

- [ ] **Step 5: Commit**

```bash
git add cmd/dotvault client
git commit -m "feat: borrow and fan out through the peer socket pool"
```

Body: "The daemon builds one peer.Pool and shares it with the startup borrow, the headless idle, auth.Manager and the lifecycle recovery path; its watcher replaces the two per-socket tokenwatch loops. One-shot commands and the client facade build transient pools. browse, notify and clipboard broadcast to every live peer and still fall back locally on any error. dotvault status prints the pool. The facade's TokenSocket becomes TokenSockets."

---

### Task 8: `peer_sockets` block on `/api/v1/status`

**Files:**
- Modify: `internal/web/server.go` (fields next to `fuseStatus`, ~line 192-200, plus setter/snapshot next to line 743), `internal/web/api.go:110` (after the fuse block), `cmd/dotvault/main.go` (call the setter after the web server is constructed, where `SetFUSEStatus` is called — `grep -n SetFUSEStatus cmd/dotvault/*.go`)
- Test: `internal/web/api_test.go`

**Interfaces:**
- Produces: `func (s *Server) SetPeerStatus(fn func() peer.Status)`.

- [ ] **Step 1: Write the failing test**

Append to `internal/web/api_test.go` (mirror how the existing fuse-status test constructs a server — `grep -n "SetFUSEStatus" internal/web/*_test.go`):

```go
func TestStatusCarriesPeerSockets(t *testing.T) {
	s := newTestServer(t) // whatever helper api_test.go uses
	s.SetPeerStatus(func() peer.Status {
		return peer.Status{
			Patterns: []string{"~/.ssh/dotvault.*.sock"},
			Members:  []peer.Member{{Path: "/home/u/.ssh/dotvault.laptop.sock", Evicted: true}},
		}
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Host = "127.0.0.1"
	s.Handler().ServeHTTP(rec, req) // or however the helper exposes the mux
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ps, ok := body["peer_sockets"].(map[string]any)
	if !ok {
		t.Fatalf("no peer_sockets block: %s", rec.Body.String())
	}
	members := ps["members"].([]any)
	if len(members) != 1 || members[0].(map[string]any)["evicted"] != true {
		t.Errorf("members = %v", members)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/web/ -run TestStatusCarriesPeerSockets`
Expected: compile error, `SetPeerStatus` undefined.

- [ ] **Step 3: Implement**

`server.go`: add after `fuseStatus`:

```go
	// peerMu guards peerStatus, wired post-construction like fuseStatus.
	peerMu sync.RWMutex
	// peerStatus reports the peer socket pool for /api/v1/status's
	// "peer_sockets" block. Nil when the daemon borrows from no peer.
	peerStatus func() peer.Status
```

and after `fuseStatusSnapshot`:

```go
// SetPeerStatus wires the peer socket pool's status query.
func (s *Server) SetPeerStatus(fn func() peer.Status) {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	s.peerStatus = fn
}

func (s *Server) peerStatusSnapshot() func() peer.Status {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.peerStatus
}
```

`api.go` after the fuse block:

```go
	// Peer socket pool (patterns, members, eviction). Unauthenticated like the
	// blocks above: it names socket files in this user's own home and reports
	// whether they answered, never anything from behind them. This is the
	// block that shows "two sockets, one evicted" when a borrow has nowhere
	// to go.
	if peerStatus := s.peerStatusSnapshot(); peerStatus != nil {
		status["peer_sockets"] = peerStatus()
	}
```

`cmd/dotvault/main.go`: next to the `SetFUSEStatus` call, `if peerPool != nil { webServer.SetPeerStatus(peerPool.Status) }` (use the actual server variable name; the pool is built before the web server, so ordering is fine — if the web server is constructed *before* line 989, move the pool construction above it; the pool only needs `cfg` and `apiSocket`).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/web/ ./cmd/... -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/web/server.go internal/web/api.go internal/web/api_test.go cmd/dotvault/main.go
git commit -m "feat(web): report the peer socket pool on status"
```

---

### Task 9: `{{HOSTNAME}}` on the forwarder

**Files:**
- Modify: `internal/sshfwd/config.go:17-20,201-234`, `internal/sshfwd/home.go:30-66`
- Modify: `cmd/dotvault/ssh_add.go:50,60`, `cmd/dotvault/ssh_edit.go:34,42`
- Test: `internal/sshfwd/home_test.go`, `internal/sshfwd/config_test.go`

**Interfaces:**
- Produces: `sshfwd.DefaultRemoteSocket = "~/.ssh/dotvault.{{HOSTNAME}}.sock"`; `const HostnameToken = "{{HOSTNAME}}"`; `func LocalHostnameLabel() (string, error)`; `var hostnameFn = os.Hostname` (test seam).

- [ ] **Step 1: Write the failing tests**

Append to `internal/sshfwd/home_test.go` (use the file's existing fake `CommandRunner` — `grep -n "type fakeRunner\|func(ctx context.Context, cmd string)" internal/sshfwd/home_test.go`):

```go
func TestExpandRemotePathSubstitutesHostname(t *testing.T) {
	old := hostnameFn
	hostnameFn = func() (string, error) { return "Gary-MBP.local", nil }
	t.Cleanup(func() { hostnameFn = old })

	r := fakeRunner{home: "/home/me"} // adapt to the file's fake
	got, err := ExpandRemotePath(context.Background(), r, "~/.ssh/dotvault.{{HOSTNAME}}.sock")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/home/me/.ssh/dotvault.gary-mbp.sock" {
		t.Errorf("got %q", got)
	}
	// Absolute paths substitute too, without a home probe.
	got, err = ExpandRemotePath(context.Background(), failingRunner{}, "/srv/dotvault.{{HOSTNAME}}.sock")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/srv/dotvault.gary-mbp.sock" {
		t.Errorf("got %q", got)
	}
}

func TestExpandRemotePathHostnameSanitised(t *testing.T) {
	old := hostnameFn
	t.Cleanup(func() { hostnameFn = old })
	cases := map[string]string{
		"desktop":          "desktop",
		"My Box_1.corp":    "my-box-1",
		"UPPER":            "upper",
		"":                 "", // error
		"...":              "", // error: empty after sanitising
	}
	for in, want := range cases {
		hostnameFn = func() (string, error) { return in, nil }
		got, err := LocalHostnameLabel()
		if want == "" {
			if err == nil {
				t.Errorf("%q: expected error, got %q", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: got (%q, %v), want %q", in, got, err, want)
		}
	}
}
```

Append to `internal/sshfwd/config_test.go`:

```go
func TestValidateRemoteSocketTemplateToken(t *testing.T) {
	if err := ValidateRemoteSocket("~/.ssh/dotvault.{{HOSTNAME}}.sock"); err != nil {
		t.Errorf("exact token rejected: %v", err)
	}
	for _, bad := range []string{
		"~/.ssh/dotvault.{{HOST}}.sock",
		"~/.ssh/dotvault.{{hostname}}.sock",
		"~/.ssh/{{.sock",
		"~/.ssh/dotvault.}}.sock",
	} {
		if err := ValidateRemoteSocket(bad); err == nil {
			t.Errorf("%q: expected rejection", bad)
		}
	}
}

func TestDefaultRemoteSocketIsPerHost(t *testing.T) {
	if DefaultRemoteSocket != "~/.ssh/dotvault.{{HOSTNAME}}.sock" {
		t.Errorf("DefaultRemoteSocket = %q", DefaultRemoteSocket)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/sshfwd/ -run 'Hostname|TemplateToken|DefaultRemoteSocket' -v`
Expected: compile errors / FAIL.

- [ ] **Step 3: Implement**

`config.go`:

```go
// DefaultRemoteSocket is the socket path used when a remote does not name
// one. It is stored literally: the leading ~ is expanded against the
// *remote* account's home and HostnameToken against this daemon's own
// hostname, both at connect time — see home.go. Naming the socket after the
// forwarding workstation is what lets two workstations forward to the same
// remote without the last one to connect taking over a shared path.
const DefaultRemoteSocket = "~/.ssh/dotvault." + HostnameToken + ".sock"

// HostnameToken is the one template token a remote_socket may carry.
const HostnameToken = "{{HOSTNAME}}"
```

In `ValidateRemoteSocket`, before the `switch`, add:

```go
	// Only the exact token is a template. Any other brace would bind a
	// literal-braced socket that happens to match the borrower's glob.
	stripped := strings.ReplaceAll(p, HostnameToken, "x")
	if strings.Contains(stripped, "{{") || strings.Contains(stripped, "}}") {
		return fmt.Errorf("remote_socket may contain only the %s template token", HostnameToken)
	}
```

`home.go`: add

```go
// hostnameFn is os.Hostname, replaceable in tests.
var hostnameFn = os.Hostname

// LocalHostnameLabel returns this host's name as a socket-safe label: the
// first DNS label of os.Hostname(), lowercased, with every byte outside
// [a-z0-9-] replaced by '-'. Lowercasing matters because the borrower's
// pattern is a filename glob and macOS hostnames are routinely mixed-case.
// An empty result is an error rather than a silent "dotvault..sock".
func LocalHostnameLabel() (string, error) {
	h, err := hostnameFn()
	if err != nil {
		return "", fmt.Errorf("resolve local hostname: %w", err)
	}
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	h = strings.ToLower(h)
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "", fmt.Errorf("local hostname %q yields no usable label for %s", h, HostnameToken)
	}
	return out, nil
}
```

(`"My Box_1.corp"` → first label `My Box_1` → `my-box-1`; `"..."` → first label `""` → error.)

In `ExpandRemotePath`, after `ValidateRemoteSocket` and before the `~/` check:

```go
	if strings.Contains(p, HostnameToken) {
		label, err := LocalHostnameLabel()
		if err != nil {
			return "", err
		}
		p = strings.ReplaceAll(p, HostnameToken, label)
	}
```

Add `"os"` to home.go's imports. Update the `ExpandRemotePath` doc: "…Only a "~/" prefix triggers the probe; the {{HOSTNAME}} token is substituted locally first and never needs one."

`cmd/dotvault/ssh_add.go:50,60` and `ssh_edit.go:34,42`: replace `~/.ssh/dotvault.sock` in the help strings with `~/.ssh/dotvault.{{HOSTNAME}}.sock` and add to `ssh add`'s long help: "The default names the socket after this workstation so several workstations can forward to one remote. A remote running a dotvault older than 0.34 only looks for ~/.ssh/dotvault.sock — pass --socket ~/.ssh/dotvault.sock for it until it is upgraded."

- [ ] **Step 4: Run tests**

Run: `go test ./internal/sshfwd/ ./cmd/... -race`
Expected: PASS. Fix any existing test asserting the old default literal (grep `dotvault.sock"` in `internal/sshfwd/*_test.go`, `internal/web/ssh_test.go`, `cmd/dotvault/ssh_*_test.go`).

- [ ] **Step 5: Commit**

```bash
git add internal/sshfwd cmd/dotvault/ssh_add.go cmd/dotvault/ssh_edit.go
git commit -m "feat(sshfwd): per-hostname default remote socket"
```

Body: "remote_socket may carry the {{HOSTNAME}} token, substituted at connect time with this host's lowercased first hostname label, and the default becomes ~/.ssh/dotvault.{{HOSTNAME}}.sock. Any other brace is rejected at validation so a typo cannot bind a literal-braced socket."

---

### Task 10: Old-default forward migration (daemon-only)

**Files:**
- Create: `cmd/dotvault/peermigrate.go`, `cmd/dotvault/peermigrate_test.go`
- Modify: `cmd/dotvault/main.go` — call after each successful daemon borrow (the startup borrow at ~line 1001, the headless adopt in `waitForHeadlessToken`, and the lifecycle path). The lifecycle borrow happens inside `internal/auth`; expose the source by wrapping the pool: the daemon passes `&migratingBorrower{pool, mig}` as the `Borrower` whose `Borrow` calls `pool.Borrow` then `mig.maybeMigrate(ctx, source)` asynchronously.

**Interfaces:**
- Produces:

```go
const remoteSocketTemplateSince = "0.34.0"
type peerMigrator struct { ... }
func newPeerMigrator(oldDefault string) *peerMigrator            // oldDefault = expanded $HOME/.ssh/dotvault.sock
func (m *peerMigrator) maybeMigrate(ctx context.Context, source string) // nil-safe, non-blocking (spawns a goroutine)
type migratingBorrower struct { pool *peer.Pool; mig *peerMigrator }
func (b *migratingBorrower) Borrow(ctx context.Context) (string, string)
func versionAtLeast(v, min string) bool
func hostIsSelf(ctx context.Context, host string) bool
```

- [ ] **Step 1: Write the failing tests**

Create `cmd/dotvault/peermigrate_test.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakePeer is a workstation dotvault's API on a Unix socket: status (with a
// version), the remotes list, csrf, and a PATCH recorder.
type fakePeer struct {
	version string
	remotes []map[string]any
	mu      sync.Mutex
	patches []struct{ host, body string }
	dropOnPatch bool
}

func (f *fakePeer) serve(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": f.version})
	})
	mux.HandleFunc("GET /api/v1/ssh/remotes", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"remotes": f.remotes})
	})
	mux.HandleFunc("GET /api/v1/csrf", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "csrf-1"})
	})
	mux.HandleFunc("PATCH /api/v1/ssh/remotes/{host}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "csrf-1" {
			w.WriteHeader(403)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.patches = append(f.patches, struct{ host, body string }{r.PathValue("host"), string(b)})
		f.mu.Unlock()
		if f.dropOnPatch {
			if hj, ok := w.(http.Hijacker); ok {
				c, _, _ := hj.Hijack()
				c.Close()
				return
			}
		}
		_, _ = w.Write([]byte(`{"host":"x"}`))
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

func (f *fakePeer) patched() []struct{ host, body string } {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]struct{ host, body string }(nil), f.patches...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met in time")
	}
}

func selfHost(t *testing.T) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		t.Skip("no hostname")
	}
	return h
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		v, min string
		want   bool
	}{
		{"0.34.0", "0.34.0", true}, {"0.35.1", "0.34.0", true}, {"1.0.0", "0.34.0", true},
		{"0.33.9", "0.34.0", false}, {"v0.34.0", "0.34.0", true}, {"0.34.0-rc1", "0.34.0", true},
		{"", "0.34.0", true}, {"dev", "0.34.0", true}, {"garbage.x", "0.34.0", true},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q,%q) = %v, want %v", c.v, c.min, got, c.want)
		}
	}
}

func TestHostIsSelf(t *testing.T) {
	ctx := context.Background()
	if !hostIsSelf(ctx, selfHost(t)) {
		t.Error("own hostname should match")
	}
	if hostIsSelf(ctx, "localhost") || hostIsSelf(ctx, "127.0.0.1") {
		t.Error("loopback must never match")
	}
	if hostIsSelf(ctx, "definitely-not-this-host.invalid") {
		t.Error("unknown host must not match")
	}
}

func TestMigratePatchesOwnOldDefaultEntry(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dotvault.sock")
	peer := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock", "port": 22, "enabled": true},
		{"host": "other.example", "remote_socket": "~/.ssh/dotvault.sock", "port": 22, "enabled": true},
		{"host": selfHost(t) + "-alias", "remote_socket": "/abs/dotvault.sock", "port": 22, "enabled": true},
	}}
	peer.serve(t, sock)

	m := newPeerMigrator(sock)
	m.maybeMigrate(context.Background(), sock)
	waitFor(t, func() bool { return len(peer.patched()) == 1 })
	got := peer.patched()[0]
	if got.host != selfHost(t) {
		t.Errorf("patched host = %q", got.host)
	}
	if got.body != `{"remote_socket":"~/.ssh/dotvault.{{HOSTNAME}}.sock"}` {
		t.Errorf("body = %s", got.body)
	}
	// Once per socket identity per process.
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(100 * time.Millisecond)
	if len(peer.patched()) != 1 {
		t.Errorf("migrated twice: %v", peer.patched())
	}
}

func TestMigrateSkipsOldPeerVersion(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dotvault.sock")
	peer := &fakePeer{version: "0.33.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	peer.serve(t, sock)
	m := newPeerMigrator(sock)
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(200 * time.Millisecond)
	if len(peer.patched()) != 0 {
		t.Errorf("old peer must not be patched: %v", peer.patched())
	}
}

func TestMigrateIgnoresOtherSockets(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "dotvault.sock")
	other := filepath.Join(dir, "dotvault.laptop.sock")
	peer := &fakePeer{version: "0.34.0", remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	peer.serve(t, other)
	m := newPeerMigrator(old)
	m.maybeMigrate(context.Background(), other)
	time.Sleep(200 * time.Millisecond)
	if len(peer.patched()) != 0 {
		t.Errorf("only the old default socket triggers migration: %v", peer.patched())
	}
}

func TestMigrateTreatsDroppedResponseAsApplied(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dotvault.sock")
	peer := &fakePeer{version: "dev", dropOnPatch: true, remotes: []map[string]any{
		{"host": selfHost(t), "remote_socket": "~/.ssh/dotvault.sock"},
	}}
	peer.serve(t, sock)
	m := newPeerMigrator(sock)
	m.maybeMigrate(context.Background(), sock)
	waitFor(t, func() bool { return len(peer.patched()) == 1 })
	// A second nudge for the same identity must not retry: the drop is the
	// expected shape of success.
	m.maybeMigrate(context.Background(), sock)
	time.Sleep(100 * time.Millisecond)
	if len(peer.patched()) != 1 {
		t.Errorf("retried after a dropped response: %v", peer.patched())
	}
}
```

`selfHost` uses the real hostname, so the self-match exercises the hostname branch; the address branch is covered by `TestHostIsSelf` only indirectly (an IP of this host is environment-specific) — acceptable.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/dotvault/ -run 'Migrate|VersionAtLeast|HostIsSelf' -v`
Expected: compile errors.

- [ ] **Step 3: Implement `peermigrate.go`**

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/goodtune/dotvault/internal/peer"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// TODO(pre-1.0, #ISSUE): delete this file. It exists only to move fleets
// off the shared ~/.ssh/dotvault.sock forward without a human touching each
// workstation.

// remoteSocketTemplateSince is the first release whose sshfwd expands
// {{HOSTNAME}}. A peer reporting an older version is left alone: handing it
// the template would bind a literal-braced socket.
const remoteSocketTemplateSince = "0.34.0"

// legacyRemoteSocket is the pre-0.34 default, the only stored value the
// migration touches.
const legacyRemoteSocket = "~/.ssh/dotvault.sock"

const migrateTimeout = 15 * time.Second

// peerMigrator PATCHes a workstation's managed-forward entry for this host
// from the old shared default to the per-hostname template, over the very
// socket that forward created. It is daemon-only and runs at most once per
// socket identity per process.
type peerMigrator struct {
	oldDefault string // expanded $HOME/.ssh/dotvault.sock

	mu   sync.Mutex
	done map[peerIdentity]bool
}

type peerIdentity struct{ dev, ino uint64 }

func newPeerMigrator(oldDefault string) *peerMigrator {
	return &peerMigrator{oldDefault: oldDefault, done: make(map[peerIdentity]bool)}
}

// migratingBorrower wraps a pool so every successful borrow through the old
// default socket schedules a migration check.
type migratingBorrower struct {
	pool *peer.Pool
	mig  *peerMigrator
}

func (b *migratingBorrower) Borrow(ctx context.Context) (string, string) {
	token, source := b.pool.Borrow(ctx)
	if token != "" {
		b.mig.maybeMigrate(ctx, source)
	}
	return token, source
}

// maybeMigrate runs the migration in the background when source is the old
// default socket and this identity has not been handled yet. Nil-safe.
func (m *peerMigrator) maybeMigrate(ctx context.Context, source string) {
	if m == nil || source == "" || source != m.oldDefault {
		return
	}
	id, ok := socketIdentity(source)
	if !ok {
		return
	}
	m.mu.Lock()
	if m.done[id] {
		m.mu.Unlock()
		return
	}
	m.done[id] = true
	m.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrateTimeout)
		defer cancel()
		if err := m.migrate(ctx, source); err != nil {
			slog.Warn("could not migrate peer forward off the shared default socket", "socket", source, "error", err)
		}
	}()
}

func socketIdentity(path string) (peerIdentity, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return peerIdentity{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return peerIdentity{}, false
	}
	return peerIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

func (m *peerMigrator) migrate(ctx context.Context, socket string) error {
	client, _, err := peer.Client(socket)
	if err != nil {
		return err
	}

	var status struct {
		Version string `json:"version"`
	}
	if err := getJSON(ctx, client, "/api/v1/status", &status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if !versionAtLeast(status.Version, remoteSocketTemplateSince) {
		slog.Debug("peer too old for {{HOSTNAME}} forwards; leaving its default socket alone", "socket", socket, "peer_version", status.Version)
		return nil
	}

	var list struct {
		Remotes []struct {
			Host         string `json:"host"`
			RemoteSocket string `json:"remote_socket"`
		} `json:"remotes"`
	}
	if err := getJSON(ctx, client, "/api/v1/ssh/remotes", &list); err != nil {
		return fmt.Errorf("list remotes: %w", err)
	}

	for _, r := range list.Remotes {
		if r.RemoteSocket != legacyRemoteSocket || !hostIsSelf(ctx, r.Host) {
			continue
		}
		if err := m.patch(ctx, client, r.Host); err != nil {
			return fmt.Errorf("patch %s: %w", r.Host, err)
		}
	}
	return nil
}

func (m *peerMigrator) patch(ctx context.Context, client *http.Client, host string) error {
	csrf, err := sshCSRFToken(ctx, client, "http://localhost")
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"remote_socket": sshfwd.DefaultRemoteSocket})
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		"http://localhost/api/v1/ssh/remotes/"+url.PathEscape(host), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		// Applying the patch rebinds the forward, which tears down the
		// connection carrying this response. A transport error after the
		// request was written is the expected shape of success; the new
		// socket appearing is the confirmation.
		slog.Info("peer forward migration sent; connection dropped as the forward rebound", "host", host, "socket", sshfwd.DefaultRemoteSocket)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("peer returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	slog.Info("migrated peer forward to the per-hostname socket", "host", host, "socket", sshfwd.DefaultRemoteSocket)
	return nil
}

func getJSON(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// versionAtLeast reports whether v (a dotvault version string, optional
// leading v, optional -prerelease/+build suffix) is at least min. Anything
// that does not parse as major.minor.patch — "", "dev", a bare commit — is
// treated as new: those are development builds, which always carry the
// template support.
func versionAtLeast(v, min string) bool {
	pv, ok := parseSemver(v)
	if !ok {
		return true
	}
	pm, _ := parseSemver(min)
	for i := 0; i < 3; i++ {
		if pv[i] != pm[i] {
			return pv[i] > pm[i]
		}
	}
	return true
}

func parseSemver(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// hostIsSelf reports whether host names this machine: equal (case-folded)
// to os.Hostname() or its first label, or resolving to a non-loopback
// address one of this machine's interfaces carries. Loopback never matches —
// it would match every borrower.
func hostIsSelf(ctx context.Context, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	if hn, err := os.Hostname(); err == nil {
		hn = strings.ToLower(hn)
		if host == hn || host == strings.SplitN(hn, ".", 2)[0] {
			return true
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(lctx, host)
	if err != nil {
		return false
	}
	local := localAddrs()
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if local[ip.String()] {
			return true
		}
	}
	return false
}

func localAddrs() map[string]bool {
	out := make(map[string]bool)
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range ifaddrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && !ip.IsLoopback() {
			out[ip.String()] = true
		}
	}
	return out
}
```

`syscall.Stat_t` again: put `socketIdentity` in `peermigrate_unix.go` (`//go:build !windows`) and a `peermigrate_windows.go` stub returning `(peerIdentity{}, false)` — the migration is inert on Windows, which never borrows over a forwarded Unix socket anyway. Drop the unused `errors` import if `go vet` complains.

- [ ] **Step 4: Wire it in `main.go`**

In `runDaemon`, after the pool is built (Task 7):

```go
	// TODO(pre-1.0, #ISSUE): remove with peermigrate.go.
	var migrator *peerMigrator
	if home, err := os.UserHomeDir(); err == nil {
		migrator = newPeerMigrator(filepath.Join(home, ".ssh", "dotvault.sock"))
	}
	var borrower peer.Borrower = peerPool
	if peerPool != nil && migrator != nil {
		borrower = &migratingBorrower{pool: peerPool, mig: migrator}
	}
```

Then use `borrower` (not `peerPool`) for: the startup borrow (`borrower.Borrow(ctx)` — guard nil since `peer.Borrower` is an interface: `if borrower != nil`), the three `Borrower:` fields, `lm.SetBorrower(borrower)`, and pass it into `waitForHeadlessToken` (change that parameter's type to `peer.Borrower`; inside, `if pool != nil { pool.Borrow(ctx) }`). `SetPeerStatus` keeps using `peerPool.Status`. One-shot commands keep the plain pool — they never migrate.

- [ ] **Step 5: Run tests**

Run: `go test ./cmd/dotvault/ -race -run 'Migrate|VersionAtLeast|HostIsSelf|Headless|Borrow' -v && go build ./... && GOOS=windows go build ./cmd/dotvault/`
Expected: PASS; builds OK.

- [ ] **Step 6: Commit**

```bash
git add cmd/dotvault/peermigrate.go cmd/dotvault/peermigrate_unix.go cmd/dotvault/peermigrate_windows.go cmd/dotvault/peermigrate_test.go cmd/dotvault/main.go
git commit -m "feat: migrate peers off the shared default forward"
```

Body: "After the daemon borrows through ~/.ssh/dotvault.sock it reads the peer's version and managed-forward list, finds the entry naming this host whose stored remote_socket is exactly the old default, and PATCHes it to ~/.ssh/dotvault.{{HOSTNAME}}.sock — the request dotvault ssh edit sends. Peers older than 0.34.0 are skipped, since they cannot expand the template. Runs once per socket identity per process; a connection dropped as the forward rebinds is treated as applied. Daemon-only; removed before 1.0."

---

### Task 11: Sunset issue, docs, CLAUDE.md, review, PR

**Files:**
- Modify: `docs/configuration/config-reference.md:131,189-207,267-299`, `docs/guide/ssh-forwards.md:36,42,48-50,77-90,131`, `CLAUDE.md` (architecture tree, `vault` config-section entry, "Peer-socket token borrow" and "Local API socket" paragraphs, the `sshfwd` default under "Managed SSH forwards", the CLI paragraphs for browse/notify/clipboard)
- Modify: every `#ISSUE` placeholder from Tasks 1, 2, 10.

- [ ] **Step 1: Create the sunset issue**

Load the GitHub tools (`ToolSearch` for `mcp__github__create_issue`) and create in `goodtune/dotvault`:

Title: `Remove pre-1.0 token_socket compatibility`

Body (flowing prose):

> Tracking the compatibility shims introduced with the peer socket pool (spec: `docs/superpowers/specs/2026-09-24-peer-socket-pool-design.md`) that must be deleted before 1.0:
>
> - The scalar form of `vault.token_socket` (`config.SocketList.UnmarshalYAML`'s scalar branch) — only the list form remains.
> - The `Vault\TokenSocket` REG_SZ fallback in the Windows loader and `regfile/parse.go` — only `TokenSockets` REG_MULTI_SZ remains.
> - `~/.ssh/dotvault.sock` in `config.DefaultPeerSocketPatterns` — only the per-hostname glob remains.
> - The old-default forward migration, `cmd/dotvault/peermigrate.go`, and the `migratingBorrower` wrapper in `runDaemon`.
>
> Every site carries a `TODO(pre-1.0, #N)` comment naming this issue.

Then replace every `#ISSUE` in the code with the real number:

```bash
grep -rln 'pre-1.0, #ISSUE' --include='*.go' . | xargs sed -i '' 's/#ISSUE/#N/g'   # macOS sed; on Linux drop the ''
```

- [ ] **Step 2: Update `docs/configuration/config-reference.md`**

- Line 131 table row: `| token_socket | string or list | ~/.ssh/dotvault.sock, ~/.ssh/dotvault.*.sock | Peer dotvault socket patterns to borrow a token from and fan peer actions out to (see below); [] disables |`
- Section `### token_socket` (line 189): after the first paragraph add a paragraph: "`token_socket` is a **list of patterns** — literal paths or globs whose metacharacters sit in the final path segment (`~/.ssh/dotvault.*.sock`). A single string is still accepted. Every match is a member of a **pool**: token borrows try the most recently seen live socket first, while the peer actions (`browse`, `notify`, `clipboard`) are sent to **every** live socket and succeed if any accepts. A socket that cannot be reached within a few seconds is evicted from the pool and readmitted when it is recreated (immediately on Linux via inotify; on the next attempt elsewhere) or after five minutes. When the key is absent the default is the pair above; set `token_socket: []` to disable peer sockets entirely." Add the YAML example from the spec (list form). Update the `RemoteForward` example (line 202-204) to `/home/me/.ssh/dotvault.laptop.sock` with a comment "one socket per workstation — see the managed-forwards guide". Line 207: "sets `token_socket` (or leaves the default)". The ASCII diagram at line 276: `~/.ssh/dotvault.<host>.sock`. Line 288: keep as an example of the explicit list. Line 297: "then the `vault.token_socket` pool, most-recently-seen first". Line 299: "…keep using the `vault.token_socket` pool **only**, and are sent to every live peer in it."
- Add under the section a short "Why per-workstation sockets" paragraph: the laptop/desktop race from the spec's Problem section, three sentences.

- [ ] **Step 3: Update `docs/guide/ssh-forwards.md`**

- Line 36 and 42: default `~/.ssh/dotvault.{{HOSTNAME}}.sock`.
- Lines 48-50 example output: `/home/me/.ssh/dotvault.desktop.sock`.
- Line 77 and the table at 86: default `~/.ssh/dotvault.{{HOSTNAME}}.sock`.
- After line 90 add a paragraph: "`{{HOSTNAME}}` is the one template token `remote_socket` accepts. It is substituted at connect time with the forwarding workstation's own hostname — first label, lowercased, non-`[a-z0-9-]` characters replaced by `-` — so two workstations forwarding to the same remote bind two sockets instead of fighting over one. The borrower's default `token_socket` pattern `~/.ssh/dotvault.*.sock` finds them all. Any other `{{`/`}}` in the path is rejected. **Remotes running dotvault older than 0.34** only look for `~/.ssh/dotvault.sock`: pass `--socket ~/.ssh/dotvault.sock` when adding one, and drop the flag once it is upgraded. Conversely, an upgraded remote that borrows through a forward still bound at the old path will, once per connection, ask this workstation to rename that forward to the template on its behalf — the same PATCH `dotvault ssh edit --socket` sends — provided this workstation reports version 0.34.0 or newer; this migration is removed before 1.0 (see issue #N)."
- Line 131: `~/.ssh/dotvault.{{HOSTNAME}}.sock`.

- [ ] **Step 4: Update `CLAUDE.md`**

- Architecture tree: add `  peer/                  Peer dotvault transport (Unix-socket web API) + Pool: pattern resolution, most-recent-first borrow, fan-out broadcast, eviction/readmission — see "Peer-socket token borrow"` after `uds/`.
- `vault` config-section entry: replace the `token_socket` clause with "token_socket (list of peer socket patterns — literal or final-segment glob, a single string still accepted; default `[~/.ssh/dotvault.sock, ~/.ssh/dotvault.*.sock]`, `[]` disables — see Peer-socket token borrow)".
- "Peer-socket token borrow" section: rewrite the opening to describe the list/pool (2-3 sentences: `config.TokenBorrowSockets` returns patterns; `peer.Pool` resolves, orders by last-seen, evicts on transport failure, readmits on inotify/inode/`EvictProbeInterval`; `auth` borrows through `peer.Borrower`). Replace the three "watches the socket" paragraphs (headless idle, running daemon, facade) with: the pool's `Watch` fires one `OnChange` hook that the daemon points at the headless wake while idling and at the `NeedsReauth`-gated `lm.Reload()` afterwards. Add a paragraph "**Old-default migration (pre-1.0).**" summarising Task 10 in four sentences, naming `cmd/dotvault/peermigrate.go`, the exact-default rule, the version gate, and the issue.
- "Local API socket" → "Borrow order is local-first" paragraph: `config.TokenBorrowSockets()` returns `[api socket, ...peer patterns]`; the carriers are now `auth.Manager.Borrower`, `LifecycleManager.SetBorrower`, `client.VaultConfig.APISocket` + `TokenSockets`. "Direction matters": the peer actions use `config.PeerActionSockets()` and `Pool.Broadcast` (every live peer, any-success).
- "Managed SSH forwards" → Config split paragraph: `remote_socket` default `~/.ssh/dotvault.{{HOSTNAME}}.sock`, `{{HOSTNAME}}` expanded at connect time alongside `~/` (`LocalHostnameLabel`, `home.go`), other braces rejected.
- CLI paragraphs for `browse`/`notify`/`clipboard`: "posts to every live peer in the `vault.token_socket` pool (`Pool.Broadcast`, any-success)".
- Web UI routes: `/api/v1/status` bullet — add "Also carries a `peer_sockets` block (patterns, members with last-seen and eviction) via `SetPeerStatus`".
- `client/` section: `TokenSocket` → `TokenSockets`; `AuthenticateCached` borrows via the pool.

- [ ] **Step 5: Full verification**

Run: `gofmt -l . ; go vet ./... && go test ./... -race && make build-all`
Expected: no gofmt output; all PASS; all five binaries build.

- [ ] **Step 6: Commit docs**

```bash
git add docs/configuration/config-reference.md docs/guide/ssh-forwards.md CLAUDE.md client/README.md $(git diff --name-only -- '*.go')
git commit -m "docs: peer socket pool, per-host forwards, sunset issue"
```

- [ ] **Step 7: Pre-push review**

Invoke `/precommit-review`. Address `blocker`/`major` findings in fix commits (`fix(peer): address precommit review findings`), `minor`/`nit` when cheap. Re-run Step 5 after fixes.

- [ ] **Step 8: Push and open a draft PR**

```bash
git push -u origin feat/peer-socket-pool
```

Create a **draft** PR via the GitHub MCP tools (title `feat: per-workstation peer sockets and a borrow pool`), body in flowing prose covering: the race (laptop/desktop), the four design points from the spec summary, the behaviour changes (default patterns now apply when `token_socket` is absent; forwarder default renamed; `client.VaultConfig.TokenSocket` → `TokenSockets`), the not-yet-upgraded-remote caveat, and the sunset issue link. Do not mention the pre-push review. Then `subscribe_pr_activity` for it.
