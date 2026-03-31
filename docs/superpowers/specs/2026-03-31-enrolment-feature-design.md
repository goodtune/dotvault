# Enrolment Feature Design

Automatic credential acquisition from external services via OAuth device flow, with secrets stored in Vault KVv2.

## Problem

When a user has no secrets in Vault, they must manually obtain credentials from external services (e.g. GitHub OAuth tokens) and write them into Vault. This is error-prone and undiscoverable. Enrolment automates this by running provider-specific auth flows and writing the results directly into Vault.

## Configuration

Enrolments are declared in the dotvault config file under a top-level `enrolments` map. The map key is the Vault KV path segment (relative to `kv/<user_prefix>/`), preventing duplicates by definition.

```yaml
enrolments:
  gh:
    engine: github
  gitlab:
    engine: gitlab
    settings:
      host: "gitlab.example.com"
      scopes:
        - api
        - read_user
```

### Config Types

```go
type Config struct {
    Vault      VaultConfig
    Sync       SyncConfig
    Web        WebConfig
    Rules      []Rule
    Enrolments map[string]Enrolment `yaml:"enrolments"`
}

type Enrolment struct {
    Engine   string         `yaml:"engine"`
    Settings map[string]any `yaml:"settings"`
}
```

Each engine defines which settings keys it recognises. Unknown keys are ignored. The `engine` field is required; `settings` is optional.

## Architecture

New package `internal/enrol/` with four files:

- **engine.go** — Engine interface and registry
- **manager.go** — Orchestrates enrolment checks and the wizard
- **wizard.go** — Sequential wizard with progress tracking
- **github.go** — GitHub device-flow engine

### Engine Interface

```go
// Engine obtains credentials from an external service.
type Engine interface {
    // Name returns a human-readable provider name for display (e.g. "GitHub").
    Name() string

    // Run executes the credential acquisition flow.
    // settings is the engine-specific config bag from YAML.
    // Returns field→value pairs to write into Vault KVv2.
    Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error)

    // Fields returns the Vault KV field names this engine writes.
    // Used to check whether enrolment is already complete.
    Fields() []string
}

// BrowserOpener opens a URL in the user's default browser.
type BrowserOpener func(url string) error

// IO provides user interaction capabilities to engines.
type IO struct {
    Out     io.Writer
    Browser BrowserOpener
    Log     *slog.Logger
}
```

Engines are registered in a package-level map:

```go
var engines = map[string]Engine{
    "github": &GitHubEngine{},
}

func GetEngine(name string) (Engine, bool)
```

### GitHub Engine

Uses `github.com/cli/oauth` for the OAuth device flow. Reuses the GitHub CLI's OAuth app credentials as defaults.

**Defaults (from github-cli):**
- Client ID: `178c6fc778ccc68e1d6a`
- Scopes: `repo`, `read:org`, `gist`
- Host: `github.com`

**Overridable settings (implemented):**
- `client_id` — OAuth app client ID
- `scopes` — list of OAuth scopes
- `host` — GitHub hostname (for GHES); accepts bare hostname or full URL with scheme

**Future work (not in this PR):**
- `client_secret` — OAuth app client secret (needed for non-device-flow apps)

**Returns:** `{"oauth_token": "<token>", "user": "<username>"}`

The engine fetches the authenticated username via GitHub's API after obtaining the token, same as github-cli does.

### Manager

The Manager holds the enrolment config, a Vault client, Vault path parameters, and IO handles. It exposes:

```go
func NewManager(cfg ManagerConfig, vault *vault.Client, io IO) *Manager
func (m *Manager) CheckAll(ctx context.Context) (enrolled bool, err error)
func (m *Manager) UpdateConfig(enrolments map[string]Enrolment)

type ManagerConfig struct {
    Enrolments map[string]Enrolment
    KVMount    string // from cfg.Vault.KVMount (e.g. "kv")
    UserPrefix string // from cfg.Vault.UserPrefix (e.g. "users/jdoe")
}
```

`CheckAll` returns `enrolled=true` if any new enrolments were completed (so main.go knows to trigger sync). It does:

1. For each enrolment, read Vault KVv2 at `<KVMount>/<UserPrefix>/<key>`.
2. Check whether all fields from `engine.Fields()` are present.
3. Collect enrolments that are missing or incomplete.
4. If any are pending, run the wizard.

`UpdateConfig` replaces the enrolment map (called when config changes are detected).

### Wizard

The wizard presents enrolments sequentially with progress tracking:

```
dotvault: checking enrolments...
  ○ gh (GitHub) — missing
  ○ gitlab (GitLab) — missing

Enrolment [1/2]: GitHub
! First, copy your one-time code: ABCD-1234
- Press Enter to open github.com in your browser...
✓ Opened https://github.com/login/device in browser
⠼ Waiting for authentication...

✓ gh (GitHub) — enrolled as @octocat

Enrolment [2/2]: GitLab
...
```

**Clipboard support:**
- The device code is auto-copied to the clipboard on display (best-effort).
- macOS: `pbcopy`, Windows: `clip.exe`, Linux: `xclip`/`xsel`.
- If no clipboard tool is available, the wizard silently continues (best-effort only).
- Web UI: click-to-copy button via `navigator.clipboard.writeText()` — future work, not implemented in this PR.

**On success:** writes credentials to Vault immediately, marks as done in progress display.

**On failure:** logs error, skips to next enrolment. Failed enrolments retry on the next cycle.

**On context cancellation:** stops the wizard. Already-completed enrolments are preserved in Vault.

### Web UI Integration (future work, not implemented in this PR)

When web mode is active, the wizard would push enrolment state to the web UI in addition to terminal output. The web UI would display a banner with:

- The current engine name and progress (e.g. "1 of 2")
- The device code prominently displayed with a click-to-copy button
- A progress indicator showing completed/current/pending enrolments

## Orchestration

`main.go` orchestrates the enrolment lifecycle. Enrolment is **not** part of the sync engine — it runs before/between sync cycles.

### Startup

```
1. Load config
2. Authenticate to Vault (OIDC/LDAP/token)
3. Create enrolment manager
4. Run enrolment check (wizard if needed)
5. Trigger initial sync
6. Enter poll loop
```

### Poll Loop

On each tick (same interval as sync), main.go:

1. Reloads config from disk. (This is new behaviour — the existing sync loop does not currently reload config. The config reload must be added as part of this feature.)
2. If enrolments config has changed, updates the manager and runs `CheckAll`.
3. If `CheckAll` returned `enrolled=true`, triggers sync.
4. Runs normal sync cycle.

This means enrolment is evaluated at startup and on every poll interval, catching both missing secrets and config changes.

## Data Flow

```
Config change or startup
  → Manager.CheckAll()
    → Read Vault KVv2 for each enrolment key
    → Filter to missing/incomplete
    → Wizard runs each pending engine sequentially
      → Engine.Run() performs device flow
      → User authenticates in browser
      → Engine returns map[string]string
    → Manager writes fields to Vault KVv2
  → main.go calls syncEngine.TriggerSync()
  → Sync engine reads Vault, writes local files
```

## Error Handling

| Failure Mode | Behaviour |
|---|---|
| Unknown engine in config | Log error at startup, skip this enrolment, continue others |
| Device flow timeout | Engine returns error, wizard skips to next, retries next cycle |
| Device flow denied by user | Same as timeout |
| Vault write failure after token obtained | Log error (not the token), token is lost, re-enrol next cycle |
| Vault unreachable during check | Skip enrolment checks entirely, normal sync also fails so lifecycle manager handles it |
| Context cancelled (SIGINT) | Wizard stops, completed enrolments preserved in Vault |
| Clipboard unavailable | Best-effort fallback message, wizard continues |

## Dependencies

**New:**
- `github.com/cli/oauth` — OAuth device flow implementation (same package used by github-cli)

**Clipboard:** shell out to `pbcopy`/`xclip`/`clip.exe` (zero additional Go dependencies, same approach as github-cli via go-gh).

**Existing (already in go.mod):**
- `github.com/hashicorp/vault/api` — Vault KVv2 reads/writes
- `github.com/pkg/browser` — open verification URL in browser
- `log/slog` — structured logging

## Testing Strategy

### Unit Tests

**`internal/enrol/manager_test.go`:**
- CheckAll with all secrets present: no engines run
- CheckAll with missing secrets: correct engines called
- Config change detection triggers re-check
- Vault write after successful engine run
- Partial failure: one engine fails, others succeed

**`internal/enrol/github_test.go`:**
- Settings merge: defaults used when no overrides
- Settings merge: overrides replace defaults
- Fields() returns expected field names

**`internal/enrol/wizard_test.go`:**
- Progress display for N enrolments
- Skips already-complete enrolments
- Continues after individual engine failure
- Context cancellation stops wizard

**`internal/config/config_test.go`:**
- Parse enrolments section from YAML
- Missing engine field: validation error
- Empty enrolments map: no error

### Integration Tests

**`test/integration/enrol_test.go`:**
- Mock OAuth server simulating the device flow protocol (device code endpoint + token endpoint with auto-approve)
- Full flow: check Vault → engine runs → Vault written → sync triggered
- Uses real Vault dev server (same as existing e2e tests)
- Verifies correct client_id and scopes sent to OAuth server

The Engine interface makes unit testing straightforward: inject a mock engine that returns canned credentials without hitting any real OAuth provider.
