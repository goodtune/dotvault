# dotvault Implementation Design

## Scope

Implement the dotvault specification (phases 1, 2, 4), deferring phase 3 (service install/uninstall). This covers:

- Core daemon: config, paths, vault client, sync engine, file handlers, template processing, CLI
- Auth flows: token reuse, OIDC, LDAP, token lifecycle
- Web UI: secret browser, OAuth2 dance orchestration, Preact SPA

## Build Approach

Bottom-up layers. Build foundational packages first, compose upward. Each layer independently testable. Integration tests hit a real Vault dev server.

## Design Decisions (from spec section 18)

| Decision | Choice |
|----------|--------|
| Netrc `default` entry | Skip — leave untouched |
| Multiple KV mounts | KVv2 only. All keys under `{user_prefix}{username}/`. Prefix configurable (default `"users/"`) |
| File locking | No advisory locks. Atomic rename for crash safety. |
| OAuth2 provider registry | Require explicit URLs in config. No built-in provider knowledge. |
| Web UI access logging | Log secret reveal requests at INFO level. |
| Web UI frontend framework | Preact (via esbuild, embedded with `embed.FS`) |
| Change detection | Hybrid: Vault Events API (WebSocket) primary, polling as fallback |

---

## 1. Config & Paths

### `internal/paths`

Thin helper returning OS-appropriate directories. Uses `runtime.GOOS` switch, `os.UserHomeDir()`, `os.UserConfigDir()`.

Exported functions:
- `SystemConfigPath() string` — system config file path
- `CacheDir() string` — cache/state directory
- `LogDir() string` — log directory
- `VaultTokenPath() string` — `~/.vault-token` equivalent
- `ExpandHome(path string) (string, error)` — tilde expansion for rule target paths

Fallback: check `$XDG_CONFIG_DIRS` entries on Linux if primary system config path is absent.

### `internal/config`

Parses the system YAML config into Go structs. Uses `gopkg.in/yaml.v3`.

Key addition to the spec's config schema — configurable user prefix:

```yaml
vault:
  address: "https://vault.example.com:8200"
  kv_mount: "kv"
  user_prefix: "users/"   # configurable, defaults to "users/"
```

Full KV path: `{kv_mount}/data/{user_prefix}{username}/{vault_key}`.

Config struct covers: vault connection, auth settings, sync interval, web UI settings, rules list.

Validation at load time:
- Required fields present (`vault.address`, at least one rule)
- `sync.interval` parseable as `time.Duration`
- `web.listen` is loopback if `web.enabled` is true
- Rule names unique, target formats are one of: `yaml`, `json`, `ini`, `netrc`

---

## 2. Vault Client & Auth

### `internal/vault`

Wraps `github.com/hashicorp/vault/api`. Thin layer:

- `NewClient(cfg config.Vault) (*Client, error)` — creates API client from config (address, CA cert, TLS skip verify)
- `ReadKVv2(mount, path string) (*Secret, error)` — reads a KVv2 secret, returns data map + version metadata
- `ListKVv2(mount, path string) ([]string, error)` — lists keys under a path (for web UI secret browser)
- `SubscribeEvents(ctx context.Context, eventType string) (<-chan Event, error)` — WebSocket subscription to Vault Events API

### `internal/auth`

Orchestrates authentication. Four files:

**`token.go`** — Token reuse:
1. Read `~/.vault-token` or `VAULT_TOKEN` env var
2. `auth/token/lookup-self` to validate
3. Valid and not expired → use it
4. Within renewable window → renew
5. Invalid/expired → proceed to fresh auth
6. Write new tokens to `~/.vault-token` with 0600 permissions

**`oidc.go`** — OIDC flow:
1. Local HTTP listener on random high port (callback URL)
2. Build auth URL via Vault API (`auth/{mount}/oidc/auth_url`)
3. Open system browser (`github.com/pkg/browser`)
4. Receive callback, extract authorization code
5. Exchange for Vault token via API
6. Write token to `~/.vault-token`

**`ldap.go`** — LDAP flow:
1. Prompt for password via `golang.org/x/term` (secure TTY input)
2. `auth/ldap/login/<username>` via Vault API
3. Write token to `~/.vault-token`

**`lifecycle.go`** — Token lifecycle goroutine:
- Periodically check token TTL
- Renew at 75% of TTL if renewable
- On renewal failure, trigger re-auth
- Exponential backoff on re-auth failure (1s → 2s → 4s → ... max 5m)
- Exposes notification mechanism (channel/callback) for sync engine to know auth state

**Username resolution:** `os/user` → `user.Current().Username`, strip domain prefix (everything before and including `\`). Stored on the auth manager for path construction.

---

## 3. Template Processing & File Handlers

### `internal/template`

Wraps `text/template`. Parses a rule's template string, executes with Vault KV data map as dot context.

Custom template functions:
- `env` — read environment variable: `{{env "HOME"}}`
- `base64encode` / `base64decode` — credential encoding
- `default` — fallback value: `{{default .foo "bar"}}`
- `quote` — shell-safe quoting

Returns rendered string, parsed by the appropriate file handler to produce structured "incoming" data.

### `internal/handlers`

Interface:

```go
type FileHandler interface {
    Read(path string) (any, error)
    Merge(existing any, incoming any) (any, error)
    Write(path string, data any, perm os.FileMode) error
}
```

`perm` parameter on `Write` so caller controls file permissions (0600 for netrc, 0644 for others). Write always through temp file + `os.Rename` for atomicity.

Factory: `HandlerFor(format string) (FileHandler, error)` maps format string to handler.

**YAML handler** (`yaml.go`):
- Uses `yaml.Node` tree for read/write (preserves comments, ordering)
- Deep merge walks mapping nodes: add/update keys from incoming, never remove existing keys

**JSON handler** (`json.go`):
- `map[string]any` via `encoding/json`
- Recursive map merge, arrays replaced wholesale
- `MarshalIndent` with 2-space indent, preserve trailing newline convention

**INI handler** (`ini.go`):
- `gopkg.in/ini.v1`
- Line-replace merge: find matching key in correct section, replace value. Missing keys appended.
- Flat files (`.npmrc`) treated as default section
- Preserves comments and section ordering

**Netrc handler** (`netrc.go`):
- Uses `github.com/jdx/go-netrc` for parse/serialize
- Per-entry merge: match on machine name, update login+password if found, add new machine if not
- Existing entries not in Vault data left untouched
- Skip `default` entry entirely
- Preserves ordering, new entries appended at end

---

## 4. Sync Engine

### `internal/sync`

**`state.go`** — manages `~/.cache/dotvault/state.json`:

```json
{
  "rules": {
    "gh": {
      "vault_version": 3,
      "last_synced": "2026-03-27T10:00:00Z",
      "file_checksum": "sha256:abcdef..."
    }
  }
}
```

Load/save with process-internal mutex. Checksum is sha256 of target file's full contents.

**`engine.go`** — hybrid event-driven + polling sync:

Three internal modes:
- **Event-driven** (WebSocket connected): reacts to `kv-v2/data-write` events, polls at fallback interval as safety net
- **Poll-only** (graceful degradation): if WebSocket fails to connect or disconnects
- **Transitions logged at INFO level**, transparent to user

Per-cycle logic (whether triggered by event or poll):
1. Read secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}`
2. Compare secret version to state — unchanged? skip
3. Render template (if rule has one) with Vault data map
4. Parse rendered output through file handler to get incoming structured data
5. Read existing target file via handler. Missing file → empty state (not error). Missing parent dir → create (0755).
6. Compute current file checksum. Mismatch with state → log warning (external modification) but proceed
7. Merge incoming into existing via handler
8. Write result via handler (atomic rename). Permissions: 0600 for netrc, 0644 for others
9. Update state: vault version, timestamp, checksum of written file

WebSocket management:
- Connect to Vault Events API, subscribe to `kv-v2/data-write`
- Filter events by path prefix (`{user_prefix}{username}/`)
- Match event path to configured rules, trigger sync for affected rule only
- Reconnect with exponential backoff (1s → 5m cap) on disconnect
- Fall back to poll-only if WebSocket unavailable

Exposes:
- `RunOnce(ctx) error` — single sync cycle (for `dotvault sync` CLI command)
- `RunLoop(ctx) error` — daemon mode with hybrid event/poll
- `TriggerSync()` — immediate sync (for web UI "Sync Now" button)

Error handling: per-rule isolation. One rule failing doesn't block others. Vault unreachable → log error, skip cycle, retry next interval.

---

## 5. CLI

### `cmd/dotvault/main.go`

Uses `github.com/spf13/cobra`.

| Command | Behaviour |
|---------|-----------|
| `dotvault` / `dotvault run` | Start daemon: auth → WebSocket connect → sync loop. Foreground. Optionally start web UI. |
| `dotvault sync` | Run one sync cycle and exit. Also `--once` flag alias. |
| `dotvault status` | Print auth state, token TTL, last sync times per rule, event subscription status, errors. |
| `dotvault version` | Print version + build info (injected via ldflags). |

Global flags:
- `--config <path>` — override system config path
- `--log-level <level>` — debug, info, warn, error (default: info)
- `--dry-run` — show what would change without writing files

Logging (`log/slog`):
- JSON when stderr is not a TTY, text when it is
- Default output: stderr
- Structured fields: rule name, vault path, action taken, etc.

Signal handling:
- SIGTERM/SIGINT → cancel context → finish current write → exit
- SIGHUP → reload config (re-parse YAML, restart sync loop with new rules/interval, reconnect WebSocket if address changed)

---

## 6. Web UI

### `internal/web`

Disabled by default. Enabled via `web.enabled: true`. Always localhost-only (hard failure on non-loopback).

**`server.go`** — HTTP server setup:
- Validate `web.listen` resolves to loopback before binding (exit code 1 if not)
- Middleware: `Content-Security-Policy: default-src 'self'`, CSRF token validation on mutating endpoints
- Serve embedded SPA via `embed.FS` at `/`
- If port in use: log error, disable web UI, daemon continues without it

**`api.go`** — JSON REST handlers:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/csrf` | Issue CSRF token |
| `GET` | `/api/v1/status` | Auth state, token TTL, last sync, event subscription status, per-rule state |
| `GET` | `/api/v1/rules` | Configured rules + current sync state |
| `GET` | `/api/v1/secrets/` | List keys at user's KV root |
| `GET` | `/api/v1/secrets/{path}` | Field names + metadata (no values) |
| `GET` | `/api/v1/secrets/{path}?reveal=true` | Field names + decrypted values (logged at INFO) |
| `POST` | `/api/v1/sync` | Trigger immediate sync. CSRF required. |

Secret reveal is a deliberate separate call. List responses never include values.

**`oauth.go`** — OAuth2 dance for rules with `oauth` block:
- `GET /api/v1/oauth/{rule}/start` — generate cryptographically random state (stored server-side), build auth URL from Vault engine config, redirect browser to IdP
- `GET /api/v1/oauth/callback` — validate state, exchange code via Vault engine API, store credential
- Invalid state → 400 + log warning
- Exchange failure → log error, show failure in UI, rule stays "pending OAuth"

**`static/`** — Preact SPA:
- Built via `go generate` using esbuild
- Embedded into binary with `embed.FS`
- **Left sidebar:** tree/list of KV keys, expandable file-browser style
- **Main panel:** field table with masked values, eye-icon reveal toggle, auto-hide after 30 seconds
- **Top bar:** status indicator (connected/disconnected/auth required), last sync time, event subscription status, "Sync Now" button
- **Alert banners:** rules in "pending OAuth" state with "Authorize" button

Build tooling: `package.json` with Preact + esbuild. `go generate` command in `web/` package runs the JS build.

---

## 7. Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/hashicorp/vault/api` | Vault client SDK |
| `gopkg.in/yaml.v3` | YAML parsing with node-level access |
| `gopkg.in/ini.v1` | INI file parsing |
| `github.com/jdx/go-netrc` | Netrc file parsing |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/pkg/browser` | Open browser for OIDC flow |
| `golang.org/x/term` | Secure TTY password input for LDAP |
| `nhooyr.io/websocket` | WebSocket client for Vault Events API subscription |
| `log/slog` (stdlib) | Structured logging |
| `text/template` (stdlib) | Template rendering |
| `encoding/json` (stdlib) | JSON handling |
| `os/user` (stdlib) | Current user identity |
| `crypto/sha256` (stdlib) | File checksum for change detection |
| `net/http` (stdlib) | Web UI HTTP server |
| `embed` (stdlib) | Embed SPA static assets |

All pure Go. No CGO dependencies. `CGO_ENABLED=0` for static binaries.

---

## 8. Testing Strategy

| Layer | Approach |
|-------|----------|
| File handlers | Unit tests with fixture files for each format. Test read → merge → write round-trips. Verify unmanaged content preserved. |
| Template rendering | Unit tests with sample Vault data maps. |
| Config parsing | Unit tests with valid/invalid YAML configs. |
| Vault integration | Integration tests against dev Vault server (`http://127.0.0.1:8200`). Test KVv2 reads, auth, token refresh, event subscription. |
| Sync engine | Integration tests with real Vault + temp file trees. Verify correct files created/updated. Test event-driven and poll-only modes. |
| Netrc handler | Unit tests: parse → merge → write with edge cases (comments, blank lines, multiple machines). |
| Web UI API | Unit tests for each endpoint. Test loopback enforcement. Test CSRF validation. Test reveal vs list responses. |
| OAuth flow | Integration test with mock IdP: start flow, simulate callback, verify exchange. Test invalid state rejection. |

---

## 9. Project Structure

```
dotvault/
├── cmd/
│   └── dotvault/
│       └── main.go              # Entry point, CLI (cobra)
├── internal/
│   ├── config/
│   │   └── config.go            # YAML config parsing & validation
│   ├── paths/
│   │   └── paths.go             # OS-specific path resolution
│   ├── auth/
│   │   ├── auth.go              # Auth orchestrator
│   │   ├── token.go             # Token read/write/refresh
│   │   ├── oidc.go              # OIDC flow
│   │   ├── ldap.go              # LDAP auth
│   │   └── lifecycle.go         # Token lifecycle goroutine
│   ├── vault/
│   │   └── client.go            # Vault API wrapper, KVv2 reads, event subscription
│   ├── sync/
│   │   ├── engine.go            # Hybrid event/poll sync loop
│   │   └── state.go             # State file management
│   ├── handlers/
│   │   ├── handler.go           # FileHandler interface + factory
│   │   ├── yaml.go
│   │   ├── json.go
│   │   ├── ini.go
│   │   └── netrc.go
│   ├── template/
│   │   └── template.go          # Go template rendering with custom funcs
│   ├── web/
│   │   ├── server.go            # HTTP server, loopback validation, middleware
│   │   ├── api.go               # JSON REST API handlers
│   │   ├── oauth.go             # OAuth2 flow handlers
│   │   └── static/              # Embedded Preact SPA (built via go generate)
│   │       ├── index.html
│   │       ├── app.js
│   │       └── style.css
│   └── web/
│       ├── frontend/             # Preact source (not embedded — built output goes to static/)
│       │   ├── package.json
│       │   ├── src/
│       │   │   ├── index.jsx
│       │   │   ├── components/
│       │   │   └── ...
│       │   └── esbuild.config.js
├── go.mod
├── go.sum
└── Makefile
```

---

## 10. Security

- Token file `~/.vault-token` always 0600. Warn if permissions differ.
- System config: warn if user-writable.
- Never log secret values, even at DEBUG. Log paths and field names only.
- Atomic file writes via temp file + `os.Rename`.
- SIGTERM/SIGINT: finish current write, then exit. SIGHUP: reload config.
- Web UI: loopback-only (hard invariant), CSRF on mutating endpoints, strict CSP.
- OAuth state: cryptographically random, stored server-side, validated on callback.
