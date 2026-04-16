# dotvault

Cross-platform daemon (Go) that runs in user context, authenticates to HashiCorp Vault, and synchronises KVv2 secrets into local configuration files via surgical, field-level merges.

## Build & Test

```sh
make test          # run all tests
make build         # build for current platform
make build-all     # cross-compile linux/darwin (amd64/arm64) and windows (amd64)
```

All builds use `CGO_ENABLED=0` for static binaries. Version is injected via ldflags (`-X main.version=...`).

The web frontend lives in `internal/web/frontend/` (Preact + esbuild). After changing frontend code:

```sh
cd internal/web/frontend && npm run build
```

The built assets are embedded into the binary via `embed.FS`.

## Local Development

Two-step workflow — start the infrastructure, then run the daemon with the dev config:

```sh
docker compose up -d   # starts Vault + Dex OIDC provider
go run ./cmd/dotvault run --config config.dev.yaml
```

Requires `127.0.0.1 dex` in `/etc/hosts`. Dex uses a mockCallback connector that auto-approves login. The dev Vault listens on `127.0.0.1:8200`; the dotvault web UI is configured on port 9000 (`127.0.0.1:9000`) in `config.dev.yaml` to avoid conflict.

JFrog enrolment testing is opt-in: `docker compose --profile jfrog up -d` additionally starts a local Artifactory JCR on port 8082 alongside a Postgres sidecar (required by Artifactory 7.78+). Plain `docker compose up -d` does not include them. Allow ~3 minutes on the first cold start for JFrog to finish its cluster-join. The admin account keeps the out-of-the-box `admin`/`password` credentials; Artifactory forces a password change on first UI login.

The vault-init container seeds sample secrets, enables OIDC auth via Dex, and exports the root token to `/vault/data/root-token`.

`config.dev.yaml` points at the local Vault (`http://127.0.0.1:8200`), enables the web UI on port 9000, and configures all available enrolment engines. When adding a new enrolment engine, add a corresponding entry to `config.dev.yaml` under the `enrolments` section so the dev config exercises all available engines.

### Claude Code Desktop

`.claude/launch.json` defines both services as Preview configurations so Claude Code Desktop can start them automatically, connect to the running web UI, and auto-verify changes. The two configurations mirror the manual steps above:

- **`vault-dex`** — `docker compose up` (port 8200)
- **`dotvault`** — `go run ./cmd/dotvault run --config config.dev.yaml` (port 9000)

## Architecture

```
cmd/dotvault/main.go     CLI entry point (Cobra)
internal/
  config/                Config loading: YAML file + Windows Registry (GPO)
  paths/                 OS-specific path resolution
  vault/                 Vault client wrapper, KVv2 operations, Events API (WebSocket)
  auth/                  Auth orchestration (OIDC, LDAP with MFA, token)
  sync/                  Hybrid event+poll sync engine, state store
  handlers/              File format handlers (yaml, json, ini, toml, text, netrc)
  tmpl/                  Go template rendering (named tmpl to avoid shadowing text/template)
  enrol/                 Credential acquisition via OAuth device flow
  web/                   Web UI server (Preact SPA), auth endpoints, REST API
  perms/                 File permission checks (Unix mode bits, Windows DACL)
test/integration/        Integration tests against real Vault
packaging/windows/       ADMX Group Policy template
```

## Configuration

YAML config file at platform-specific system paths:

- macOS: `/Library/Application Support/dotvault/config.yaml`
- Linux: `/etc/xdg/dotvault/config.yaml` (also checks `$XDG_CONFIG_DIRS`)
- Windows: `%ProgramData%\dotvault\config.yaml`

On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\dotvault`, configuration is loaded entirely from the registry and the file-based config is ignored. Only machine-level (HKLM) policy is read; HKCU is intentionally skipped because it is user-writable.

### Config Sections

- **`vault`** — address (required), auth_method, auth_mount, auth_role, kv_mount (default `"kv"`), user_prefix (default `"users/"`, trailing slash enforced), ca_cert, tls_skip_verify
- **`sync`** — interval as Go duration string (default `15m`)
- **`web`** — enabled (default false), listen (loopback only, hard invariant), login_text (markdown), secret_view_text (markdown)
- **`rules`** — array of sync rules (name, vault_key, target.path, target.format, target.template, target.merge)
- **`enrolments`** — map of Vault KV path segment to engine config for credential acquisition

### Config Validation

- `vault.address` is required
- At least one rule is required
- Rule names must be unique
- `target.format` must be one of: yaml, json, ini, toml, text, netrc
- `web.listen` must resolve to a loopback address if web is enabled
- Enrolment entries must have a non-empty engine field

## CLI

```
dotvault          Run daemon (default command)
dotvault run      Explicit daemon mode (same as bare invocation)
dotvault sync     One-shot sync cycle, then exit
dotvault status   Display auth state, token TTL, per-rule sync state
dotvault version  Print build version
```

Flags: `--config <path>`, `--log-level debug|info|warn|error`, `--dry-run`, `--once` (redirects to sync from within runDaemon).

Logging uses `log/slog` — text format when stderr is a TTY, JSON otherwise. Always writes to stderr; no file-based logging.

## Daemon Lifecycle

1. Load config (file or registry)
2. Create Vault client, attempt token reuse (VAULT_TOKEN env or `~/.vault-token`)
3. Start web UI if enabled (before auth, so it can serve browser-based login)
4. Authenticate if needed: web mode routes all auth through the SPA; CLI mode uses method-specific flows (OIDC browser, LDAP terminal prompt, token file)
5. Start token lifecycle manager (renews at 75% TTL, exponential backoff 1s-5m on failure)
6. Run enrolment check (wizard if any credentials missing in Vault)
7. Start sync engine: initial sync, then hybrid event+poll loop
8. Background goroutine reloads config on each tick for enrolment changes only

Config reload via SIGHUP is **not implemented**. The daemon must be fully restarted to pick up config changes (except enrolment changes, which are detected on the polling interval).

## Authentication

### Methods

- **OIDC** — Requests auth URL from Vault, opens browser, listens on random localhost port for callback, exchanges code for Vault token
- **LDAP** — Prompts for password; supports MFA (Duo push and TOTP) via the LoginTracker async state machine
- **Token** — Reads from VAULT_TOKEN env var or `~/.vault-token`

### LoginTracker

Async login state machine (`internal/auth/login.go`) shared by CLI and web paths. States: `pending` -> `mfa_required` -> `authenticated` | `failed`. The web frontend polls status; CLI polls at 500ms intervals. Session IDs are server-generated (random 32 bytes, hex-encoded).

### Token Lifecycle

`LifecycleManager` checks token TTL every 5 minutes. Renews at 75% remaining TTL. Signals re-auth needed on 403 Forbidden or token expiration. In web mode, re-auth opens the browser to the web UI root.

## Sync Engine

Hybrid event-driven + polling model (`internal/sync/`):

- **Enterprise Vault:** subscribes to `kv-v2/data-write` events via WebSocket (Events API), filters by user prefix, syncs affected rule immediately
- **Community Vault:** poll-only at configured interval
- **Graceful degradation:** if WebSocket fails, falls back to polling with exponential backoff (1s-5m)

Per-rule sync logic:
1. Read secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}`
2. Skip if vault version unchanged AND file checksum unchanged
3. Render template (if present) with Vault data map as dot context
4. Parse rendered output through handler to get incoming structured data
5. Read existing file via handler (missing file is empty state, not error; missing parent dir created at 0755)
6. Merge incoming into existing via handler
7. Write atomically (temp file + rename)
8. Update state (version, timestamp, checksum)

Per-rule isolation: one rule failing does not block others.

### State Store

Persists to `{cache_dir}/state.json`. Per-rule: vault version, last synced timestamp, SHA-256 file checksum. Atomic writes via temp file + rename.

## File Format Handlers

All handlers implement the `FileHandler` interface (Read, Merge, Write). Handlers that support templates also implement the `Parser` interface. Factory: `handlers.HandlerFor(format)`.

| Format | Library | Merge Behaviour |
|--------|---------|-----------------|
| YAML | `gopkg.in/yaml.v3` (Node-based) | Deep merge mapping nodes; preserves existing keys not in incoming |
| JSON | `encoding/json` | Recursive map merge; arrays replaced wholesale |
| INI | `gopkg.in/ini.v1` | Section + key merge; supports flat files (default section) |
| TOML | Custom parser (no external dep) | Recursive merge like JSON; supports tables, inline tables, dotted keys |
| Text | Plain string | Full replacement (no merge) — for private keys, certificates |
| Netrc | `github.com/jdx/go-netrc` | Per-entry merge by machine name; default entry skipped |

The `merge` field exists in rule config but is not dispatched on. Each handler always uses its native merge strategy, which is the only sensible strategy for that format.

All writes are atomic (temp file with target permissions + rename). Permissions: all managed files use 0600.

## Template Processing

`internal/tmpl/` wraps `text/template` with custom functions:

- `env(key)` — environment variable lookup
- `base64encode(s)` / `base64decode(s)` — credential encoding
- `default(fallback, val)` — Sprig convention (fallback first)
- `quote(s)` — shell-safe single quoting

Templates receive the Vault KV data map as dot context. The rendered output is parsed by the target format's handler to produce structured incoming data.

## Enrolment

Automated credential acquisition from external services (`internal/enrol/`). Enrolments are declared in config under a top-level `enrolments` map keyed by Vault KV path segment.

### Engine Interface

Engines implement `Name()`, `Run(ctx, settings, io)`, and `Fields()`. Registered in a package-level map. Currently implemented: GitHub (OAuth device flow), JFrog (browser-based web login), SSH (Ed25519 key generation).

### GitHub Engine Defaults

- Client ID: `178c6fc778ccc68e1d6a` (GitHub CLI's OAuth app)
- Scopes: `repo`, `read:org`, `gist`
- Host: `github.com`

Overridable via settings: `client_id`, `scopes`, `host`. Returns `{"oauth_token": "<token>", "user": "<username>"}`.

### JFrog Engine

Mirrors the `jf login` web login flow from `jfrog-cli`. No public OAuth app exists — JFrog Platform hosts its own browser login endpoint, so the engine just requires the platform URL.

Required settings:
- `url` — JFrog Platform URL (e.g. `https://mycompany.jfrog.io`)

Defaults (from the upstream `jfrog-cli-core` source, overridable via settings):
- `client_name`: `JFrog-CLI` (sent as `jfClientName` query parameter)
- `client_code`: `1` (sent as `jfClientCode` query parameter)

Flow:
1. POST `{url}/access/api/v2/authentication/jfrog_client_login/request` with a random UUID
2. Open `{url}/ui/login?jfClientSession=<uuid>&jfClientName=JFrog-CLI&jfClientCode=1` — user confirms the last 4 chars of the UUID after sign-in
3. Poll GET `{url}/access/api/v2/authentication/jfrog_client_login/token/<uuid>` until 200

Returns the full identity needed to render a `jfrog-cli.conf.v6` server entry: `{"access_token", "refresh_token", "token_type", "expires_in", "scope", "url", "server_id", "user"}`. `server_id` is deduced from the platform hostname (e.g. `mycompany.jfrog.io` → `mycompany`, IP addresses → `default-server`); `user` is extracted from the access-token JWT subject. Requires JFrog Artifactory 7.64.0 or newer on the remote side.

### SSH Engine

Generates Ed25519 key pairs in OpenSSH format. Returns `{"public_key": "<ssh-ed25519 ...>", "private_key": "<PEM>"}`. The public key comment is `{username}@dotvault`.

Passphrase mode controlled via settings `passphrase` field:
- `"required"` (default) — user must provide a passphrase; fails if empty
- `"recommended"` — user prompted but can skip
- `"unsafe"` — no passphrase (unencrypted private key)

No external dependencies beyond `golang.org/x/crypto/ssh`.

### Manager & Wizard

The Manager checks Vault for missing/incomplete secrets, then runs the Wizard for any pending enrolments. The Wizard runs engines sequentially with terminal progress display and best-effort clipboard support (pbcopy/xclip/clip.exe). On success, credentials are written to Vault KVv2, and the sync engine is triggered.

Config changes to the enrolments section are detected on each polling tick without requiring a daemon restart.

## Web UI

Preact SPA embedded via `embed.FS`. Disabled by default (`web.enabled: true` to enable). Loopback-only binding is a hard invariant — the daemon refuses to start if `web.listen` resolves to a non-loopback address.

### Routes

**Auth (not CSRF-protected where noted):**
- `GET /auth/oidc/start` — redirect to Vault OIDC auth URL
- `GET /auth/oidc/callback` — handle OIDC callback
- `POST /auth/ldap/login` — start async LDAP login (CSRF-protected)
- `GET /auth/ldap/status` — poll login status
- `POST /auth/ldap/totp` — submit TOTP passcode (CSRF-protected)
- `POST /auth/token/login` — validate and set token (CSRF-protected)

**API:**
- `GET /api/v1/csrf` — issue CSRF token (one-time use, max 1000 in memory)
- `GET /api/v1/status` — server status (auth, vault version, token TTL, sync state, vault address, kv_mount, user_prefix, username)
- `GET /api/v1/rules` — configured sync rules
- `GET /api/v1/secrets/{path}` — list or reveal secret (reveal requires `?reveal=true`)
- `POST /api/v1/sync` — trigger immediate sync (CSRF-protected)

**Security headers:** `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff`.

Configurable markdown content via `web.login_text` and `web.secret_view_text` fields rendered by `internal/web/markdown.go`.

## Windows Registry / Group Policy

When HKLM registry keys exist at `SOFTWARE\Policies\dotvault`, the daemon loads all config from registry and ignores the YAML file. The `registryLayer` struct reads Vault, Sync, and Web settings from typed subkeys (REG_SZ, REG_DWORD). Rules are subkeys under `Rules\{RuleName}` with an optional `OAuth` subkey.

ADMX template at `packaging/windows/dotvault.admx` defines Group Policy UI for Vault, Sync, and Web settings.

## File Permissions & Security

- Managed files (all sync rule targets): written at 0600
- Token file (`~/.vault-token`): written at 0600, warns if permissions differ
- Config file: warns if group or world writable
- Secret values are never logged, even at DEBUG level
- All file writes are atomic (temp file + rename)
- Web UI: loopback only, CSRF on all mutating endpoints, strict CSP
- Windows: DACL-based permission checks via Security API (GetNamedSecurityInfo, GetAce)

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/hashicorp/vault/api` | Vault client SDK |
| `github.com/spf13/cobra` | CLI framework |
| `gopkg.in/yaml.v3` | YAML parsing (Node-level) |
| `gopkg.in/ini.v1` | INI parsing |
| `github.com/jdx/go-netrc` | Netrc parsing |
| `github.com/cli/oauth` | GitHub OAuth device flow |
| `github.com/pkg/browser` | Open browser |
| `nhooyr.io/websocket` | WebSocket client (Vault Events API) |
| `golang.org/x/term` | Secure terminal input |
| `golang.org/x/sys` | OS-specific syscalls (Windows registry, etc.) |

All pure Go. No CGO dependencies.

## Testing

- **Unit tests** per package with fixture files and table-driven tests
- **Integration tests** in `test/integration/` against a real Vault dev server (via docker-compose)
- Engine interface allows mock injection for enrolment tests without real OAuth providers
- `go test ./...` runs all unit tests; integration tests require the docker-compose environment
