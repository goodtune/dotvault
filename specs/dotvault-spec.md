# dotvault: Vault-to-File Secret Synchronisation Daemon

## Project Summary

A cross-platform background service (daemon) written in **Go** that runs in user context, authenticates to HashiCorp Vault, and performs one-way synchronisation of KVv2 secrets into local configuration files. It performs surgical, field-level edits to target files — never full overwrites — guided by a system-managed configuration file.

---

## 1. Language & Toolchain

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Go 1.22+ | First-class Vault SDK (`github.com/hashicorp/vault/api`), excellent cross-compilation, single binary output, strong stdlib for file I/O |
| Build | `go build` with `GOOS`/`GOARCH` | Native cross-compilation to all targets |
| Module name | `github.com/goodtune/dotvault` | Placeholder — adjust to actual repo |

### Target Platforms

| OS | Arch | Min Version | Binary Name |
|----|------|-------------|-------------|
| Linux | amd64, arm64 | RHEL 8+ (glibc 2.28) | `dotvault` |
| macOS | amd64, arm64 | 13 Ventura+ | `dotvault` |
| Windows | amd64 | Windows 11 | `dotvault.exe` |

Build with `CGO_ENABLED=0` to produce fully static binaries on Linux.

---

## 2. Directory & File Conventions

All paths must be resolved using OS-appropriate conventions. Use a helper package (e.g. `internal/paths`) that wraps the logic below.

### 2.1 System Configuration (read-only, admin-managed)

| OS | Path |
|----|------|
| Linux | `/etc/xdg/dotvault/config.yaml` |
| macOS | `/Library/Application Support/dotvault/config.yaml` |
| Windows | `C:\ProgramData\dotvault\config.yaml` |

Fallback: also check for the file at `$XDG_CONFIG_DIRS` entries on Linux if the primary path is absent.

### 2.2 User Runtime Data (daemon-managed)

| Purpose | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Cache / state | `~/.cache/dotvault/` | `~/Library/Caches/dotvault/` | `%LOCALAPPDATA%\dotvault\cache\` |
| Logs | `~/.cache/dotvault/logs/` | `~/Library/Logs/dotvault/` | `%LOCALAPPDATA%\dotvault\logs\` |
| Vault token | `~/.vault-token` (standard) | `~/.vault-token` | `%USERPROFILE%\.vault-token` |

### 2.3 User Identity

The daemon resolves the current OS username (Go `os/user` package → `user.Current().Username`). On systems with domain prefixes (e.g. `DOMAIN\gary`), strip the prefix. This username is used to construct the Vault KV path prefix: `users/<username>/`.

---

## 3. System Configuration Schema

The system config file is YAML. It defines the Vault connection and a list of **sync rules**.

```yaml
# /etc/xdg/dotvault/config.yaml

vault:
  address: "https://vault.example.com:8200"
  # Optional: CA certificate path for TLS verification
  ca_cert: "/etc/pki/tls/certs/vault-ca.pem"
  # Optional: skip TLS verify (development only)
  tls_skip_verify: false
  # KVv2 mount path
  kv_mount: "kv"
  # Auth method to use if no token exists.
  # Supported: "oidc", "ldap", "token" (manual)
  auth_method: "oidc"
  # Optional: Vault role for OIDC auth
  auth_role: ""
  # Optional: OIDC mount path if non-default
  auth_mount: "oidc"

sync:
  # How often to poll Vault for changes (duration string)
  interval: "5m"

# Web UI — disabled by default. Must be explicitly enabled.
# Intended for end-user workstations, NOT servers.
web:
  enabled: false
  # Listen address. Always localhost-only.
  listen: "127.0.0.1:8200"

rules:
  - name: gh
    description: "GitHub CLI token"
    # Vault KV key name, appended to users/<username>/
    vault_key: "gh"
    target:
      # Path to the file to manage. Supports ~ expansion.
      path: "~/.config/gh/hosts.yml"
      # File format: yaml, json, ini, netrc
      format: yaml
      # Template for the data to merge into the file.
      # Uses Go text/template syntax.
      # Dot context is the Vault KV data map.
      template: |
        github.com:
          oauth_token: "{{.token}}"
          user: "{{.user}}"
          git_protocol: https
      # Merge strategy: "deep" (default) — deep-merge into existing file
      # For YAML/JSON: recursive merge at the key level
      merge: deep

  - name: netrc
    description: "Machine credentials for .netrc"
    vault_key: "netrc"
    target:
      path: "~/.netrc"
      format: netrc
      # For netrc format, no template is needed.
      # Each Vault KV field key = machine name
      # Each value = JSON object with "login" and "password" keys.
      # Entries not present in Vault data are left untouched.
      merge: per-entry

  - name: npm
    description: "NPM registry token"
    vault_key: "npm"
    target:
      path: "~/.npmrc"
      format: ini
      template: |
        //registry.npmjs.org/:_authToken={{.token}}
      merge: line-replace

  - name: docker
    description: "Docker registry credentials"
    vault_key: "docker"
    target:
      path: "~/.docker/config.json"
      format: json
      template: |
        {
          "auths": {
            "{{.registry}}": {
              "auth": "{{.auth}}"
            }
          }
        }
      merge: deep
```

---

## 4. Vault Authentication

### 4.1 Token Reuse

On startup, check for an existing Vault token:

1. Read `~/.vault-token` (or `VAULT_TOKEN` env var).
2. Call `auth/token/lookup-self` to validate it.
3. If valid and not expired → use it.
4. If within the renewable window → renew it.
5. If invalid/expired → proceed to fresh authentication.

### 4.2 OIDC Authentication Flow

When `auth_method: oidc`:

1. Use the Vault API client to initiate OIDC auth (`auth/<mount>/oidc/auth_url`).
2. Open a local HTTP listener on a random high port (callback URL).
3. Launch the system browser with the auth URL (use `github.com/pkg/browser` or equivalent).
4. Receive the callback, extract the authorization code.
5. Exchange for a Vault token via the Vault API.
6. Write the token to `~/.vault-token`.

### 4.3 LDAP Authentication

When `auth_method: ldap`:

1. Prompt for password via a platform-appropriate secure input (TTY if available, or system credential prompt).
2. Authenticate via `auth/ldap/login/<username>`.
3. Write the token to `~/.vault-token`.

**Note:** Since this is a background service, LDAP is a fallback. OIDC is the primary expected method.

### 4.4 Token Lifecycle

- Maintain a goroutine that periodically checks token TTL.
- If the token is renewable, renew it at 75% of its TTL.
- If the token cannot be renewed, trigger re-authentication.
- On re-authentication failure, log the error and retry with exponential backoff (max 5 minutes).

---

## 5. Sync Engine

### 5.1 Polling Loop

```
loop:
  for each rule in config.rules:
    1. Read secret from Vault: GET kv/data/users/<username>/<rule.vault_key>
    2. Compare secret version to last-known version (stored in cache)
    3. If unchanged → skip
    4. If changed → invoke the appropriate file writer
    5. Update cached version metadata
  sleep(config.sync.interval)
```

### 5.2 Version Tracking

Store sync state in the cache directory:

```
~/.cache/dotvault/state.json
```

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

Before writing, also compute the current file checksum. If the file has been modified locally since last sync (checksum mismatch), log a warning but still overwrite the managed fields only — never the entire file.

### 5.3 File Writing Strategy

**Critical invariant:** The daemon must never truncate or fully overwrite a target file. It must read the existing file (if present), apply only the changes dictated by the rule, and write the result back. If the file does not exist, create it with only the content from the rule.

Set file permissions on creation:
- `.netrc`: `0600`
- All others: `0644`
- Windows: rely on default user ACLs

---

## 6. File Format Handlers

Each handler implements the same interface:

```go
type FileHandler interface {
    // Read parses the target file. Returns structured data.
    // If the file doesn't exist, returns empty/zero state (not an error).
    Read(path string) (any, error)
    
    // Merge takes existing data + new data from template/vault and returns merged result.
    Merge(existing any, incoming any) (any, error)
    
    // Write serialises the merged data back to the file.
    Write(path string, data any) error
}
```

### 6.1 YAML Handler

- Library: `gopkg.in/yaml.v3`
- Read: parse into `yaml.Node` tree (preserves comments and ordering).
- Merge (deep): walk both trees; for mapping nodes, add/update keys from incoming into existing. Do not remove keys from existing that are absent in incoming.
- Write: serialise from `yaml.Node` to preserve original formatting as much as possible.

**Example — gh rule:**

Existing `~/.config/gh/hosts.yml`:
```yaml
github.com:
  oauth_token: "old-token"
  user: gary
  git_protocol: https
github.example.com:
  oauth_token: "enterprise-token"
  user: gary
```

After sync (only `github.com` block updated, `github.example.com` untouched):
```yaml
github.com:
  oauth_token: "new-token-from-vault"
  user: gary
  git_protocol: https
github.example.com:
  oauth_token: "enterprise-token"
  user: gary
```

### 6.2 JSON Handler

- Library: `encoding/json`
- Read: parse into `map[string]any`.
- Merge (deep): recursive merge of maps. Incoming keys overwrite existing keys at the same path. Arrays are replaced wholesale (not merged element-by-element).
- Write: marshal with `json.MarshalIndent` (2-space indent). If the file existed, attempt to preserve trailing newline convention.

### 6.3 INI Handler

- Library: `gopkg.in/ini.v1`
- Read: parse into INI sections/keys.
- Merge (line-replace): for each key=value in the incoming data, find and replace the matching key in the correct section. If the key doesn't exist, append it to the appropriate section.
- Write: serialise back, preserving comments and section ordering.

For flat files like `.npmrc` (no sections), treat as the default/global section.

### 6.4 Netrc Handler

Custom parser required (Go stdlib does not have one). Use or vendor a simple netrc parser.

**Data model:**
```go
type NetrcEntry struct {
    Machine  string
    Login    string
    Password string
    // Preserve any other fields (account, macdef, etc.)
    Extra    []string
}
```

**Merge (per-entry):**

Given Vault data where each KV field key is a machine name and its value is a JSON object:

```json
{
  "api.github.com": {"login": "goodtune", "password": "ghx_proxyToken"},
  "example.com": {"login": "gary", "password": "hunter2"}
}
```

1. Parse existing `.netrc` into a list of entries.
2. For each Vault entry:
   - If a matching `machine` exists → update `login` and `password`.
   - If no match → append a new entry.
3. Existing entries NOT in Vault data → leave untouched.
4. Write the file back, preserving ordering of existing entries (new entries appended at end).

---

## 7. Template Processing

For rules with a `template` field:

1. Parse the template string using `text/template`.
2. Execute the template with the Vault KV data map as the dot context (`.`).
3. The rendered output is then parsed by the appropriate file format handler to produce the "incoming" structured data.

Template functions to register:
- `env`: read environment variable — `{{env "HOME"}}`
- `base64encode` / `base64decode`: for credential encoding
- `default`: provide fallback value — `{{default .foo "bar"}}`
- `quote`: shell-safe quoting

---

## 8. Auto-Start on Login

### 8.1 Linux (systemd user unit)

Install to `~/.config/systemd/user/dotvault.service` (or ship in `/usr/lib/systemd/user/`):

```ini
[Unit]
Description=Vault Secret Sync Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dotvault
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=default.target
```

Enable: `systemctl --user enable --now dotvault`

### 8.2 macOS (launchd)

Install to `~/Library/LaunchAgents/com.goodtune.dotvault.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.goodtune.dotvault</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/dotvault</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/dotvault.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/dotvault.err.log</string>
</dict>
</plist>
```

### 8.3 Windows (Scheduled Task)

Create a scheduled task triggered on user logon:

```
schtasks /create /tn "DotVault" /tr "C:\Program Files\dotvault\dotvault.exe" /sc onlogon /rl limited
```

Or ship a PowerShell install script that creates the task.

---

## 9. CLI Interface

The binary should support the following subcommands for operational use:

```
dotvault                    # Run the daemon (default, foreground)
dotvault run                # Explicit: run daemon in foreground
dotvault sync               # Run one sync cycle and exit
dotvault status             # Show auth status, last sync times, and any errors
dotvault install-service    # Install the auto-start unit/plist/task for the current OS
dotvault uninstall-service  # Remove the auto-start configuration
dotvault version            # Print version and build info
```

### Flags

```
--config <path>       Override system config file path
--log-level <level>   debug, info, warn, error (default: info)
--dry-run             Show what would be changed without writing files
--once                Alias for `sync` subcommand
```

---

## 10. Web UI

The daemon includes an optional local web interface for end-user workstations. It is **disabled by default** and must be explicitly enabled in the system configuration (`web.enabled: true`). It must only bind to loopback addresses — the daemon must refuse to start if `web.listen` is configured with a non-loopback address.

### 10.1 Purpose

1. **Secret browser** — a file-browser-style view of the user's Vault KV tree (`users/<username>/`). Users can navigate keys, see field names, and selectively reveal secret values (hidden by default, shown on click/toggle). This gives users a convenient way to inspect what dotvault is managing without needing the Vault CLI or Vault's own UI.

2. **OAuth2 dance orchestration** — some Vault secret engines (e.g. GitHub, Okta, cloud provider credential brokers) require an interactive OAuth2 authorization code flow to obtain or refresh credentials. The Web UI provides the callback endpoint and user-facing flow for these dances, initiated either from the UI or triggered automatically by a sync rule that requires it.

### 10.2 Architecture

- Serve using Go `net/http` stdlib. No external web framework.
- The UI is a single-page application (SPA) embedded into the binary using `embed.FS` (Go 1.16+). No external asset files at runtime.
- API endpoints are JSON REST, prefixed under `/api/v1/`.
- The SPA frontend should be built with a lightweight framework suitable for embedding — vanilla JS, Preact, or similar. It must be buildable as static assets and committed to the repo (or built via `go generate`).

### 10.3 Security Model

- **Loopback only:** the listener must validate that the resolved listen address is a loopback address (`127.0.0.0/8` or `::1`). Refuse to start otherwise.
- **CSRF protection:** all mutating API endpoints require a CSRF token issued by the server on page load.
- **No authentication on the HTTP layer:** the threat model assumes that only the local user can reach `127.0.0.1`. The daemon already runs as that user, so the Web UI operates with the same Vault token the daemon holds.
- **Secret reveal is client-side gated:** secret values are not sent in list/browse responses. A separate API call (`GET /api/v1/secrets/{path}?reveal=true`) returns the actual values, so the UI can implement a deliberate "click to reveal" interaction.
- **Content-Security-Policy header:** set a strict CSP (`default-src 'self'`) to prevent XSS in the embedded UI.

### 10.4 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/secrets/` | List keys at the root of `users/<username>/` |
| `GET` | `/api/v1/secrets/{path}` | List fields for a specific KV entry. Returns field names and metadata only. |
| `GET` | `/api/v1/secrets/{path}?reveal=true` | Returns field names and their decrypted values. |
| `GET` | `/api/v1/status` | Daemon status: Vault auth state, last sync time, rule statuses, token TTL. |
| `GET` | `/api/v1/rules` | List configured sync rules and their current state. |
| `POST` | `/api/v1/sync` | Trigger an immediate sync cycle. |
| `GET` | `/api/v1/oauth/{rule}/start` | Initiate an OAuth2 authorization flow for a rule's external engine. Redirects the browser to the IdP. |
| `GET` | `/api/v1/oauth/callback` | OAuth2 callback endpoint. Receives the authorization code, completes the token exchange via the Vault engine, and redirects the user back to the UI with a success/failure status. |

### 10.5 OAuth2 Engine Integration

Some sync rules may reference Vault secret engines that broker credentials via OAuth2 (e.g. a GitHub App token engine, an Okta integration). The flow works as follows:

1. A rule in the config can optionally declare an `oauth` block:
   ```yaml
   rules:
     - name: github-app
       vault_key: "github-app"
       oauth:
         # Vault secret engine path that requires an OAuth2 flow
         engine_path: "github/token"
         # OAuth2 provider name (for UI display)
         provider: "GitHub"
         # Scopes to request
         scopes: ["repo", "read:org"]
       target:
         path: "~/.config/gh/hosts.yml"
         format: yaml
         template: |
           github.com:
             oauth_token: "{{.token}}"
         merge: deep
   ```

2. When the daemon detects this rule needs a credential that requires user interaction (e.g. no valid token cached, or the engine returns a redirect URL), it marks the rule as "pending OAuth" in its status.

3. The user opens the Web UI, sees the pending status, and clicks "Authorize". This hits `GET /api/v1/oauth/github-app/start`.

4. The daemon constructs the authorization URL (from the Vault engine's response or config), sets up a pending state keyed by a random nonce, and redirects the user's browser to the IdP.

5. The IdP redirects back to `http://127.0.0.1:8200/api/v1/oauth/callback?code=...&state=...`.

6. The daemon validates the state/nonce, exchanges the code via the Vault engine API, and stores the resulting credential.

7. The normal sync loop then picks up the new credential and writes it to the target file.

### 10.6 UI Layout

The UI should be simple and functional:

- **Left sidebar:** tree/list view of KV keys under the user's path. Expandable like a file browser.
- **Main panel:** when a key is selected, show a table of field names with masked values. Each row has a "reveal" toggle (eye icon). Revealed values should auto-hide after 30 seconds or on navigation.
- **Top bar:** daemon status indicator (connected/disconnected/auth required), last sync time, "Sync Now" button.
- **Alerts area:** any rules in "pending OAuth" state shown as actionable banners with an "Authorize" button.

---

## 11. Logging

- Use `log/slog` (Go 1.21+ structured logging).
- Default output: stderr when running in foreground; file in `logs/` directory when daemonised.
- Log format: JSON for machine consumption, text for TTY.
- Auto-detect: if stderr is a terminal → text format; otherwise → JSON.

### Log Events

| Level | Event |
|-------|-------|
| INFO | Startup, config loaded, auth success, sync cycle complete, file updated |
| WARN | Token near expiry, file modified externally since last sync, retry auth |
| ERROR | Auth failure, Vault unreachable, file write failure, config parse error |
| DEBUG | Individual KV reads, template rendering, merge diffs, token TTL checks |
| INFO | Web UI started on `<listen address>`, OAuth flow initiated/completed |
| WARN | OAuth callback received with invalid state parameter |
| ERROR | Web UI failed to bind (non-loopback address rejected), OAuth token exchange failed |

---

## 12. Error Handling & Resilience

| Scenario | Behaviour |
|----------|-----------|
| System config missing | Exit with clear error message and exit code 1 |
| System config invalid | Exit with parse error details and exit code 1 |
| Vault unreachable on startup | Retry with exponential backoff (1s, 2s, 4s, ... max 5m). Log each attempt. |
| Vault unreachable during sync | Log error, skip this cycle, retry next interval |
| Auth token expired mid-cycle | Re-authenticate immediately, then resume |
| KV path not found for user | Log warning (not error), skip that rule |
| Target file parent dir missing | Create parent directories (0755) then create file |
| Target file not writable | Log error, skip that rule, continue others |
| Template rendering fails | Log error with template name and data keys, skip rule |
| Corrupt target file (unparseable) | Log error, optionally back up file to `<path>.dotvault-backup`, write fresh content from template |
| Web UI listen address non-loopback | Refuse to start, exit with error code 1 and clear message |
| Web UI port already in use | Log error, disable Web UI, continue running daemon without it |
| OAuth callback with invalid state | Log warning, return 400 to browser, do not exchange code |
| OAuth token exchange failure | Log error, show failure in UI, leave rule in "pending OAuth" state |

---

## 13. Project Structure

```
dotvault/
├── cmd/
│   └── dotvault/
│       └── main.go              # Entry point, CLI parsing
├── internal/
│   ├── config/
│   │   └── config.go            # YAML config parsing & validation
│   ├── paths/
│   │   └── paths.go             # OS-specific path resolution
│   ├── auth/
│   │   ├── auth.go              # Auth orchestrator
│   │   ├── token.go             # Token read/write/refresh
│   │   ├── oidc.go              # OIDC flow implementation
│   │   └── ldap.go              # LDAP auth implementation
│   ├── vault/
│   │   └── client.go            # Vault API client wrapper, KVv2 reads
│   ├── sync/
│   │   ├── engine.go            # Polling loop, version tracking
│   │   └── state.go             # State file management
│   ├── handlers/
│   │   ├── handler.go           # FileHandler interface
│   │   ├── yaml.go              # YAML read/merge/write
│   │   ├── json.go              # JSON read/merge/write
│   │   ├── ini.go               # INI read/merge/write
│   │   └── netrc.go             # Netrc read/merge/write
│   ├── template/
│   │   └── template.go          # Go template rendering with custom funcs
│   ├── web/
│   │   ├── server.go            # HTTP server setup, loopback validation, middleware
│   │   ├── api.go               # JSON REST API handlers (/api/v1/*)
│   │   ├── oauth.go             # OAuth2 flow start/callback handlers
│   │   └── static/              # Embedded SPA assets (built via go generate)
│   │       ├── index.html
│   │       ├── app.js
│   │       └── style.css
│   └── service/
│       ├── install.go           # Service install/uninstall orchestrator
│       ├── systemd.go           # Linux systemd unit management
│       ├── launchd.go           # macOS launchd plist management
│       └── windows.go           # Windows scheduled task management
├── go.mod
├── go.sum
├── Makefile                     # Build targets for all OS/arch combos
└── README.md
```

---

## 14. Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/hashicorp/vault/api` | Vault client SDK |
| `gopkg.in/yaml.v3` | YAML parsing with node-level access |
| `gopkg.in/ini.v1` | INI file parsing |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/pkg/browser` | Open browser for OIDC flow |
| `log/slog` (stdlib) | Structured logging |
| `text/template` (stdlib) | Template rendering |
| `encoding/json` (stdlib) | JSON handling |
| `os/user` (stdlib) | Current user identity |
| `crypto/sha256` (stdlib) | File checksum for change detection |
| `net/http` (stdlib) | Web UI HTTP server |
| `embed` (stdlib) | Embed SPA static assets into binary |

Avoid CGO dependencies. All libraries must be pure Go for clean cross-compilation.

---

## 15. Build & Release

### Makefile Targets

```makefile
VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

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
```

---

## 16. Testing Strategy

| Layer | Approach |
|-------|----------|
| File handlers | Unit tests with fixture files for each format (YAML, JSON, INI, netrc). Test read → merge → write round-trips. Test that unmanaged content is preserved. |
| Template rendering | Unit tests with sample Vault data maps. |
| Config parsing | Unit tests with valid/invalid YAML configs. |
| Vault integration | Integration tests using a real Vault dev server (`vault server -dev`). Test KVv2 reads, auth flows, token refresh. |
| Sync engine | Integration tests with mock Vault data and temp file trees. Verify correct files are created/updated. |
| Netrc parser | Dedicated unit tests: parse → modify → write with edge cases (comments, macdef, default entry, blank lines). |
| End-to-end | Docker-based test: run Vault dev server, seed KV data, run `dotvault sync`, verify file output. |
| Web UI API | Unit tests for each API endpoint. Test loopback enforcement rejects non-loopback addresses. Test CSRF token validation. Test secret reveal vs list responses. |
| OAuth flow | Integration test with a mock IdP: start flow, simulate callback, verify token exchange. Test invalid state rejection. |

---

## 17. Security Considerations

- **Token file permissions:** `~/.vault-token` must be `0600`. Warn if it isn't.
- **Config file permissions:** system config should be owned by root and world-readable but not writable by users. The daemon should warn if the config is user-writable.
- **Secret logging:** never log secret values, even at DEBUG level. Log Vault paths and field names only.
- **File atomicity:** write target files by writing to a temp file in the same directory, then `os.Rename()` for atomic replacement. This prevents partial writes on crash.
- **Signal handling:** handle SIGTERM/SIGINT gracefully — finish current write operation, then exit. Handle SIGHUP to reload configuration.
- **Web UI loopback enforcement:** the daemon must resolve `web.listen` and confirm it is a loopback address before binding. Refuse to start if it resolves to a non-loopback interface. This is a hard invariant, not a warning.
- **Web UI CSRF:** all state-mutating API endpoints (`POST /api/v1/sync`, OAuth start) must require a CSRF token. Issue the token via a `GET /api/v1/csrf` endpoint or embed it in the initial page load.
- **Web UI CSP:** set `Content-Security-Policy: default-src 'self'` on all responses. No inline scripts unless hashed.
- **OAuth state parameter:** the OAuth2 flow must use a cryptographically random `state` parameter stored server-side, validated on callback to prevent CSRF on the OAuth redirect.

---

## 18. Open Design Questions

These are areas where the implementer should make a pragmatic choice and document it:

1. **Conflict resolution for netrc `default` entry:** should the daemon manage it, or always skip it?
2. **Multiple Vault KV mounts:** should rules be able to specify a per-rule `kv_mount`, or is one global mount sufficient?
3. **Webhook/watch mode:** should there be an option to use Vault's blocking queries instead of polling? (Future enhancement — polling is fine for v1.)
4. **File locking:** should the daemon acquire advisory file locks during writes to prevent races with other tools editing the same files?
5. **Notifications:** should the daemon expose a mechanism (e.g. D-Bus on Linux, osascript on macOS) to notify the user when secrets are updated?
6. **Web UI frontend framework:** the spec suggests vanilla JS or Preact for the embedded SPA. The implementer should choose based on what produces the smallest embedded asset footprint while remaining maintainable.
7. **OAuth2 provider registry:** should the daemon ship with built-in knowledge of common OAuth2 providers (GitHub, Okta, Google) and their endpoints, or should every OAuth rule require fully explicit URLs in config?
8. **Web UI access logging:** should the Web UI log every API request (including secret reveals) to an audit trail, or is that excessive for a localhost-only tool?
