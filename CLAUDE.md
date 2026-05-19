# dotvault

Cross-platform daemon (Go) that runs in user context, authenticates to HashiCorp Vault, and synchronises KVv2 secrets into local configuration files via surgical, field-level merges.

## Agent workflow: review before pushing

Every Claude agent on this repo runs a five-persona pre-push review of the unpushed changes BEFORE executing `git push`. The personas are security, architecture, cross-platform, test & correctness, and docs & DX. This replaces the previous PR-time CI review (`.github/workflows/claude-code-review.yml`, since deleted), which generated a round-trip comment loop that the author always had to babysit one commit behind.

How:

1. **Invoke `/precommit-review`.** The skill at `.claude/skills/precommit-review/` packages the dispatch logic: it inspects the unpushed diff, fires five `Agent` tool calls in a single message (one per persona), and waits for all of them. Each persona reports under 250 words with `file:line` references and a severity tag (`blocker` / `major` / `minor` / `nit`).
2. **Address the findings** in the same commit series — fix in place, don't push and then fix in a follow-up.
   - `blocker` and `major`: fix, or push a commit whose message names the persona and explains why the trade-off was made deliberately.
   - `minor` and `nit`: fix when cheap; otherwise mention in the commit message.
3. **Push once.** A clean series with the review baked in is the deliverable.

Skip the review only when the user explicitly tells you to, or when the push is purely administrative (rebase pointer update with no diff change, tag, etc.). When in doubt, run it — five short agent calls are cheap; a public-PR comment loop with a human in the middle is not.

This is non-negotiable for code-changing pushes. Doc-only changes can use the review at your judgement.

## PR descriptions and commit messages

Write PR bodies and long-form commit messages in **flowing prose** — one long line per paragraph or bullet, no manual line wrapping inside a paragraph. GitHub renders both as Markdown and re-wraps to the viewer's column width; hard-wrapping in the source produces ragged right edges in the rendered HTML, makes single-sentence edits churn multiple lines in a diff, and breaks copy-paste into other tools.

Hard breaks are still right for a new bullet, a new numbered step, a blank line between paragraphs, or the boundaries of a code block / table. Inside a paragraph or bullet, let the renderer wrap. (Commit-message *subject* lines remain ~50 chars; this rule applies to the body.)

This convention is non-negotiable when an agent writes a PR description — re-flow any prose written by a previous step that violates it before opening or updating the PR.

Do **not** mention the pre-push review in PR descriptions. Running `/precommit-review` is the default workflow on this repo (per the section above) — calling it out in every PR body is noise. The audit trail lives in the commit series itself: a separate `fix(...): address precommit review findings` commit (or an inline rationale in the implementation commit) is sufficient when the review produced material follow-ups. If the review found nothing, there is nothing to say.

## Build & Test

```sh
make test          # run all tests
make build         # build for current platform
make build-all     # cross-compile linux/darwin (amd64/arm64) and windows (amd64)
```

All builds use `CGO_ENABLED=0` for static binaries. Version is injected via ldflags (`-X main.version=...`).

Windows ships two binaries from the same source — the PE subsystem flag is immutable post-link, so the only correct fix is to build twice:

- `dotvault.exe` — Console subsystem. The CLI for `sync`, `status`, `run` (foreground daemon), `reg-export`/`reg-import`, etc. cmd.exe / PowerShell wait for it, stdio is inherited, Ctrl+C works. Bare invocation prints help.
- `dotvaultw.exe` — GUI subsystem (`-H=windowsgui`). For double-click. Runs the daemon with the system-tray icon and no console flash. Bare invocation defaults to the daemon (equivalent to `dotvault run`) because there's no console to show help on; this is detected at runtime via `os.Args[0]`. CLI subcommands invoked through it will appear to do nothing because cmd.exe does not wait for GUI-subsystem binaries — use `dotvault.exe` for CLI work.

Installer / Start Menu shortcuts should point at `dotvaultw.exe`; the PATH entry should be `dotvault.exe`.

Both Windows binaries embed the application icon. `assets/dotvault.ico` is the multi-resolution source (16/24/32/48/64/128/256, generated from `assets/dotvault-no-text.png`); the Makefile and the `.goreleaser.yml` `before:` hook run `go tool rsrc` to emit `cmd/dotvault/rsrc_windows_amd64.syso`, which the Go linker picks up automatically for `windows_amd64` targets and ignores everywhere else. The `.syso` is a build artefact (regeneratable, gitignored). The system-tray code in `internal/tray/tray_windows.go` loads this icon by resource ID rather than the stock `IDI_APPLICATION`, so the tray, taskbar, and Start Menu shortcuts all carry the dotvault glyph; if the resource is missing (e.g. a hand-rolled `go build` skipping rsrc) the tray falls back to the system default.

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
  loginsuppress/         login-check suppression marker (path/window/freshness/refresh)
  observability/         OTel metrics SDK wiring, package-level instrument helpers
  sdnotify/              Tiny sd_notify(3) helper (READY/STOPPING/WATCHDOG); no-op off Linux
  sync/                  Hybrid event+poll sync engine, state store
  handlers/              File format handlers (yaml, json, ini, toml, text, netrc)
  tmpl/                  Go template rendering (named tmpl to avoid shadowing text/template)
  enrol/                 Credential acquisition via OAuth device flow
  web/                   Web UI server (Preact SPA), auth endpoints, REST API
  perms/                 File permission checks (Unix mode bits, Windows DACL)
  tray/                  Windows system-tray icon (no-op on other platforms)
test/integration/        Integration tests against real Vault
packaging/windows/       ADMX Group Policy template
packaging/linux/         systemd units (dotvault.service + token-watch path/service, shipped in RPM/DEB)
```

## Configuration

YAML config file at platform-specific system paths:

- macOS: `/Library/Application Support/dotvault/config.yaml`
- Linux: `/etc/xdg/dotvault/config.yaml` (also checks `$XDG_CONFIG_DIRS`)
- Windows: `%ProgramData%\dotvault\config.yaml`

On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\goodtune\dotvault`, configuration is loaded entirely from the registry and the file-based config is ignored. Only machine-level (HKLM) policy is read; HKCU is intentionally skipped because it is user-writable.

### Config Sections

- **`vault`** — address (required), auth_method, auth_mount, auth_role, kv_mount (default `"kv"`), user_prefix (default `"users/"`, trailing slash enforced), ca_cert, tls_skip_verify, disable_token_renewal (default false — set true to prevent the daemon from calling RenewSelf; TTL expiry still triggers re-auth)
- **`sync`** — interval as Go duration string (default `15m`)
- **`web`** — enabled (default false), listen (loopback only, hard invariant), login_text (markdown), secret_view_text (markdown)
- **`observability`** — enabled (default false), endpoint, protocol (`grpc` or `http/protobuf`), insecure, headers (map), export_interval. OTLP metrics exporter; falls through to standard `OTEL_*` env vars when fields are empty. Disabled by default — instruments fall back to the OTel no-op meter so call sites never need to branch. **Treat `headers` as a credential** — values typically carry OTLP bearer tokens (Datadog / Grafana Cloud / etc.). Store the config file at 0600 and prefer setting them via the per-user `EnvironmentFile` (`~/.config/dotvault/env`) rather than checked-in YAML. `ObservabilityConfig.MarshalYAML` strips `Headers` from every export so a downloaded config or `reg-export` artefact never contains the live token.
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
dotvault             Print help (no implicit daemon start)
dotvault run         Run the long-lived daemon
dotvault sync        One-shot sync cycle, then exit
dotvault login       Force a fresh login via the configured auth method
dotvault login-check Validate/renew cached token on interactive login (tty-aware)
dotvault enrol       Interactive enrolment picker (`dotvault enrol <name>` to run one directly)
dotvault status      Display auth state, token TTL, per-rule sync state
dotvault version     Print build version (--json for machine-readable resource metadata)
dotvault reg-export  Convert a Windows .reg file to YAML (or canonical .reg)
dotvault reg-import  Convert a YAML config to a Windows .reg file
```

Running `dotvault` with no subcommand prints help — the daemon is no
longer the default. Use `dotvault run` to start it explicitly.

`dotvault login` always runs the configured fresh-auth flow (OIDC, LDAP),
ignoring any cached token. It is the dotvault-config-driven analogue of
`vault login -address … -method …` and is the natural entry point when a
running daemon needs a new token after expiry.

`dotvault login-check` is intended for interactive-shell login profiles
wired in via a thin wrapper that gates on interactivity, TTY, and the
daemon being active (`systemctl --user is-active dotvault.service`).
The binary trusts those preconditions and never re-checks them, so the
wrapper stays trivial and signal handling works correctly during shell
startup.

- A suppression marker at
  `${XDG_STATE_HOME:-$HOME/.local/state}/dotvault/login-check-suppress`
  is checked first. While its mtime is within `DOTVAULT_SUPPRESS_HOURS`
  (positive integer, default `6`) the command exits silently with no
  vault calls. A future mtime is treated as stale so clock skew, VM
  snapshot rollback, or restored backups cannot lock suppression on.
  The path can be overridden via `DOTVAULT_SUPPRESS_MARKER` (used by
  tests). The path matches the previous shell-managed location, so
  existing suppression state survives the rollout without migration.
  Logic lives in `internal/loginsuppress/`.
- If a cached token is valid and still within the first half of its
  creation TTL, exit clean.
- If the cached token is valid but past the halfway mark, attempt renewal.
  On renewal failure where the token is still valid, warn with the
  absolute expiry time and exit 0.
- If the cached token is missing or invalid, run the configured login
  flow. Ctrl-C exits immediately without requiring an extra Enter: a
  dedicated signal handler restores the terminal state captured before
  the password prompt, refreshes the marker, and `os.Exit(0)`s
  (`term.ReadPassword` does not observe context cancellation, so going
  through a goroutine + `os.Exit` is the only reliable way to honour
  the contract).
- The marker is refreshed on every exit past the freshness check
  (success, decline, failure, Ctrl+C, internal errors) so concurrent
  shells across tmux/IDE/SSH-multiplex fanout only ever prompt once
  per window. Concurrent marker updates are intentionally
  unsynchronised — duplicate prompts in a tight race are acceptable;
  blocking shell startup on a `flock` is not.
- Exits `0` for suppressed, success, decline, cancellation, or
  expected authentication failure. Exits `1` only on invalid
  `DOTVAULT_SUPPRESS_HOURS` or genuine internal errors. The shell
  wrapper does not branch on exit code.

`dotvault enrol` is the CLI counterpart to the web UI's enrolment page,
intended for terminal-only users (servers, headless setups, devs who
don't run the local web UI). With no argument it draws a small raw-mode
picker listing every configured enrolment alongside its current state
(`enrolled` / `not enrolled` / `error: …` for unknown engines or Vault
read failures); arrow keys navigate, Enter runs the highlighted entry,
`q` or Esc exits. With a single positional argument it skips the picker
and runs that enrolment directly, looking the name up against the
configured `enrolments:` map. An unknown name prints the configured
keys and exits non-zero.

Both forms require a valid cached Vault token and refuse to initiate
fresh authentication — the user is pointed at `dotvault login` instead.
The picker also refuses to run without a TTY on both stdin and stderr,
because a headless caller has no way to drive the selection; pass an
explicit name to enrol non-interactively. The underlying engine runs
through `enrol.Manager.RunOne`, which is deliberately a re-run-on-demand
entry point: unlike `CheckAll`, it executes the engine even if the
target is already populated, so the command doubles as a way to refresh
expiring credentials without first wiping the Vault secret.

The naming follows regedit's `/e` (export) and `/s` (import) directional
convention: `reg-export` pulls policy out of the registry world into a
user-facing form, `reg-import` casts a YAML config into the .reg form a
Windows admin would push back into the registry.

`reg-export` parses a `.reg` file (positional path or stdin when
omitted/`-`) under `HKLM\SOFTWARE\Policies\goodtune\dotvault` and emits the
equivalent dotvault YAML configuration to stdout (or `--output <path>`,
0600). Both UTF-16LE-with-BOM and plain ASCII inputs are accepted — the
encoding is detected from the leading BOM. The reconstructed YAML is
run through `config.Load` validation before being printed, so malformed
inputs surface as clear errors rather than producing partial YAML. Pass
`--regedit` to re-emit the canonicalised .reg form instead of YAML;
combine with `--ascii` for the plain-text variant of the v5 format.

`reg-import` is the inverse: it reads and validates a YAML config, then
emits a `Windows Registry Editor Version 5.00` file targeting
`HKLM\SOFTWARE\Policies\goodtune\dotvault` to stdout (or `--output <path>`,
written with 0600 permissions). Default encoding is UTF-16LE with BOM,
matching the canonical format produced by regedit.exe; `--ascii`
produces an unencoded plain-text variant of the same v5 format.
Multi-line values such as Go templates round-trip via `hex(1):`
(UTF-16LE bytes). Optional string fields are emitted as `""` even when
empty so re-importing clears stale registry values. Rendering lives in
`internal/regfile/regfile.go`, parsing in `internal/regfile/parse.go`,
and the canonical YAML emitter in `internal/regfile/yaml.go`.

The web UI's Effective Configuration screen exposes the same conversion
in-browser via download buttons backed by `GET
/api/v1/config/download?format=yaml|reg`. The endpoint reassembles the
in-memory `*config.Config` and routes through the same regfile renderers,
so a daemon that loaded its config from a Windows GPO can be exported
back as YAML (or vice versa) without restart.

Flags: `--config <path>`, `--log-level debug|info|warn|error`, `--log-format auto|text|json` (forces the slog handler; default `auto` picks text on TTY, JSON otherwise), `--dry-run`. Subcommand-scoped: `--once` on `dotvault run` redirects to the sync path; `--json` on `dotvault version` emits a structured `{version, service, go_version, os, arch}` envelope.

Logging uses `log/slog` — text format when stderr is a TTY, JSON otherwise. Always writes to stderr; no file-based logging.

## Daemon Lifecycle

1. Load config (file or registry)
2. Create Vault client, attempt token reuse (VAULT_TOKEN env or `~/.vault-token`)
3. Start web UI if enabled (before auth, so it can serve browser-based login)
4. Authenticate if needed: web mode routes all auth through the SPA; CLI mode uses method-specific flows (OIDC browser, LDAP terminal prompt, token file)
5. Start token lifecycle manager (renews at 75% TTL, exponential backoff 1s-5m on failure)
6. Start RefreshManager (rotates expiring credentials for `Refresher` engines, e.g. JFrog) and WatchManager (re-mirrors upstream sources for `Watcher` engines, e.g. Copy)
7. Run enrolment check (wizard if any credentials missing in Vault)
8. Start sync engine: initial sync, then hybrid event+poll loop
9. Background goroutine reloads config on each tick for enrolment changes only
10. On Windows, install a system-tray icon (`internal/tray/`) with Exit and (when web is enabled) "View web UI" entries; the tray owns the main goroutine because the Win32 message pump must run on a locked OS thread, while the sync loop moves to a goroutine. On non-Windows the same call simply blocks on ctx.

SIGHUP triggers an immediate `~/.vault-token` re-read via `LifecycleManager.Reload` — handy for picking up a token freshly written by `dotvault login` without waiting for the 5-minute lifecycle tick. The shipped `packaging/linux/dotvault-token-watch.path` unit drives this automatically: any change to `~/.vault-token` activates `dotvault-token-watch.service`, which runs `systemctl --user kill --signal=SIGHUP dotvault.service`. The systemd-native path is deliberate — it targets the unit's MainPID rather than scanning the process table for anything named `dotvault`, so a developer running `go run ./cmd/dotvault` or `dotvault sync` from a shell while the daemon also happens to be running won't have those side processes SIGHUP'd (their default disposition for SIGHUP is *terminate*).

Full config reload via SIGHUP is **not implemented**. The daemon must be fully restarted to pick up config changes (except enrolment changes, which are detected on the polling interval).

## Authentication

### Methods

- **OIDC** — Requests auth URL from Vault, opens browser, listens on random localhost port for callback, exchanges code for Vault token
- **LDAP** — Prompts for password; supports MFA (Duo push and TOTP) via the LoginTracker async state machine
- **Token** — Reads from VAULT_TOKEN env var or `~/.vault-token`

### LoginTracker

Async login state machine (`internal/auth/login.go`) shared by CLI and web paths. States: `pending` -> `mfa_required` -> `authenticated` | `failed`. The web frontend polls status; CLI polls at 500ms intervals. Session IDs are server-generated (random 32 bytes, hex-encoded).

### Token Lifecycle

`LifecycleManager` checks token TTL every 5 minutes. Renews at 75% remaining TTL.
On detecting an invalid/expired token (403 Forbidden or TTL=0 + concrete
`expire_time`) the manager runs a recovery sequence:

1. Re-read the token file (and `VAULT_TOKEN` env). If a different value
   is present and `LookupSelf` succeeds with it, swap the in-memory token
   on the Vault client, clear the needs-reauth flag, and return to the
   normal 5-minute check cadence. This lets a parallel `dotvault login`
   recover a running daemon without a restart.
2. If no fresh token is on disk, signal re-auth: fire the registered
   `OnReauth` callback (web mode clears the in-memory token, invalidating
   any browser session sitting on a stale "logged-in" view), push an
   error on the error channel, and switch to a 10-second recovery poll
   so a subsequent token write is picked up quickly.

In web mode the daemon also re-opens the browser to the web UI root when
the lifecycle manager signals re-auth, subject to a 10-minute cooldown
to avoid flapping during transient errors.

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

Engines implement `Name()`, `Run(ctx, settings, io)`, and `Fields()`. Registered in a package-level map. Currently implemented: GitHub (OAuth device flow), JFrog (browser-based web login), SSH (Ed25519 key generation), Copy (mirror an existing KVv2 secret).

Optional interfaces extend the contract for engines that need them:

- `SettingsFielder.FieldsFromSettings(settings)` — engines whose written-field set depends on per-enrolment settings (currently the Copy engine, where the JSON template determines the keys). The manager and web runner use `EngineFields(engine, settings)` which falls back to `Fields()` when not implemented.
- `Refresher.Refresh(ctx, settings, existing)` — engines whose credentials expire and can be rotated without user interaction (currently JFrog). Driven by `RefreshManager`.
- `Watcher.WatchSources(settings, username) []WatchSource` — engines whose output is derived from upstream Vault data and must track source changes (currently Copy). Driven by `WatchManager`, which polls every sync interval and (on Enterprise Vault) reacts to source-write events within seconds.

### GitHub Engine Defaults

- Client ID: `178c6fc778ccc68e1d6a` (GitHub CLI's OAuth app)
- Scopes: `repo`, `read:org`, `gist`
- Host: `github.com`

Overridable via settings: `client_id`, `scopes`, `host`. Returns `{"oauth_token": "<token>", "user": "<username>"}`.

### JFrog Engine

Mirrors the `jf login` web login flow from `jfrog-cli`, then mints a dotvault-owned refreshable token with a configurable TTL. No public OAuth app exists — JFrog Platform hosts its own browser login endpoint, so the engine just requires the platform URL.

Required settings:
- `url` — JFrog Platform URL (e.g. `https://mycompany.jfrog.io`)

Optional settings:
- `token_ttl` — lifetime of the dotvault-minted access token. Accepts `time.ParseDuration` syntax plus `Nd` for whole days (e.g. `60d`, `6h`, `10m`). Default `60d`. Floor `10m` — validated at config-load time. Non-admin users can mint refreshable tokens at any non-zero TTL; only the never-expire case (`expires_in=0`) requires admin.
- `client_name`: `JFrog-CLI` (sent as `jfClientName` query parameter)
- `client_code`: `1` (sent as `jfClientCode` query parameter)

Flow (enrolment — runs once per user):
1. POST `{url}/access/api/v2/authentication/jfrog_client_login/request` with a random UUID
2. Open `{url}/ui/login?jfClientSession=<uuid>&jfClientName=JFrog-CLI&jfClientCode=1` — user confirms the last 4 chars of the UUID after sign-in
3. Poll GET `{url}/access/api/v2/authentication/jfrog_client_login/token/<uuid>` until 200 — returns a bootstrap token with the JFrog server default TTL (typically 1 year)
4. POST `{url}/access/api/v1/tokens` with `Authorization: Bearer <bootstrap>` and `{"expires_in":<token_ttl_seconds>,"refreshable":true,"scope":"applied-permissions/user"}` — mints the dotvault-owned pair; the bootstrap token is discarded. v1 rather than v2 because v2 is admin-only on most JFrog deployments (non-admins and older Artifactory versions see it as a 404); v1 has been the self-token endpoint since Artifactory 7.21.1 and is what `jfrog-client-go` uses.

Flow (refresh — periodic, driven by `RefreshManager`):
1. Every `check_interval` (daemon-wired at 5 min), iterate all enrolments whose engine implements `Refresher`
2. For each, read the secret and skip unless `now >= issued_at + (expires_at - issued_at) / 2`
3. POST `{url}/access/api/v1/tokens` with `grant_type=refresh_token&access_token=<current>&refresh_token=<current>` — **JFrog rotates both tokens on every successful refresh**, so the old refresh_token is invalid immediately
4. Stamp new `issued_at: now`, `expires_at: now + token_ttl` (dotvault's configured TTL, not whatever JFrog returns), write the replacement map atomically
5. `401`/`403` from the refresh endpoint is treated as permanent revocation — the secret is deleted from Vault and the user is prompted to re-enrol. Other errors are transient; the existing secret is kept and retried with exponential backoff

Vault schema (7 fields): `access_token`, `refresh_token`, `url`, `server_id`, `user`, `issued_at` (RFC3339), `expires_at` (RFC3339). The rendered `jfrog-cli.conf.v6` only contains `accessToken` — `refreshToken` and `webLogin: true` are deliberately omitted so `jf` never attempts its own refresh (which would race the sync-engine clobber).

`server_id` is deduced from the platform hostname (e.g. `mycompany.jfrog.io` → `mycompany`, IP addresses → `default-server`); `user` is extracted from the access-token JWT subject. Requires JFrog Artifactory 7.64.0 or newer on the remote side.

### SSH Engine

Generates Ed25519 key pairs in OpenSSH format. Returns `{"public_key": "<ssh-ed25519 ...>", "private_key": "<PEM>"}`. The public key comment is `{username}@dotvault`.

Passphrase mode controlled via settings `passphrase` field:
- `"required"` (default) — user must provide a passphrase; fails if empty
- `"recommended"` — user prompted but can skip
- `"unsafe"` — no passphrase (unencrypted private key)

No external dependencies beyond `golang.org/x/crypto/ssh`.

### Copy Engine

Mirrors an existing KVv2 secret into the user's enrolment path, optionally
transforming its shape via a JSON template. Useful when other tooling (or a
separate operator workflow) populates a per-user secret under a shared prefix
(e.g. `apps/<app>/keys/<user>`) and dotvault needs to expose that value to
the user under their own path with potentially different field names.

Required settings (nested map):

- `from.mount` — source KV mount (e.g. `kv`)
- `from.path` — source path; supports a `{{.user}}` substitution that resolves to the authenticated Vault username (`token_meta_username`)
- `format` — must be `json` (only supported format)
- `template` — Go template producing JSON; receives `{ "data": <source secret data>, "user": <username> }` as dot context. Top-level keys of the rendered JSON become the fields written to the target.

Behaviour:

- Only `json` format is supported; the rendered output must parse as a JSON object whose values are strings (or are coerced to strings).
- The target secret is **merged**, not replaced — keys produced by the template are written, but pre-existing keys at the target that the template does not name are preserved. This makes it safe for multiple operators / processes to maintain different fields under the same user path.
- The set of fields the engine writes is derived dynamically from the template's top-level JSON keys (via the `SettingsFielder` interface). The manager treats the enrolment as complete when those fields are present in the target, just as for static-field engines.
- Preserved values are **stringified**, not type-preserved: the engine flattens the returned data to `map[string]string`, so any pre-existing object/number/bool field at the target is JSON-marshalled to its textual form before being written back. This is intentional (the engine contract is `map[string]string` and dropping non-strings would lose data) but means the copy engine should not be co-tenanted with workflows that depend on KVv2 fields keeping their original JSON type.

Periodic refresh:

- The Copy engine implements `Watcher`, so the daemon's `WatchManager` re-evaluates each copy enrolment on every poll cycle (defaults to the sync interval) and writes back only when the merged result differs from the current target — avoiding spurious KVv2 versions.
- On Vault Enterprise, the WatchManager also subscribes to the `kv-v2/data-write` event type and filters incoming events client-side against the configured source paths, triggering an immediate refresh when a matching source secret is updated. Failures degrade gracefully to poll-only, mirroring the sync engine's reconnection behaviour.

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

**Health probes** (require `web.enabled: true` — served on the loopback web listener):
- `GET /healthz` — liveness, always 200 while serving
- `GET /readyz` — readiness, 200 once the daemon holds a Vault token AND has marked the initial sync complete (mirrors the `sd_notify(READY=1)` contract). 503 otherwise. Token check reflects the cached in-memory state, not a per-probe Vault round-trip.

**API:**
- `GET /api/v1/csrf` — issue CSRF token (one-time use, max 1000 in memory)
- `GET /api/v1/status` — server status (auth, vault version, token TTL, sync state, vault address, kv_mount, user_prefix, username)
- `GET /api/v1/rules` — configured sync rules
- `GET /api/v1/config` — redacted view of the running config for the UI
- `GET /api/v1/config/download?format=yaml|reg` — full config download for the Effective Configuration screen
- `GET /api/v1/secrets/{path}` — list or reveal secret (reveal requires `?reveal=true`)
- `POST /api/v1/sync` — trigger immediate sync (CSRF-protected)

**Security headers:** `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff`.

**DNS-rebinding defence:** the middleware rejects any request whose `Host` header is not a loopback alias (`127.0.0.1`, `::1`, `localhost`) or the configured `web.listen` hostname. Loopback binding alone doesn't stop a hostile origin from resolving its own DNS name to `127.0.0.1` and using a victim's browser as a relay; the Host check ensures the daemon refuses such requests before any handler runs.

Configurable markdown content via `web.login_text` and `web.secret_view_text` fields rendered by `internal/web/markdown.go`.

## Windows Registry / Group Policy

When HKLM registry keys exist at `SOFTWARE\Policies\goodtune\dotvault`, the daemon loads all config from registry and ignores the YAML file. The `registryLayer` struct reads Vault, Sync, and Web settings from typed subkeys (REG_SZ, REG_DWORD). Rules are subkeys under `Rules\{RuleName}` with an optional `OAuth` subkey.

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

## Dependency Updates

Dependabot is configured in `.github/dependabot.yml` and currently covers:

- `gomod` at repo root
- `npm` at `internal/web/frontend`
- `github-actions` at repo root

When introducing a new package ecosystem (e.g. a second npm workspace, a Dockerfile, a Python tool directory), extend `.github/dependabot.yml` with a matching `updates:` entry so the new manifests are kept up to date. Use the same weekly schedule and grouped-updates pattern as the existing entries unless there is a reason to diverge.
