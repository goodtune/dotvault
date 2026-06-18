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

All builds use `CGO_ENABLED=0` for static binaries. Version is injected via ldflags (`-X main.version=...`). Release tags are `v`-prefixed (`v0.19.0`) for Go-module consumption, but `main.version` is the v-stripped semantic version (`0.19.0`): GoReleaser's `{{.Version}}` strips the prefix and the Makefile strips it via `sed`, so local and release builds agree. Consumers (the `version` command, `/api/v1/status`, the OTel `service.version` attribute, the tray tooltip, and the web UI header which prepends its own `v`) treat the value as v-stripped and must not add or assume a leading `v`.

Windows ships two binaries from the same source — the PE subsystem flag is immutable post-link, so the only correct fix is to build twice:

- `dotvault.exe` — Console subsystem. The CLI for `sync`, `status`, `run` (foreground daemon), `reg-export`/`reg-import`, etc. cmd.exe / PowerShell wait for it, stdio is inherited, Ctrl+C works. Bare invocation prints help.
- `dotvaultw.exe` — GUI subsystem (`-H=windowsgui`). For double-click. Runs the daemon with the system-tray icon and no console flash. Bare invocation defaults to the daemon (equivalent to `dotvault run`) because there's no console to show help on; this is detected at runtime via `os.Args[0]`. CLI subcommands invoked through it will appear to do nothing because cmd.exe does not wait for GUI-subsystem binaries — use `dotvault.exe` for CLI work.

Installer / Start Menu shortcuts should point at `dotvaultw.exe`; the PATH entry should be `dotvault.exe`.

Both Windows binaries embed the application icon **and** a `VS_VERSIONINFO` resource (the latter is what populates Explorer's right-click → Properties → Details tab: File version, Product version, Company, File description, Copyright). `assets/dotvault.ico` is the multi-resolution source (16/24/32/48/64/128/256, generated from `assets/dotvault-no-text.png`); `assets/versioninfo.json` holds the static string metadata. The Makefile and the `.goreleaser.yml` `before:` hook run `go tool goversioninfo` (replacing the icon-only `go tool rsrc`) to emit `cmd/dotvault/rsrc_windows_amd64.syso`, which the Go linker picks up automatically for `windows_amd64` targets and ignores everywhere else. The version is injected at generation time, not stored in the JSON: the full v-stripped `VERSION` string fills the string `FileVersion`/`ProductVersion` fields, and its `major.minor.patch` core (with build `0`, falling back to `0.0.0` for an untagged build) fills the numeric `FixedFileInfo` block, which requires four 16-bit integers. Both binaries are built from `cmd/dotvault`, so the single `.syso` is linked into each — they carry identical version metadata and share the static `OriginalFilename` string (`dotvault.exe`). The `.syso` is a build artefact (regeneratable, gitignored). The system-tray code in `internal/tray/tray_windows.go` loads the icon by resource ID rather than the stock `IDI_APPLICATION`, so the tray, taskbar, and Start Menu shortcuts all carry the dotvault glyph; if the resource is missing (e.g. a hand-rolled `go build` skipping the `.syso`) the tray falls back to the system default.

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
client/                  Public, importable Go API (facade over internal/{config,auth,vault}) — see "Public client API"
internal/
  config/                Config loading: YAML file + Windows Registry (GPO)
  regfile/               .reg ⇄ YAML conversion (reg-import/reg-export, web config download)
  paths/                 OS-specific path resolution
  vault/                 Vault client wrapper, KVv2 operations, Events API (WebSocket)
  remoteconfig/          Remote config overlay: ETag-conditional fetcher, last-known-good cache, fail-open ladder
  auth/                  Auth orchestration (OIDC, LDAP with MFA, token, mtls/mtls+tpm cert auth)
  securestore/           Platform-agnostic key store for cert auth: file + build-tagged TPM (Linux/Windows) backends; non-Linux/Windows (incl. macOS) falls back to ErrUnsupported pending a Secure Enclave backend
  loginsuppress/         login-check suppression marker (path/window/freshness/refresh)
  passwd/                /etc/passwd parsing for login-check --no-passwd (local vs directory account)
  observability/         OTel metrics + logs SDK wiring, package-level instrument helpers
  sdnotify/              Tiny sd_notify(3) helper (READY/STOPPING/WATCHDOG); no-op off Linux
  tokenwatch/            Watches ~/.dotvault-token for replacement (inotify on Linux); no-op elsewhere
  httpproxy/             Per-request proxy resolver (ieproxy/PAC on Windows, env vars elsewhere) + http.Client builder
  sync/                  Hybrid event+poll sync engine, state store
  handlers/              File format handlers (yaml, json, ini, toml, text, netrc, ssh_config)
  tmpl/                  Go template rendering (named tmpl to avoid shadowing text/template)
  enrol/                 Credential acquisition via OAuth device flow
  web/                   Web UI server (Preact SPA), auth endpoints, REST API
  perms/                 File permission checks (Unix mode bits, Windows DACL)
  tray/                  Windows system-tray icon (no-op on other platforms)
  agent/                 SSH agent: read-only ExtendedAgent backend + Unix-socket (Linux/macOS) and named-pipe (Windows) listeners
test/integration/        Integration tests against real Vault
packaging/windows/       NSIS installer script + build helper
packaging/linux/         systemd units (dotvault.service, shipped in RPM/DEB/APK)
```

## Configuration

YAML config file at platform-specific system paths:

- macOS: `/Library/Application Support/dotvault/config.yaml`
- Linux: `/etc/xdg/dotvault/config.yaml` (also checks `$XDG_CONFIG_DIRS`)
- Windows: `%ProgramData%\dotvault\config.yaml`

On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\goodtune\dotvault`, configuration is loaded entirely from the registry and the file-based config is ignored. Only machine-level (HKLM) policy is read; HKCU is intentionally skipped because it is user-writable.

### Config Sections

- **`bypass_system_config`** (top-level) — bool, default false. Gates whether the `--config` command-line override is honoured. With a system-wide config present, `--config` is refused (the daemon exits with an error) unless the *system* config sets this true. Enforcement lives in `cmd/dotvault` (`resolveConfigSource` → `config.SystemConfigBypass`); the field is just data and behaves identically on every platform. "System-wide config" is the Windows GPO registry policy when present, else the YAML at `paths.SystemConfigPath()`. When the bypass is allowed and `--config` is used, the file is loaded via `config.Load` (deliberately bypassing the registry on a GPO machine that opted in). Round-trips through the registry (`BypassSystemConfig` REG_DWORD directly under the policy root key, not a subkey), `.reg`, and YAML. `reg-import`/`reg-export` deliberately are *not* subject to the gate — they are conversion tools whose `--config`/positional input selects the YAML to convert, not a daemon config to run.
- **`vault`** — address (required), auth_method (`oidc`/`ldap`/`token`/`mtls`/`mtls+tpm`; any base method also accepts a `+tpm` suffix — `oidc+tpm`, `ldap+tpm`, etc. — which TPM-seals the cached token file at rest, see Authentication), auth_mount, auth_role, kv_mount (default `"kv"`), user_prefix (default `"users/"`, trailing slash enforced), ca_cert, tls_skip_verify, disable_token_renewal (default false — set true to prevent the daemon from calling RenewSelf; TTL expiry still triggers re-auth). The nested **`vault.mtls`** block configures the cert auth methods (consulted only when auth_method is `mtls`/`mtls+tpm`): `bootstrap_method` (`ldap`/`oidc`, default `oidc`), `bootstrap_mount`, `cert_mount` (default `cert`), `cert_role` (required), `pki_mount` (default `pki`), `pki_role` (required unless BYO), `key_type` (`ec`/`rsa`, default `ec`; `rsa` rejected for `mtls+tpm`), `common_name` (template over `{{.user}}`, default `{{.user}}`), `ttl`, `reissue_before` (default `168h`), `seal_to_pcrs` (mtls+tpm boot-state binding), `storage_dir` (default `{cache_dir}/mtls`), and `byo.cert`/`byo.key` (both-or-neither bring-your-own seeding). Validated by `validateMTLS`; round-trips through registry/`.reg`.
- **`sync`** — interval as Go duration string (default `15m`)
- **`web`** — enabled (default false), listen (loopback only, hard invariant), login_text (markdown), secret_view_text (markdown)
- **`observability`** — enabled (default false), endpoint, protocol (`grpc` or `http/protobuf`), insecure, headers (map), export_interval. OTLP metrics + logs exporters share the same block: a single endpoint/protocol/headers configuration drives both signals. Falls through to standard `OTEL_*` env vars when fields are empty (signal-specific overrides `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` / `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL` take precedence over the generic `OTEL_EXPORTER_OTLP_PROTOCOL`). For `http/protobuf` the endpoint must be a *base* URL like `https://otel.example` — the exporters append `/v1/metrics` and `/v1/logs` themselves, so a URL that already includes a signal-specific path routes both signals to the wrong route. Disabled by default — metric instruments fall back to the OTel no-op meter and `Log*` helpers fall back to the no-op global logger, so call sites never need to branch. **Treat `headers` as a credential** — values typically carry OTLP bearer tokens (Datadog / Grafana Cloud / etc.). Config conversion is lossless in every direction, so `headers` round-trip verbatim through YAML, `.reg`, and the registry (and through the web config-download endpoint); nothing strips them. Operators who want tokens kept out of a checked-in or downloaded config should leave `headers` empty and set them via `OTEL_EXPORTER_OTLP_HEADERS` in the per-user `EnvironmentFile` (`~/.config/dotvault/env`), which the SDK falls through to. Store the config file at 0600. The daemon does scrub `headers` from its own long-lived in-memory `Config` after the OTel SDK consumes them (heap hygiene, `cmd/dotvault/main.go`); when the web UI is enabled it retains a separate copy so the download stays lossless.

  Logs vs. slog: the OTel logs exporter is **not** a slog replacement. Operational logging continues to go through `log/slog` to stderr. The OTel logger is reserved for deployment-fact records that should reach a central collector but must not noise up an end user's terminal — currently only `LogRegistryConfigManaged`, which surfaces "GPO config is active, file config is ignored" as a WARN record once per daemon/sync startup. Routing this through slog would print an INFO line on every CLI invocation against a GPO-managed Windows box, which is exactly the noise we wanted to eliminate.
- **`remote_config`** — optional remote configuration overlay (design: `docs/superpowers/specs/2026-06-10-remote-config-design.md`). `url` (https required except loopback hosts; empty disables), `refresh_interval` (duration string, default = sync interval, floor 1m), `ca_cert` (CA pin for the fetch; deliberately no skip-verify option), `headers` (extra dimension headers, e.g. `X-Dotvault-Env`; cannot override the built-in `X-Dotvault-OS/User/Arch/Hostname/Version` identity headers). When `url` is set the local config becomes the *base*: the client fetches a partial document — dynamic sections only (`rules`, `enrolments`, `sync`); static sections in a remote document are a hard error, unknown sections warn-and-ignore — and merges it on top before validation. Rules merge by name (same-named rule replaced wholesale, new names appended), enrolments by map key, `sync.interval` scalar override; additive-only, no tombstones (removal converges because base ⊕ fresh-remote is recomputed every refresh). Fetching fails open: fresh → cached last-known-good (`{cache_dir}/remote-config.json`, identity-bound, 0600) → base alone with a warning. The ≥1-rule validation requirement applies only when no remote URL is configured. `run`/`sync`/`status`/`enrol` use the merged loader; `login`/`login-check` (shell-startup latency budget) and `reg-import`/`reg-export` (pure converters) stay local-only. The section is itself local-only and round-trips through the registry (`RemoteConfig` subkey + `Headers` subkey), `.reg`, and YAML like every other section.
- **`rules`** — array of sync rules (name, vault_key, target.path, target.format, target.template, target.merge)
- **`enrolments`** — map of Vault KV path segment to engine config for credential acquisition. A key may use a single-level `group/name` form (e.g. `databricks/prod`) to organise related enrolments; the group becomes a nested Vault path segment (`users/<you>/databricks/prod`) and an expandable folder in the web UI. Exactly one level is allowed — more than one `/`, a leading/trailing `/`, an empty segment, or a backslash is rejected at config load (`validateEnrolmentKey`)
- **`agent`** — SSH agent surface (default disabled). `enabled`, `unix.path` (default per-user runtime socket), `windows.pipe` (default `\\.\pipe\dotvault-agent`), `windows.putty` (default true; Windows-only `*bool` tri-state — when enabled, the daemon serves a *second* parallel listener on the Pageant-convention pipe `\\.\pipe\pageant.<user>.<hash>` so PuTTY-family clients auto-discover the agent; only takes effect when `agent.enabled`), and an ordered `keys[]` list of sources: `source: kv` (`path_prefix`, resolved under `kv/data/users/<you>/`) and `source: vault-ca` (`mount`, `role`, templated `principals`, `ttl`, `ephemeral_key`)

### Config Validation

- `vault.address` is required
- At least one rule is required
- Rule names must be unique
- `target.format` must be one of: yaml, json, ini, toml, text, netrc, ssh_config
- `web.listen` must resolve to a loopback address if web is enabled
- Enrolment entries must have a non-empty engine field
- Enrolment keys are flat (`gh`) or one-level grouped (`group/name`); at most one `/`, no empty segments, no backslash
- When `agent.enabled`, at least one `agent.keys[]` source is required; each must be `kv` or `vault-ca`; a `vault-ca` source requires `mount` and `role`, and its `ttl` (if set) must parse as a positive duration

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
- `--no-passwd` exits 0 immediately when the current user has an entry
  in `/etc/passwd` — in directory-service fleets a passwd entry means a
  local machine account with no Vault credentials, so a fleet-wide
  profile.d script can pass the flag unconditionally. The file is
  parsed directly (`internal/passwd/`), never via getent/NSS, because
  merged-source lookups cannot say which source an entry came from.
  NIS/compat `+`/`-` splice lines are skipped (they reference directory
  sources, not local accounts). Ignored with a WARN log on Windows. A
  passwd read failure warns and falls through to the normal check (fail
  open; exit 1 stays reserved for genuine internal errors). The check
  runs after the suppression-marker freshness check and refreshes the
  marker on early exit, so subsequent shells in the window stop at the
  marker without re-reading the file. The heuristic is Linux-targeted:
  macOS keeps local accounts in Open Directory, so the lookup never
  matches a human there and the flag degrades to a no-op (falls through
  to the normal check — it cannot wrongly skip auth). Test override:
  `DOTVAULT_PASSWD_FILE`.
- If a cached token is valid and still within the first half of its
  creation TTL, exit clean.
- If the cached token is valid but past the halfway mark, attempt renewal.
  On renewal failure where the token is still valid, warn with the
  absolute expiry time and exit 0.
- If the cached token is missing or invalid, print a one-line
  explanation of why an authentication prompt is about to appear
  ("no cached Vault token was found", "the cached Vault token has
  expired", "the cached Vault token is no longer valid") and then
  run the configured login flow. The line is yellow on a colour-capable
  TTY (ANSI SGR 33; honours `NO_COLOR`; ANSI is gated on the writer
  being `os.Stderr` so test buffers / piped output stay plain) and
  plain text otherwise. Without it, a profile-script invocation would
  drop the user straight into a context-free password prompt. Pass
  `--quiet` to suppress just the notice (the prompt still appears) for
  wrappers that surface their own context. Ctrl-C exits immediately
  without requiring an extra Enter: a dedicated signal handler restores
  the terminal state captured before the password prompt, refreshes the
  marker, and `os.Exit(0)`s (`term.ReadPassword` does not observe
  context cancellation, so going through a goroutine + `os.Exit` is the
  only reliable way to honour the contract).
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
2. Create Vault client, attempt token reuse (DOTVAULT_TOKEN env or `~/.dotvault-token`)
3. Start web UI if enabled (before auth, so it can serve browser-based login)
4. Authenticate if needed: web mode routes all auth through the SPA; CLI mode uses method-specific flows (OIDC browser, LDAP terminal prompt, token file). A non-interactive host with neither a web UI nor a TTY does not give up — it registers a synchronous token-file watch and idles until an external facility (e.g. a login profile running `dotvault login`) writes a usable token, then resumes startup. The watch is registered before the no-token decision so a token written during startup cannot be missed; this replaced the previous behaviour where a headless daemon idled until shutdown and required a restart to pick up a token (`waitForHeadlessToken`, `cmd/dotvault/main.go`).
5. Start token lifecycle manager (renews at 75% TTL, exponential backoff 1s-5m on failure)
6. Start RefreshManager (rotates expiring credentials for `Refresher` engines, e.g. JFrog) and WatchManager (re-mirrors upstream sources for `Watcher` engines, e.g. Copy)
7. Run enrolment check (wizard if any credentials missing in Vault)
8. Start sync engine: initial sync, then hybrid event+poll loop
9. Background config-refresh loop (all daemon modes — web, headless, CLI) re-runs the startup loader every `remote_config.refresh_interval` (default: sync interval): the remote overlay re-fetches with an ETag-conditional GET, and dynamic-section changes fan out — enrolments to the enrolment manager (CLI mode), RefreshManager, WatchManager, and the web enrolment runner (deferred while an enrolment is mid-run); rules and sync interval to `sync.Engine.UpdateConfig` (state entries for removed rules pruned, ticker reset, immediate sync trigger) and the web server's locked snapshots
10. On Windows, install a system-tray icon (`internal/tray/`) with Exit and (when web is enabled) "View web UI" entries; the tray owns the main goroutine because the Win32 message pump must run on a locked OS thread, while the sync loop moves to a goroutine. On non-Windows the same call simply blocks on ctx.

The daemon watches `~/.dotvault-token` for replacement and re-reads it immediately via `LifecycleManager.Reload` — handy for picking up a token freshly written by `dotvault login` without waiting for the 5-minute lifecycle tick. On Linux this uses inotify on the token file's parent directory (`internal/tokenwatch/`, watching the directory rather than the inode because atomic writers replace it via temp-file+rename); creation and write-completion events trigger a reload, deletes are ignored so the daemon keeps using its current in-memory token until a new one is written. On non-Linux platforms the watcher is a no-op. This replaces the previously shipped `dotvault-token-watch.path`/`.service` systemd units, which forwarded token-file changes to the daemon via SIGHUP out-of-process. SIGHUP still triggers the same re-read manually (`LifecycleManager.Reload`) on every platform where it is delivered (not Windows), e.g. `systemctl --user kill --signal=SIGHUP dotvault.service`, which targets the unit's MainPID rather than scanning the process table for anything named `dotvault`, so a developer running `go run ./cmd/dotvault` or `dotvault sync` from a shell while the daemon also happens to be running won't have those side processes SIGHUP'd (their default disposition for SIGHUP is *terminate*).

Full config reload via SIGHUP is **not implemented**. The dynamic sections — rules, enrolments, and the sync interval — converge on the config-refresh tick in every daemon mode (whether the change came from the remote overlay or an edited local config); the static sections (vault, web, agent, observability, and `remote_config` itself) still require a full restart. Known cadence limitations: the WatchManager poll interval and the RefreshManager check interval are fixed at construction.

## Authentication

### Methods

- **OIDC** — Requests auth URL from Vault, opens browser, listens on random localhost port for callback, exchanges code for Vault token
- **LDAP** — Prompts for password; supports MFA (Duo push and TOTP) via the LoginTracker async state machine
- **Token** — Reads from DOTVAULT_TOKEN env var or `~/.dotvault-token`. The upstream `VAULT_TOKEN` variable is deliberately ignored everywhere — including the Vault SDK's automatic pickup, which `internal/vault.NewClient` neutralises by setting the token unconditionally — so a concurrent `vault` CLI session's environment never leaks into the daemon or external `client/` consumers
- **mTLS** / **mTLS+TPM** — A TLS client certificate authenticates against Vault's `cert` auth method instead of a human credential; LDAP/OIDC is demoted to a one-time bootstrap that mints the first certificate via the PKI engine (`pki/sign/<role>`). Orchestration is `internal/auth/mtls.go` (`Manager.authenticateMTLS`: load-or-seed → cert login), the on-disk envelope `internal/auth/mtls_envelope.go` (`{cache_dir}/mtls/credential.json`, 0600 — for `mtls+tpm` the private key is never in plaintext, only the sealed blob). The private key sits behind the platform-agnostic `internal/securestore` seam: a `file` backend (software key, plain `mtls`) and a build-tagged TPM backend (Linux `/dev/tpmrm0`, Windows TBS — EC P-256 only, sealing the scalar via go-tpm-tools). The SRK is derived as a *transient* primary (`client.NewKey` + `SRKTemplateECC`, `loadSRK` in `tpm.go`) rather than `client.StorageRootKey*`: the latter persists via `TPM2_EvictControl`, an owner-hierarchy op Windows TBS denies to standard users (`0x80280400`) even on a healthy TPM; primary keys are deterministic, so re-deriving each operation costs nothing and unseals prior blobs. `seal_to_pcrs` binds to PCRs 0/2/4/7 on Linux but **excludes PCR7 on Windows** (`pcrSelectionFor`) because BitLocker claims it there. macOS Secure Enclave is a stub returning `ErrUnsupported` until the binary is code-signed, so `mtls+tpm` errors there rather than silently degrading to a plaintext key. `tls.Certificate.PrivateKey` only needs `crypto.Signer`, so one assembly path serves every backend. Cert presentation is wired through `vault.Config.ClientCert` (a `GetClientCertificate` callback that invokes the signer lazily). Re-issuance is proactive: at auth time a cert inside `reissue_before` is rotated using the still-valid cert. The `vault.mtls` block round-trips through YAML, the registry (`Vault\MTLS` + `Vault\MTLS\BYO`), and `.reg`. See `docs/authentication/mtls.md` (certificate auth) and `docs/authentication/tpm.md` (the TPM hardware backend, shared with token sealing). Known v1 limits: first-run bootstrap runs the CLI-style OIDC (browser) or LDAP (TTY) flow directly and takes precedence over web-driven auth even when the web UI is enabled, so it needs a browser or TTY (or a BYO cert) on the host — the web-SPA bootstrap is not wired because the SPA only obtains an operational token, not the login→`pki/sign`→seal→cert-login issuance flow; and the TPM backend is not hardware-tested in CI.

### TPM token sealing (`+tpm` suffix)

A `+tpm` suffix on a token-minting base auth method (`oidc+tpm`, `ldap+tpm`, `mtls+tpm`) seals the cached Vault token in `~/.dotvault-token` at rest under the TPM. The suffix is a general modifier parsed by `auth.BaseMethod` / `auth.SealTokenAtRest` (`internal/auth/method.go`): `BaseMethod` strips it for login dispatch, `SealTokenAtRest` reports it for the write path. The suffix parses on any base for uniformity, but `token+tpm` is inert for sealing — the bare `token` method consumes a token you supply and never writes the file itself, so there is nothing for dotvault to seal (it will still transparently *read* a sealed file). For `mtls+tpm` this is *additive* — the cert key was already TPM-sealed; now the operational token is too, so nothing sensitive is on disk in plaintext. For `oidc+tpm`/`ldap+tpm` the token sealing is the only TPM use (the login flow is otherwise unchanged).

The token file is **self-describing**: when sealing is on, `WriteTokenFile` writes a `$dotvault-tpm-sealed$v1$`-prefixed, base64 envelope around the TPM-sealed bytes; `ReadTokenFile` detects that prefix and transparently unseals via the TPM, returning a plaintext file verbatim otherwise. Detection is from the file content alone, so **every reader consumes a sealed token without knowing the auth method** — the daemon, `dotvault status`/`enrol`, the token-file watcher, and crucially the exported `client/` facade (which already routes reads through `auth.ResolveToken`). This is also why migration is free: an existing plaintext token keeps working, and the first `+tpm` login replaces it with a sealed one.

Sealing reuses the same TPM backend as the cert key (`securestore.SealData`/`UnsealData`/`HardwareAvailable`, behind the `securestore.DataSealer` capability; the `file` backend deliberately does *not* implement it — sealing under a software key on the same disk buys nothing). The token is SRK-bound only, **never** PCR-bound: it is ephemeral and re-derivable, so binding it to boot state would needlessly strand it across a firmware update. Two invariants follow the mtls+tpm precedent: there is **no silent plaintext fallback** — a `+tpm` method on a host with no TPM fails fast at login (a `securestore.HardwareAvailable` preflight in `Manager.Login`, skipped for the `mtls` base which owns its own check) and `WriteTokenFile(..., seal=true)` errors rather than writing plaintext — and the `DOTVAULT_TOKEN` **env var is always plaintext** (an environment value cannot be sealed), so sealing applies to the file only. A sealed file that cannot be unsealed (cleared TPM, copied to another machine) resolves to "" and triggers re-authentication.

### LoginTracker

Async login state machine (`internal/auth/login.go`) shared by CLI and web paths. States: `pending` -> `mfa_required` -> `authenticated` | `failed`. The web frontend polls status; CLI polls at 500ms intervals. Session IDs are server-generated (random 32 bytes, hex-encoded).

### Token Lifecycle

`LifecycleManager` checks token TTL every 5 minutes. Renews at 75% remaining TTL.
On detecting an invalid/expired token (403 Forbidden or TTL=0 + concrete
`expire_time`) the manager runs a recovery sequence:

1. Re-read the token file (and `DOTVAULT_TOKEN` env). If a different value
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

## Public client API

`client/` (`github.com/goodtune/dotvault/client`) is the only supported import boundary for other Go modules. It is a thin facade over `internal/config`, `internal/auth`, and `internal/vault` that exposes dotvault's connectivity, token-resolution order, login flow, and `kv/users/<user>/...` path convention so a consumer reads from exactly where dotvault writes instead of re-deriving any of it. The surface is deliberately generic — it makes no assumptions about the calling tool. The internals stay internal; the facade lets them be refactored freely. See `client/README.md` for the consumer-facing write-up.

Surface: `LoadConfig(path)` (projects the validated system config onto a connectivity-and-auth-only `Config`; `DefaultConfigPath()` / `DefaultTokenFile()` give the canonical locations), `New(cfg, ...Option)`, and on `*Client`: `Authenticate` (env → file → interactive login, short-circuiting `ErrUnreachable` without prompting), `AuthenticateCached` (env → file only, never prompts — for side-effect-free `doctor`-style preflight, returns `ErrLoginRequired` when no token is usable), `Login` (unconditional fresh login, `= dotvault login`), `IdentityName`, `Token`, `ReadKVField(ctx, mount, path, field)`, and `ReadUserSecret(ctx, service, field)` (composes `{kv_mount}/{user_prefix}{identity}/{service}`). Reads return `(value, found, err)` so a missing path/field is `found == false` with `err == nil`, never conflated with a transport failure. Error categories are `errors.Is`-able sentinels: `ErrLoginRequired`, `ErrAuthFailed`, `ErrDenied`, `ErrUnreachable`. `New` takes functional `Option`s (extension point kept open so future inputs don't break callers); `WithIdentity(name)` overrides the path-identity segment. The exported `Reader` interface (`IdentityName`/`ReadKVField`/`ReadUserSecret`, which `*Client` satisfies) is the seam consumers depend on and fake in tests — auth is excluded from it because it has side effects that belong in `main`.

**Identity is the OS user, not the token.** `IdentityName` (deliberately ctx-less — a local OS lookup, no Vault call) returns `paths.Username()` (the OS account, `DOMAIN\` prefix stripped) — the same value the sync engine and enrolment manager use to lay out `kv/users/<user>/...`. It is deliberately *not* derived from the Vault token's `display_name`/entity/metadata, because that is not what dotvault writes under. Consumers must therefore run as the same OS user as the dotvault that populated the secrets (normally true for a per-user daemon) or pass `WithIdentity(name)` to set the segment explicitly when they can't (a service account, a container) — `WithIdentity` also makes downstream tests deterministic. This is the one place the public API contradicts a naive "identity comes from the token" assumption, and it is load-bearing — changing the *default* derivation would be a path-layout migration, not a facade tweak.

The facade legally imports `internal/*` because it lives inside the same module; external modules import only `client`, never the internals. When the connectivity/auth shape of the system config changes, update the `client.Config` projection (`client/config.go`) in lockstep so the public surface doesn't silently drift from what the daemon parses.

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
| ssh_config | Custom parser (no external dep) | Surgical directive-level merge within each Host/Match section; comments and unmanaged directives preserved verbatim. Template-only (no raw-data path) |

The `merge` field exists in rule config but is not dispatched on. Each handler always uses its native merge strategy, which is the only sensible strategy for that format.

All writes are atomic (temp file with target permissions + rename). Permissions: all managed files use 0600.

## Template Processing

`internal/tmpl/` wraps `text/template` with custom functions:

- `env(key)` — environment variable lookup
- `base64encode(s)` / `base64decode(s)` — credential encoding
- `default(fallback, val)` — Sprig convention (fallback first)
- `quote(s)` — shell-safe single quoting
- `username` — the OS account dotvault runs under, i.e. the same `paths.Username()` identity the `kv/users/<username>/…` layout is built from (`DOMAIN\` stripped). It is a function rather than a dot-context field so it is available regardless of the secret's contents and cannot be shadowed by a secret field named `user`. Bound by `tmpl.RenderWithUsername` (the sync engine passes `e.username`); plain `tmpl.Render` leaves it bound to `""`. This is the seam that lets a rule template build per-user paths like `/home/{{ username }}/.ssh/agent.sock` without the username being stored in Vault.

Templates receive the Vault KV data map as dot context. The rendered output is parsed by the target format's handler to produce structured incoming data. The dot context is *only* the secret's fields — there is no implicit `.user`; per-user values that aren't secret data come from the `username` function instead.

## Enrolment

Automated credential acquisition from external services (`internal/enrol/`). Enrolments are declared in config under a top-level `enrolments` map keyed by Vault KV path segment.

Enrolment keys support one level of grouping (`group/name`, e.g. `databricks/prod`) so related enrolments cluster under a shared prefix. The key is treated as an opaque segment everywhere it flows: the Vault path nests naturally (`users/<you>/databricks/prod`); the web UI groups by the prefix-before-slash and renders an expandable folder (`internal/web/frontend/src/components/enrol-page.jsx`); the web API serves grouped keys through both a percent-encoded `{key}` segment and parallel `{group}/{name}` routes (`enrolKeyFromRequest`, `server.go`); and the Windows registry / `reg-import`/`reg-export` round-trip stores the key as one subkey literally named `databricks/prod` (a forward slash is legal in a registry key *name* — only backslash is the separator — so no nesting is introduced and the GPO-parity contract holds). `validateEnrolmentKey` (`internal/config/config.go`) enforces the one-level limit.

### Engine Interface

Engines implement `Name()`, `Run(ctx, settings, io)`, and `Fields()`. Registered in a package-level map. Currently implemented: GitHub (OAuth device flow), JFrog (browser-based web login), Databricks (OAuth U2M authorization-code + PKCE), SSH (Ed25519 key generation), Copy (mirror an existing KVv2 secret).

Optional interfaces extend the contract for engines that need them:

- `SettingsFielder.FieldsFromSettings(settings)` — engines whose written-field set depends on per-enrolment settings (currently the Copy engine, where the JSON template determines the keys). The manager and web runner use `EngineFields(engine, settings)` which falls back to `Fields()` when not implemented.
- `Refresher.Refresh(ctx, settings, existing)` — engines whose credentials expire and can be rotated without user interaction (currently JFrog and Databricks). Driven by `RefreshManager`.
- `Watcher.WatchSources(settings, username) []WatchSource` — engines whose output is derived from upstream Vault data and must track source changes (currently Copy). Driven by `WatchManager`, which polls every sync interval and (on Enterprise Vault) reacts to source-write events within seconds.

### GitHub Engine Defaults

- Client ID: `178c6fc778ccc68e1d6a` (GitHub CLI's OAuth app)
- Scopes: `repo`, `read:org`, `gist`
- Host: `github.com`

Overridable via settings: `client_id`, `scopes`, `host`. Returns `{"oauth_token": "<token>", "user": "<username>"}`.

Outbound HTTPS (device-code request, polling, and the post-flow `/user` lookup) is routed through `internal/httpproxy`. By default the resolver consults the host's native proxy machinery — on Windows that's `ieproxy.GetProxyFunc()`, which evaluates the IE/WinHTTP configuration (PAC scripts included) once per request, so a policy returning DIRECT for one host and a proxy for another is honoured. On Linux and macOS the resolver falls back to `http.ProxyFromEnvironment` (HTTP_PROXY / HTTPS_PROXY / NO_PROXY); native CFNetwork detection on macOS would require CGO and is deliberately avoided. A per-enrolment override is available via the `https_proxy` (or `http_proxy`, accepted as an alias) setting — when set, every request is pinned to that URL and host-conditional PAC routing is bypassed, by design. The override accepts the `http`, `https`, `socks5`, and `socks5h` schemes; anything else fails at config-load. The settings adapter lives in `internal/httpproxy.ClientFromSettings` so the JFrog engine and any future HTTP-talking package can opt in to the same YAML key contract without duplication (#76). Example:

```yaml
enrolments:
  gh:
    engine: github
    settings:
      https_proxy: http://squid.example.com:3128
```

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
4. POST `{url}/access/api/v1/tokens` with `Authorization: Bearer <bootstrap>` and `{"expires_in":<token_ttl_seconds>,"refreshable":true,"scope":"applied-permissions/user","include_reference_token":true}` — mints the dotvault-owned pair; the bootstrap token is discarded. v1 rather than v2 because v2 is admin-only on most JFrog deployments (non-admins and older Artifactory versions see it as a 404); v1 has been the self-token endpoint since Artifactory 7.21.1 and is what `jfrog-client-go` uses. `include_reference_token` is always sent so the response also carries an opaque `reference_token` alongside the JWT `access_token`; on servers older than Access 7.38.4 the field is simply absent and `reference_token` is stored empty.

Flow (refresh — periodic, driven by `RefreshManager`):
1. Every `check_interval` (daemon-wired at 5 min), iterate all enrolments whose engine implements `Refresher`
2. For each, read the secret and skip unless `now >= issued_at + (expires_at - issued_at) / 2`
3. POST `{url}/access/api/v1/tokens` with `grant_type=refresh_token&access_token=<current>&refresh_token=<current>&include_reference_token=true` — **JFrog rotates both tokens (and the reference token) on every successful refresh**, so the old refresh_token is invalid immediately
4. Stamp new `issued_at: now`, `expires_at: now + token_ttl` (dotvault's configured TTL, not whatever JFrog returns), write the replacement map atomically
5. `401`/`403` from the refresh endpoint is treated as permanent revocation — the secret is deleted from Vault and the user is prompted to re-enrol. Other errors are transient; the existing secret is kept and retried with exponential backoff

Vault schema (8 fields): `access_token`, `refresh_token`, `reference_token`, `url`, `server_id`, `user`, `issued_at` (RFC3339), `expires_at` (RFC3339). The rendered `jfrog-cli.conf.v6` only contains `accessToken` — `refreshToken` and `webLogin: true` are deliberately omitted so `jf` never attempts its own refresh (which would race the sync-engine clobber). `reference_token` is the opaque equivalent of the JWT access token — useful where a compact credential is preferred (Docker/registry logins, clients that choke on long JWTs). It is captured unconditionally but not written to any target by default; a sync rule opts in by referencing `{{ .reference_token }}` in its template.

`server_id` is deduced from the platform hostname (e.g. `mycompany.jfrog.io` → `mycompany`, IP addresses → `default-server`); `user` is extracted from the access-token JWT subject. Requires JFrog Artifactory 7.64.0 or newer on the remote side. `reference_token` additionally requires Access 7.38.4 or newer; older servers leave it empty.

`reference_token` and `user` are written when available but are deliberately excluded from the engine's `Fields()` set, so `enrol.Manager.HasAllFields` does not reject enrolments on deployments that don't return them.

### Databricks Engine

Replicates the `databricks auth login` OAuth user-to-machine (U2M) flow: an authorization-code grant with PKCE against the workspace (or account) OAuth endpoints, caught by a localhost redirect listener. Databricks access tokens are short-lived (~1 hour), so the engine implements `Refresher` and dotvault owns the rotation — the rendered credential carries only the access token (the native CLI token cache is intentionally not written, so nothing races the sync-engine clobber). This is the same ownership model as JFrog.

Required settings:
- `host` — the Databricks workspace URL (https, scheme + host only, no path; e.g. `https://dbc-xxxx.cloud.databricks.com`). For account-level login, the accounts console URL. (This is the Databricks analogue of the JFrog engine's `url` setting.)

Optional settings:
- `account_id` — when set, the engine performs account-level login (`{host}/oidc/accounts/{account_id}/…`) instead of workspace login.
- `client_id` — default `databricks-cli` (the CLI's public OAuth app). Override only for a custom registered OAuth app that also registers the `http://localhost:8020`–`8040` redirect range.
- `scopes` — default `offline_access all-apis`. A custom list is honoured verbatim except `offline_access` is always ensured (it yields the refresh token dotvault rotates with).
- `https_proxy` / `http_proxy` — same `internal/httpproxy.ClientFromSettings` contract as GitHub/JFrog; routes the OAuth + SCIM traffic.

Flow (enrolment — runs once per user):
1. GET `{host}/oidc/.well-known/oauth-authorization-server` (account-level inserts `/oidc/accounts/{account_id}`) to discover `authorization_endpoint` and `token_endpoint`.
2. Bind a loopback redirect listener (prefer port 8020, walk up to 8040, matching the CLI). Generate a PKCE verifier + `S256` challenge and an anti-CSRF `state`.
3. Open the browser to the authorization endpoint (`client_id=databricks-cli`, redirect URI, `response_type=code`, scopes, PKCE challenge). The user signs in; Databricks redirects back to the loopback with a `code`. The handler validates `state`.
4. POST `token_endpoint` with `grant_type=authorization_code` + `code_verifier` (public client, params in the body) → access + refresh token + `expires_in`.
5. Best-effort `GET /api/2.0/preview/scim/v2/Me` resolves the username (the access token is opaque to dotvault).

Flow (refresh — periodic, driven by `RefreshManager`): every check interval, refresh past half-life via `grant_type=refresh_token`. Databricks may rotate the refresh token (adopted when returned, otherwise the existing one is kept). `401`/`403` is permanent revocation (`ErrRevoked` → wipe + re-enrol); other errors are transient.

Vault schema: `access_token`, `refresh_token`, `host`, `issued_at` (RFC3339), `expires_at` (RFC3339), plus `user` (from SCIM `/Me`, written when available). `user` is deliberately excluded from `Fields()` so a transient SCIM failure doesn't mark an enrolment incomplete. The typical sync rule renders `~/.databrickscfg` (INI) with `host` + `token = {{ .access_token }}` — an OAuth access token is accepted wherever a PAT is, and dotvault keeps it fresh.

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

### Browser-based enrolment in the web UI

Several engines drive an interactive browser login (GitHub device flow, JFrog web login, Databricks OAuth U2M). These present an **actionable URL** to the user and then block on a result — a poll (GitHub/JFrog) or a loopback redirect listener (Databricks). The contract that makes these render correctly in the web UI, and the bug class to avoid:

- The web enrol runner (`internal/web/enrol_runner.go`) deliberately builds `enrol.IO` **without** a `Browser` opener (unlike the CLI paths in `cmd/dotvault/`, which set `Browser: browser.OpenURL`). The daemon must not pop a browser on a possibly-headless host, and the loopback web UI is the user's actual surface — so each engine's `io.Browser == nil` branch fires and it writes the login URL to `io.Out` rather than opening anything server-side.
- The enrolment card (`internal/web/frontend/src/components/enrol-card.jsx`) parses the engine's line-oriented output and renders one of: a **device-code card** when a `! First, copy your one-time code: X` line **and** an `https://` URL are present (GitHub/JFrog); a **redirect card** when only an `https://` URL is present with no code (Databricks); a **passphrase prompt** (ssh); or a raw-output fallback. Both the device-code and redirect cards expose a real **clickable "Open <service> →" anchor** — a genuine user gesture, so it isn't swallowed by pop-up blockers the way a programmatic `window.open` would be. The user clicks it, authenticates, and the card flips to the progress/complete state as the engine's output advances.
- **The failure mode this guards against:** a browser-login engine whose output the card doesn't recognise falls through to the raw-output branch and the user just sees the bare URL dumped into a code block with nothing to click — a "terminal flow in the browser". This was fixed for GitHub/JFrog (the device-code card) and then again for Databricks (the redirect card, which exists precisely because a pure authorization-code+PKCE flow has no user code to key the device-code card on).
- **When adding a new browser-driven engine,** emit the actionable URL to `io.Out` in a form the card already recognises (a line containing an `https://` URL, plus the `! First, copy your one-time code: X` line if and only if there is a user code), and attempt `io.Browser` only inside the non-nil branch. If the new flow has a genuinely new shape, add a matching branch to `enrol-card.jsx` rather than letting it land in the raw-output fallback. Verify the web experience, not just the CLI — the CLI path opens a real browser via `io.Browser` and can mask a missing web card.

## SSH Agent

`internal/agent/` exposes a read-only SSH agent backed by the live Vault token, served over a Unix domain socket (Linux/macOS) or a named pipe (Windows). Disabled by default (`agent.enabled: true`). The two platform listeners serve one shared, platform-neutral `Backend` that implements `golang.org/x/crypto/ssh/agent.ExtendedAgent`.

- **Backend (`backend.go`).** `List` aggregates identities from every configured `Source` and caches the result briefly (default 8s) so repeated `ssh-add -l` doesn't hammer Vault. `Sign`/`SignWithFlags` route the requested key to the owning source and honour `rsa-sha2-256`/`rsa-sha2-512`. `Add`/`Remove`/`RemoveAll`/`Lock`/`Unlock`/`Signers` return `ErrReadOnly` — dotvault is one-way, so the agent is too. Concurrency-safe: each connection is serviced in its own goroutine. If the lifecycle manager reports a re-auth in progress, `Sign` blocks on a bounded wait (`WithReauthTimeout`, default 30s) via the `ReauthGate` interface (`*auth.LifecycleManager` satisfies it) rather than failing spuriously. The gate is stored in an `atomic.Value` (wrapped in a `gateHolder`) so the daemon's post-construction `SetReauthGate` never races a concurrent `Sign`.
- **Sources (`agent.go` interface; `kv.go`, `vaultca.go`, `factory.go`).** A `Source` provides `Identities` and `Sign`. The **KV source** discovers keys under `kv/data/users/<you>/<path_prefix>` (the `public_key`/`private_key` schema the SSH enrolment engine writes), reads+parses+discards the private key per `Sign`; passphrase-protected keys are rejected (the agent can't prompt — enrol agent keys with `passphrase: unsafe`, since Vault is the at-rest protection). The **Vault-CA source** (ephemeral mode) generates an in-memory Ed25519 key at startup, mints a certificate via `<mount>/sign/<role>` (behind the `certSigner` interface so it's unit-testable without a live SSH CA), caches it until shortly before expiry (shared `defaultCertTTL` = 15m), and re-mints transparently on the next `List`/`Sign`. Principals are Go templates over `{{.vault_username}}`. A source that can't be constructed (unknown engine, non-ephemeral vault-ca) becomes an `errSource` that reports its reason through `Status` without aborting the daemon.
- **Transport (`listener.go` + `listener_unix.go` / `listener_windows.go`).** Common `Serve(ctx)`/`Close` logic with platform-specific endpoint creation. `Serve` accepts in a loop, dispatches each connection to `agent.ServeAgent`, and treats post-`ServeAgent` `io.EOF` as a normal disconnect (debug log, not fatal). Context cancellation closes the endpoint and returns cleanly; `Close` is idempotent. **Endpoint permissions are a hard invariant** (the `0600`-equivalent): the Unix socket is bound then `chmod 0600` inside a `0700` dir (no process-global umask swap — that would race other daemon goroutines' file creation; the 0700 dir closes the brief window), with stale-socket removal that refuses to clobber a live instance ("already running"); the Windows pipe is created in byte mode with a protected-DACL SDDL (`D:P(A;;GA;;;OW)(A;;GA;;;SY)`) granting access only to the owning user and LocalSystem. dotvault never sets `SSH_AUTH_SOCK` or PuTTY registry values on the user's behalf. On Windows with `agent.windows.putty` (default true), `listener_windows.go` additionally derives the Pageant-convention pipe name — `\\.\pipe\pageant.<user>.<sha256-hex>`, where the suffix is the hex SHA-256 of the `CryptProtectMemory(CROSS_PROCESS)`-obfuscated string `"Pageant"`, reproducing PuTTY's `capi_obfuscate_string` (per-boot key, so it must be computed at runtime; non-Windows builds carry a stub). The obfuscated bytes are fed to SHA-256 through PuTTY's length-prefixed `put_string` encoding — a four-byte big-endian length ahead of the bytes — not hashed raw; current PuTTY (`windows/utils/cryptoapi.c`) adds that prefix and a clone that omits it derives the stale pre-CMake-refactor name no live PuTTY client dials (`pageantSuffixHash`, `internal/agent/pageant_hash.go`). A pipe carries one name, so this is served as a *second parallel listener* over the same backend rather than an alias; failure to derive it is logged and skipped (the primary pipe always stands).
- **Service + lifecycle (`service.go`).** `agent.Service` bundles the backend and its listener(s). `resolveServeEndpoints` builds the endpoint list — the primary (configured/default) endpoint plus, on Windows with PuTTY enabled, the Pageant pipe — and `Run` supervises one listener goroutine per endpoint, all sharing the single backend. `Endpoint()` reports the primary (the one `dotvault status` queries); `Endpoints()` reports all. The backend is constructed before auth (side-effect-free) so the web server can surface its status; the listeners `Run` only after the first successful Vault auth, supervise themselves (restart-on-terminate after a short backoff), and stop on context cancellation. The backend persists across token refreshes without a listener restart. `Status(ctx)` returns listed identities, per-cert TTL, and per-source resolution errors — surfaced on `/api/v1/status` (web dashboard, parallel to per-rule sync state).
- **Status as a client (`query.go`).** `dotvault status` does not stand up a backend. When `agent.enabled`, it dials the resolved endpoint via `QueryListening` (the platform-split `dialEndpoint`: `net.Dial("unix", …)` / `winio.DialPipeContext`) and runs `agent.NewClient(conn).List()` — the `ssh-add -l` equivalent — so it reports what the live daemon actually serves, including a cert's true remaining validity parsed from the advertised blob. It never creates the endpoint. A dial failure when the agent is enabled is surfaced as unexpected (daemon not running / not yet authenticated), not papered over with a config-derived view.

Cert mode is the documented recommendation: the private key never lands on disk, rotation is automatic, and remote hosts trust only the CA public key (`TrustedUserCAKeys`). See `docs/guide/ssh-agent.md` for the user-facing write-up (client wiring, agent-forwarding caveat, passphrase-mode guidance). When the connectivity/auth shape changes, the source factory in `factory.go` is the wiring seam. The `agent` section round-trips through the Windows registry and `reg-export`/`reg-import` (see "Windows Registry / Group Policy"). The Vault-CA signing engine internals (advanced cache/re-mint timing, non-ephemeral keys) remain a follow-up work item.

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

When HKLM registry keys exist at `SOFTWARE\Policies\goodtune\dotvault`, the daemon loads all config from registry and ignores the YAML file. The `registryLayer` struct reads Vault, Sync, Web (`Enabled`, `Listen`, `LoginText`, `SecretViewText`), Observability (`Enabled`, `Endpoint`, `Protocol`, `Insecure`, `ExportInterval`), and Agent (scalar transport: `Enabled`, `UnixPath`, `WindowsPipe`, and the tri-state `WindowsPutty` REG_DWORD — absent leaves the `*bool` nil so the default-true applies) settings from typed subkeys (REG_SZ, REG_DWORD). Rules are subkeys under `Rules\{RuleName}` with an optional `OAuth` subkey. Enrolments are subkeys under `Enrolments\{Name}` with an optional `Settings` subkey. Wiring up the Observability subkey matters beyond config fidelity: without it a GPO-managed daemon would have `Observability.Enabled=false`, `observability.Init` would short-circuit, and `LogRegistryConfigManaged`'s WARN record would vanish into the no-op global logger.

**Coverage is total: every YAML field has a registry equivalent and round-trips losslessly through `reg-import`/`reg-export` and the live loader — including `observability.headers`.** Header values carry OTLP bearer tokens, but conversion is lossless in every direction with no stripping: the regfile renderer emits each header as a REG_SZ value under `Observability\Headers` (header-name case preserved verbatim, unlike the lowercased enrolment `Settings` names), deleting the subtree before re-creation so a removed header clears on re-import — the same idempotency pattern as Rules / Enrolments / `Agent\Keys`. The live loader (`readRegistryObservabilityHeaders`) and the `.reg` parser read those values back. The recommended way to keep tokens out of a checked-in config remains leaving `headers` empty and using `OTEL_EXPORTER_OTLP_HEADERS` in the per-user `EnvironmentFile`. When adding a new config field, extend all three surfaces in lockstep — `internal/config/registry_windows.go` (live loader), `internal/regfile/regfile.go` (render), and `internal/regfile/parse.go` (parse) — and add a round-trip test; the `internal/regfile` tests are platform-neutral and run everywhere, while the `registry_windows*` loader tests are `//go:build windows`.

The `agent.keys[]` list is **ordered**, unlike the name-keyed rules/enrolments maps. It is stored under `Agent\Keys\{N}` where `{N}` is the zero-based list index (`Agent\Keys\0`, `\1`, …); both the live registry loader (`readRegistryAgentKeys`) and the regfile parser sort those subkey names numerically to rebuild the slice in order, and reject a non-integer subkey name as a hard error rather than silently reordering or dropping a key. `Principals` round-trips as a REG_MULTI_SZ (like OAuth `Scopes`); an explicit empty list is preserved as a non-nil empty slice.

This means a Windows GPO deployment can configure rules, enrolments, the SSH agent, and the observability exporter end-to-end, and `reg-export` / `reg-import` (plus the web `GET /api/v1/config/download`) round-trip every section through both the YAML and `.reg` forms. dotvault does **not** ship an ADMX administrative template and there is no plan to — it was never adequately tested and has been removed entirely. Admins author the registry values directly (e.g. via `reg-import` from a YAML config); the registry surface is the supported Group Policy integration.

## File Permissions & Security

- Managed files (all sync rule targets): written at 0600
- Token file (`~/.dotvault-token`): written at 0600, warns if permissions differ
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
| `github.com/Microsoft/go-winio` | Windows named-pipe listener (SSH agent transport) |
| `golang.org/x/crypto/ssh/agent` | SSH agent protocol server (read-only backend) |
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
