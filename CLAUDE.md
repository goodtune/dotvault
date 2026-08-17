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

All builds use `CGO_ENABLED=0` for static binaries. Version is injected via ldflags (`-X main.version=...`). Release tags are `v`-prefixed (`v0.19.0`) for Go-module consumption, but `main.version` is the v-stripped semantic version (`0.19.0`): GoReleaser's `{{.Version}}` strips the prefix and the Makefile strips it via `sed`, so local and release builds agree. Consumers (the `version` command, `/api/v1/status`, the OTel `service.version` attribute and the `dotvault.build_info` gauge's `version` attribute, the tray tooltip, and the web UI header which prepends its own `v`) treat the value as v-stripped and must not add or assume a leading `v`.

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
python/                  Python bindings: cgo c-shared bridge over client/ + ctypes wrapper — see "Python bindings"
internal/
  config/                Config loading: YAML file + Windows Registry (GPO)
  regfile/               .reg ⇄ YAML conversion (reg-import/reg-export, web config download)
  paths/                 OS-specific path resolution
  vault/                 Vault client wrapper, KVv2 operations, Events API (WebSocket)
  remoteconfig/          Remote config overlay: ETag-conditional fetcher, last-known-good cache, fail-open ladder
  auth/                  Auth orchestration (OIDC, LDAP with MFA, token, mtls/mtls+tpm/mtls+os cert auth)
  securestore/           Platform-agnostic key store for cert auth: file + build-tagged TPM (Linux/Windows) + build-tagged OS-native cert store (Windows-only, via google/certtostore) backends; unsupported platforms fall back to ErrUnsupported pending Secure Enclave / PKCS#11 backends
  loginsuppress/         login-check suppression marker (path/window/freshness/refresh)
  passwd/                /etc/passwd parsing for login-check --no-passwd (local vs directory account)
  observability/         OTel metrics + logs SDK wiring, package-level instrument helpers, slog→OTel log bridge
  tokenwatch/            Watches ~/.dotvault-token for replacement (inotify on Linux); no-op elsewhere
  httpproxy/             Per-request proxy resolver (ieproxy/PAC on Windows, env vars elsewhere) + http.Client builder
  notify/                Cross-platform desktop notifications via beeep (Windows toast / macOS Notification Center / Linux D-Bus), with a level vocabulary and input sanitization
  clipboard/             Cross-platform clipboard writer (pbcopy / wl-copy / xclip / xsel via exec; Win32 CF_UNICODETEXT syscalls) + content-free validation; shared by the remote-clipboard peer action and the enrolment wizard
  urlallow/              Shared http/https URL allowlist for OS-opener/notification sinks (used by web browse + notify action link)
  uds/                   Per-user Unix-socket listener with the 0600-in-0700 owner-only invariant; shared by the SSH agent and the local API socket
  sync/                  Hybrid event+poll sync engine, state store
  handlers/              File format handlers (yaml, json, ini, toml, text, netrc, ssh_config)
  tmpl/                  Go template rendering (named tmpl to avoid shadowing text/template)
  enrol/                 Credential acquisition via OAuth device flow
  web/                   Web UI server (Preact SPA), auth endpoints, REST API
  perms/                 File permission checks (Unix mode bits, Windows DACL)
  tray/                  Windows system-tray icon (no-op on other platforms)
  agent/                 SSH agent: read-only ExtendedAgent backend + Unix-socket (Linux/macOS) and named-pipe (Windows) listeners
  sshfwd/                Daemon-managed SSH remote forwards: declarative reconciler, per-host connection lifecycle, host-key trust, ssh.yaml load/save — see "Managed SSH forwards"
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
- **`vault`** — address (required), auth_method (`oidc`/`ldap`/`token`/`mtls`/`mtls+tpm`/`mtls+os`; any base method also accepts a `+tpm` suffix — `oidc+tpm`, `ldap+tpm`, etc. — which TPM-seals the cached token file at rest, see Authentication; `mtls+os` is a cert-key-storage modifier that additionally keeps **no token at rest at all** — see Authentication), auth_mount, auth_role, oidc_callback_port (fixed local TCP port the OIDC CLI flow binds for the OAuth redirect_uri; 0/unset defaults to 8250 — the `vault` CLI's own default — with fallback to a random port if unavailable; see Authentication → OIDC below), policies (least-privilege token policy list; per-deployment, no default — when non-empty dotvault exchanges the login token for a child token restricted to exactly these policies, see Least-privilege token policies below), no_default_policy (default false today — strips the implicit `default` policy from the working token; staged to default true in a future release and become mandatory at 1.0), kv_mount (default `"kv"`), user_prefix (default `"users/"`, trailing slash enforced), ca_cert, tls_skip_verify, disable_token_renewal (default false — set true to prevent the daemon from calling RenewSelf; TTL expiry still triggers re-auth), token_socket (optional path to a peer dotvault's web-API Unix socket; empty disables — see dotvault-to-dotvault token sharing below). The nested **`vault.mtls`** block configures the cert auth methods (consulted only when auth_method is a cert method — `config.IsMTLSMethod`: `mtls`/`mtls+tpm`/`mtls+os`): `bootstrap_method` (`ldap`/`oidc`, default `oidc`), `bootstrap_mount`, `cert_mount` (default `cert`), `cert_role` (required), `pki_mount` (default `pki`), `pki_role` (required — it rotates the certificate before expiry, BYO included, since BYO only seeds the first cert while steady-state rotation still runs `pki/sign/<role>`), `key_type` (`ec`/`rsa`, default `ec`; `rsa` rejected for `mtls+tpm` only), `key_bits` (RSA modulus: 2048/3072/4096/8192, 0 = 2048 — a Vault PKI role's `key_bits` is a *minimum*, so a role pinning RSA at 4096 rejects dotvault's default 2048-bit CSR; rejected at config load with `key_type: ec` or under `mtls+tpm`, rather than silently ignored), `common_name` (template over `{{.user}}`, default `{{.user}}`), `ttl` (empty defers to the PKI role, except `mtls+os` defaults it to `720h`/30d — the PKI role's max_ttl still caps it), `reissue_before` (default `168h`), `seal_to_pcrs` (mtls+tpm boot-state binding), `storage_dir` (default `{cache_dir}/mtls`), and `byo.cert`/`byo.key` (both-or-neither bring-your-own seeding; rejected for `mtls+os`, which cannot import an external key). Validated by `validateMTLS`; round-trips through registry/`.reg`.
- **`sync`** — interval as Go duration string (default `15m`)
- **`web`** — enabled (default false), listen (loopback only, hard invariant), login_text (markdown), secret_view_text (markdown)
- **`observability`** — enabled (default false), endpoint, protocol (`grpc` or `http/protobuf`), insecure, headers (map), export_interval, plus nested per-signal **`metrics`** and **`logs`** override blocks. The top-level fields are shared defaults driving both signals against one collector; a signal block overrides them field-by-field (`enabled` tri-state — unset inherits, explicit false switches the signal off, and the top-level flag stays the master switch a per-signal true cannot resurrect; `endpoint`/`protocol` non-empty overrides; `insecure` tri-state; `headers` REPLACE the shared map wholesale — no merging, since merging credential maps invites sending one backend's bearer token to the other, and an explicitly empty `headers: {}` means "this signal sends no headers"). The layering deliberately mirrors the OTel env-var convention (generic `OTEL_EXPORTER_OTLP_*` + signal-specific `_METRICS_*`/`_LOGS_*`) and is defined in exactly one place, `config.ObservabilityConfig.ResolveSignal`; `observability.Init` consumes only resolved per-signal values and installs each signal's global provider only when that signal is enabled, so a disabled logs signal leaves the global LoggerProvider on the no-op — the `Log*` helpers emit nothing and the slog→OTel mirror stays inert (its `Enabled` check early-exits) while metrics keep flowing. `observability.enabled` true with both signals explicitly off is rejected at config load. **Staged deprecation of the shared exporter fields** (tracking issue #140): the top-level endpoint/protocol/insecure/headers layer is being retired in favour of per-signal-only configuration — this release WARNs at startup and increments `dotvault.config.deprecated` (attribute `field`, one per field per process start; the counter is generic and future deprecations should reuse it) when a shared exporter field is in use with observability enabled (`config.ObservabilityConfig.DeprecatedSharedFields` → `warnDeprecatedObservabilityConfig`, `cmd/dotvault/main.go`); a later release makes the warning louder (and must first give `export_interval` a per-signal home or exempt it); 1.0 removes the shared fields. `enabled` (master switch) and `export_interval` are not deprecated; the `OTEL_*` env-var fallthrough is the supported way to share settings across signals and is where the deprecation steers shared-credential use. The migration's fleet-dashboard companion is `dotvault.build_info` — a Prometheus-convention constant-1 gauge (attributes `version`/`go_version`/`os`/`arch`, mirroring `dotvault version --json`; registered as an observable in `rebindInstruments`, version injected via `setBuildVersion` from Init) to join `dotvault.config.deprecated` against by `version`; the same identity rides every series as resource attributes (`service.version`, `os.type`, `host.arch`, `process.runtime.name`/`.version`). Round-trips through the registry (`Observability\Metrics`/`Observability\Logs` subkeys; tri-states as present-or-absent DWORDs, per-signal `Headers` subkeys where a present-but-empty key means "no headers" as distinct from absent meaning inherit) and `.reg`. Falls through to standard `OTEL_*` env vars when fields are empty (signal-specific overrides `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` / `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL` take precedence over the generic `OTEL_EXPORTER_OTLP_PROTOCOL`). Endpoints share one contract across both signals and protocols: a full URL's scheme carries the TLS intent (`https`→TLS, `http`→plaintext — the gRPC path routes http(s) URLs through `WithEndpointURL` so this holds there too) and an explicit URL path is used verbatim (no assumed mount path); a path-less URL gets the OTLP-standard `/v1/metrics`/`/v1/logs` appended (http/protobuf only); bare `host:port` (canonical gRPC) leaves TLS to the `insecure` flag, `grpc://` is stripped as meaningless, `dns:///` passes through as a gRPC resolver target. `metrics.temporality` (`cumulative`/`delta`/`lowmemory`, per-signal-only — rejected on `logs`, no shared-layer equivalent by design) selects the exporter's aggregation temporality with exactly the `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` vocabulary and kind-mapping (empty falls through to that env var; `config.validateOTLPTemporality` ⇄ `observability.temporalitySelector` in lockstep). Disabled by default — metric instruments fall back to the OTel no-op meter and `Log*` helpers fall back to the no-op global logger, so call sites never need to branch. **Treat `headers` as a credential** — values typically carry OTLP bearer tokens (Datadog / Grafana Cloud / etc.). Config conversion is lossless in every direction, so `headers` round-trip verbatim through YAML, `.reg`, and the registry (and through the web config-download endpoint); nothing strips them. Operators who want tokens kept out of a checked-in or downloaded config should leave `headers` empty and set them via `OTEL_EXPORTER_OTLP_HEADERS` in the per-user `EnvironmentFile` (`~/.config/dotvault/env`), which the SDK falls through to. Store the config file at 0600. The daemon does scrub `headers` from its own long-lived in-memory `Config` after the OTel SDK consumes them (heap hygiene, `cmd/dotvault/main.go`); when the web UI is enabled it retains a separate copy so the download stays lossless.

  Logs vs. slog: `log/slog` to stderr remains the primary sink (text on a TTY, JSON otherwise), but every record handled through it is also mirrored to the OTel LoggerProvider — `setupLogging` (`cmd/dotvault/main.go`) wraps the stderr handler in `observability.NewSlogHandler`, an `slog.Handler` that forwards to the wrapped handler first and then, in `emit()`, resolves the logger from `global.GetLoggerProvider().Logger(...)` (fresh on every call, exactly like `LogRegistryConfigManaged`) and checks `logger.Enabled(ctx, ...)` *before* building anything. The no-op provider's `Enabled` always returns `false`, so the disabled/pre-`observability.Init` path costs one `Logger()` call plus one `Enabled()` call and never walks attrs or allocates a `Record` — that early exit, not just "the emit is cheap," is what makes wrapping unconditional safe on hot paths (sync loop, web handlers, per-rule sync) with no `cfg.Observability.Enabled` branch needed at the wrap site, matching the no-op-backed convention the metric instruments and `LogRegistryConfigManaged` already follow. When enabled, the conversion builds an equivalent OTel `log.Record` (message → body, level → `Severity`/`SeverityText`, attrs/groups → dotted-prefixed `KeyValue`s; a `slog.KindAny` value with no `error`/`Stringer` implementation is rendered via `json.Marshal`, not `fmt.Sprint`, so it doesn't leak unexported or `json:"-"`-tagged struct fields the JSON stderr sink would have omitted). The intent is that a configured OTel collector can fan every operational log line — not just deployment-fact records — out to a `file` exporter, syslog/journald forwarding, or (via a collector build that includes a suitable exporter — not a stock core-distribution component) the Windows Event Log, without dotvault needing platform-specific sink code of its own. Because every record now leaves the process once a collector endpoint is configured, treat `observability.endpoint`/`insecure`/`headers` as part of the logging trust boundary, not just the metrics one: a call site that logs something sensitive is no longer contained to local stderr/journald. `LogRegistryConfigManaged` is unaffected by this and continues to emit directly via the OTel logger only (bypassing slog on purpose, since it must not print on every CLI invocation against a GPO-managed box); both paths share the `loggerName` instrumentation-scope constant in `internal/observability`.
- **`remote_config`** — optional remote configuration overlay (design: `docs/superpowers/specs/2026-06-10-remote-config-design.md`). `url` (https required except loopback hosts; empty disables), `refresh_interval` (duration string, default = sync interval, floor 1m), `ca_cert` (CA pin for the fetch; deliberately no skip-verify option), `headers` (extra dimension headers, e.g. `X-Dotvault-Env`; cannot override the built-in `X-Dotvault-OS/User/Arch/Hostname/Version` identity headers). When `url` is set the local config becomes the *base*: the client fetches a partial document — dynamic sections only (`rules`, `enrolments`, `sync`); static sections in a remote document are a hard error, unknown sections warn-and-ignore — and merges it on top before validation. Rules merge by name (same-named rule replaced wholesale, new names appended), enrolments by map key, `sync.interval` scalar override; additive-only, no tombstones (removal converges because base ⊕ fresh-remote is recomputed every refresh). Fetching fails open: fresh → cached last-known-good (`{cache_dir}/remote-config.json`, identity-bound, 0600) → base alone with a warning. The ≥1-rule validation requirement applies only when no remote URL is configured. `run`/`sync`/`status`/`enrol` use the merged loader; `login`/`login-check` (shell-startup latency budget) and `reg-import`/`reg-export` (pure converters) stay local-only. The section is itself local-only and round-trips through the registry (`RemoteConfig` subkey + `Headers` subkey), `.reg`, and YAML like every other section.
- **`rules`** — array of sync rules (name, vault_key, target.path, target.format, target.template, target.merge). `vault_key` is optional: present, it is read and its data fills the template context; absent, the rule is *keyless* — no Vault read, empty data context, must carry a `target.template` (the common case being an ssh_config built from `{{ username }}` and literals)
- **`enrolments`** — map of Vault KV path segment to engine config for credential acquisition. A key may use a single-level `group/name` form (e.g. `databricks/prod`) to organise related enrolments; the group becomes a nested Vault path segment (`users/<you>/databricks/prod`) and an expandable folder in the web UI. Exactly one level is allowed — more than one `/`, a leading/trailing `/`, an empty segment, or a backslash is rejected at config load (`validateEnrolmentKey`)
- **`api`** — local API socket (default disabled). `enabled`, `unix.path` (default `$XDG_RUNTIME_DIR/dotvault/api.sock`, cache-dir fallback when the runtime dir is unset; must be absolute or `~`-relative). Serves the *same* web API mux over a per-user Unix socket in addition to — or instead of — the loopback TCP listener `web.enabled` controls. See "Local API socket" under Authentication for why it exists and how it interacts with the borrow order. Unix only: `api.enabled` on Windows warns and serves nothing (`resolveAPISocket`, `cmd/dotvault/apisocket.go`). Static section — the listener is bound once at startup.
- **`agent`** — SSH agent surface (default disabled). `enabled`, `unix.path` (default per-user runtime socket), `windows.pipe` (default `\\.\pipe\dotvault-agent`), `windows.putty` (default true; Windows-only `*bool` tri-state — when enabled, the daemon serves a *second* parallel listener on the Pageant-convention pipe `\\.\pipe\pageant.<user>.<hash>` so PuTTY-family clients auto-discover the agent; only takes effect when `agent.enabled`), and an ordered `keys[]` list of sources: `source: kv` (`path_prefix`, resolved under `kv/data/users/<you>/`) and `source: vault-ca` (`mount`, `role`, templated `principals`, `ttl`, `ephemeral_key`)
- **`ssh`** — admin-owned trust material for daemon-managed SSH forwards (see "Managed SSH forwards" below), analogous to `agent` but system-config-only: `certificate_authorities` (a list of `@cert-authority` known_hosts lines; a host whose certificate one of these signs needs no per-host pin) and `insecure_ignore_host_key` (default false — disables host-key verification entirely, logging a WARN naming the host on every connection made under it). Deliberately does *not* hold the remotes themselves — those live in the user-level `ssh.yaml` (see `paths.SSHConfigPath`), which has no registry surface because it is user-writable and must never act as policy. Dynamic: a config-refresh-loop change to this section applies to a remote's *next* connection attempt without a restart, but an already-connected forward keeps using the `HostKeyPolicy` it dialled with. Round-trips through YAML, the registry (`SSH\CertificateAuthorities` REG_MULTI_SZ + `SSH\InsecureIgnoreHostKey` REG_DWORD), and `.reg`.

### Config Validation

- `vault.address` is required
- At least one rule is required
- Rule names must be unique
- A rule's `vault_key` is **optional**. A keyless rule manages a file that has no Vault-backed content — it renders from `{{ username }}` and literals alone, with an empty data context — and never contacts Vault. Because there is no secret data to fall back on, a keyless rule must supply `target.template`. The `username` function still resolves (it is a template function, not a context field).
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
dotvault browse      Open a URL in a browser, preferring the peer over vault.token_socket
dotvault notify      Raise a desktop notification, preferring the peer over vault.token_socket
dotvault clipboard   Put text on the clipboard, preferring the peer over vault.token_socket
dotvault ssh         Manage daemon-maintained SSH remote forwards (add/list/remove)
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
fresh *interactive* authentication — the user is pointed at `dotvault login`
instead. The exception is `mtls+os`, which keeps no token at rest: there an
absent token is the normal state rather than "not authenticated", so enrol
derives one from the certificate via `CertLoginFromStore`. That needs no human,
so it does not breach the rule the refusal exists to enforce, and refusing would
otherwise point the user at a `dotvault login` that is neither necessary nor
meaningful for that method.

The picker also refuses to run without a TTY on both stdin and stderr,
because a headless caller has no way to drive the selection; pass an
explicit name to enrol non-interactively. The underlying engine runs
through `enrol.Manager.RunOne`, which is deliberately a re-run-on-demand
entry point: unlike `CheckAll`, it executes the engine even if the
target is already populated, so the command doubles as a way to refresh
expiring credentials without first wiping the Vault secret.

`dotvault browse <url>` is a `$BROWSER`-shaped wrapper over the web
API's remote-browse endpoint. When `vault.token_socket` names a
reachable peer dotvault (the same SSH-forwarded socket the token
borrow uses, so an already-wired headless host needs no new config),
the URL is form-posted to the peer's `POST /api/v1/remote/browse` and
the browser opens on the workstation; otherwise the URL opens in the
local default browser. Only http/https URLs with a host are accepted —
validated locally (`web.ValidateBrowseURL`, shared with the endpoint)
before any socket or opener is touched. Config load is local-only
(interactive latency budget, and the vault section is local-only
anyway); a config-load failure warns and degrades to the local
browser rather than failing, so the command works on hosts with no
dotvault config. Silent on success, per `$BROWSER` convention. The
socket client lives in `cmd/dotvault/browse.go`
(`postBrowseToSocket`); the transport (expand ~, stat-before-dial,
unix `http.Transport`) is the shared `auth.PeerSocketClient` that
`auth.FetchTokenFromSocket` also uses — only the error policy
differs (browse returns failures for its fallback decision; the
borrow swallows them). The local fallback opener is the injectable
`openLocalBrowser` var (tests fake it, mirroring `internal/auth`'s
`openBrowser`). Note the `$BROWSER` caveat: Python-based tools exec
a multi-word value as one program name — docs point those at a
wrapper script.

`dotvault notify <level> <title> [description]` is the notification
sibling of `browse`, same peer-preferring shape over the same
`vault.token_socket`. It form-posts to the peer's `POST
/api/v1/remote/notify` so a native desktop notification (Windows
toast, macOS Notification Center, Linux D-Bus) appears on the
workstation where a human is looking; otherwise it raises the
notification locally. An optional `--action-url` attaches an
http/https link the notification takes the user to when clicked: it is
genuinely clickable on Windows (the toast is protocol-activated via
go-toast directly, since beeep exposes no activation API — fire-and-forget,
the shell handles the click), and degrades on macOS/Linux (a one-shot
delivery cannot register a click handler there) by appending the URL to
the body so it stays visible. The URL is validated with the same
http/https allowlist as browse — the rule lives in one place
(`internal/urlallow.Validate`, shared by `web.ValidateBrowseURL` and
`notify.validateActionURL`) so the invariant can't drift. Delivery lives in `internal/notify` (a thin
level vocabulary — `info`/`warning`/`error`/`attention` — over
`github.com/gen2brain/beeep`, pure-Go with build-tagged platform
backends, preserving CGO_ENABLED=0). `notify.NewMessage` validates
the level and an optional http/https `action_url`, and sanitizes
title/body — strips control characters and neutralizes the
metacharacters that would break out of beeep's Windows toast backends
(the XML CDATA terminator `]]>`, and the PowerShell here-string
metacharacters `$`/backtick that the COM-unavailable fallback would
otherwise evaluate as a subexpression, i.e. RCE). It is shared by the
CLI and the endpoint so both reject or neutralize input identically.
Level drives urgency (error/attention → `beeep.Alert`,
audible; info/warning → `beeep.Notify`) and, on Linux/BSD where the
D-Bus `app_icon` accepts freedesktop stock names, the icon
(`dialog-error` etc.); on macOS/Windows a stock name isn't a real
file path so `iconArg` returns `""` there and the level shows via
urgency. Delivery is split by build tag: `send_windows.go` raises a
protocol-activated clickable toast via `git.sr.ht/~jackmordaunt/go-toast`
directly when an `action_url` is set (beeep has no activation API), with
`safeToastArgs` XML-escaping `& " < >` and percent-encoding `$`/backtick
for the launch attribute's XML + PowerShell-here-string sinks;
`send_other.go` appends the URL to the body via `actionBody`. Both route
their non-clickable path through the shared `beeepDeliver`. The go-toast
clickable path is not exercised in the (Linux) CI, like the TPM backend —
but its pure encoder `safeToastArgs` is unit-tested everywhere. The local fallback notifier is the injectable
`sendLocalNotification` var.

`dotvault clipboard [text]` is the third peer action, same
peer-preferring shape over the same `vault.token_socket`. It
form-posts to the peer's `POST /api/v1/remote/clipboard` so the value
lands on the clipboard of the workstation the user is actually pasting
on; otherwise it writes this host's clipboard. Together with `browse`
and `notify` it closes the headless-auth loop: open the login page in
the workstation's browser, then stage the one-time token or device
code right where the user's Ctrl+V is. With no positional argument
(or `-`) the text is read from stdin — the documented-preferred path
for secrets, since argv is visible in process listings — and exactly
one trailing newline is stripped (`clipboardText`,
`cmd/dotvault/clipboard.go`); a positional argument is taken verbatim.
Delivery lives in `internal/clipboard`: exec-based writers on the Unix
platforms (`pbcopy`; `wl-copy` → `xclip` → `xsel` in candidate order,
Wayland-first with X11 fallthrough) and direct Win32 syscalls on
Windows (`CF_UNICODETEXT` via `golang.org/x/sys/windows` — not
clip.exe, whose console-code-page stdin mangles non-ASCII text;
preserving CGO_ENABLED=0, hardware-untested in the Linux CI like the
go-toast path, with the shared exec/candidate logic unit-tested
everywhere). The Win32 writer runs the Open→Set→Close sequence under
`runtime.LockOSThread` (the clipboard is thread-affine) and registers
the `CanIncludeInClipboardHistory`/`CanUploadToCloudClipboard`/
`ExcludeClipboardContentFromMonitorProcessing` exclusion formats
alongside the text (best-effort), so the credential stays out of
Win+V history and cross-device Cloud Clipboard sync. `clipboard.ValidateText` (shared by CLI and endpoint) is
deliberately *not* a sanitizer: clipboard content is data, never
interpolated into an evaluated context, and the typical payload is a
credential that must arrive byte-for-byte intact — it only rejects
what no clipboard can carry faithfully (interior NUL, invalid UTF-8)
or what signals a caller bug (empty, >64 KiB), and its error messages
are content-free by contract. The exec writers take text on stdin
(never argv) and deliberately capture no output pipes (wl-copy/xclip
fork a selection-owning child that inherits the descriptors — a pipe
would block until the clipboard is next replaced). The enrolment
wizard's best-effort device-code copy reuses the same writers. The
local fallback writer is the injectable `setLocalClipboard` var. All
three peer-action CLIs (`browse`/`notify`/`clipboard`) share the peer
form-POST transport (`auth.PostFormToPeer`,
`internal/auth/peerpost.go`) and, on the server, the single-flight +
bounded-wait + panic-recovery launcher (`internal/web/launcher.go`,
`guardedLaunch`).

`dotvault ssh add|list|remove` manages the SSH remote forwards the daemon maintains for itself (see "Managed SSH forwards" below). `add` and `remove` are thin clients of the daemon's own web API (`cmd/dotvault/ssh.go`, `ssh_add.go`, `ssh_remove.go`) — the CLI never writes `ssh.yaml` directly, because the verifying login `add` performs needs the daemon's agent identity, and routing every mutation through the one `sshfwd.Registry` the web UI also uses removes the CLI-versus-daemon write race outright. The daemon is reached over the local API socket (`api.enabled`) when configured, else the loopback web listener (`web.enabled`) — on Windows only the latter exists today, since the API socket is Unix-only, so `dotvault ssh` there requires `web.enabled`. `ssh add <host>` performs a live SSH dial, credential check, and host-key verification before persisting anything (`--force` skips the dial for a host known to be offline right now); an unpinned host's key surfaces as a printed fingerprint requiring confirmation (`--accept-host-key` on a non-interactive shell, after verifying the fingerprint out of band — there is no silent-accept path). `ssh list` degrades to reading `ssh.yaml` directly (reporting `unavailable` status) when the daemon can't be reached, since reading is safe without a daemon but writing is not; `ssh remove` is idempotent on an unconfigured host (prints and exits 0).

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

Logging uses `log/slog` — text format when stderr is a TTY, JSON otherwise. Always writes to stderr; no file-based logging directly from dotvault (a configured OTel collector can fan the mirrored log stream out to a file, syslog, or the Windows Event Log — see Config Sections → `observability`).

## Daemon Lifecycle

1. Load config (file or registry)
2. Create Vault client, attempt token reuse (DOTVAULT_TOKEN env or `~/.dotvault-token`)
3. Start web UI if enabled (before auth, so it can serve browser-based login)
4. Authenticate if needed: web mode routes all auth through the SPA; CLI mode uses method-specific flows (OIDC browser, LDAP terminal prompt, token file). A non-interactive host with neither a web UI nor a TTY does not give up — it registers a synchronous token-file watch and idles until an external facility (e.g. a login profile running `dotvault login`) writes a usable token, then resumes startup. The watch is registered before the no-token decision so a token written during startup cannot be missed; this replaced the previous behaviour where a headless daemon idled until shutdown and required a restart to pick up a token (`waitForHeadlessToken`, `cmd/dotvault/main.go`).
5. Start token lifecycle manager (renews at 75% TTL, exponential backoff 1s-5m on failure)
6. Start RefreshManager (rotates expiring credentials for `Refresher` engines, e.g. JFrog) and WatchManager (re-mirrors upstream sources for `Watcher` engines, e.g. Copy)
7. Run enrolment check (wizard if any credentials missing in Vault)
8. Start sync engine: initial sync, then hybrid event+poll loop
9. Background config-refresh loop (all daemon modes — web, headless, CLI) re-runs the startup loader every `remote_config.refresh_interval` (default: sync interval): the remote overlay re-fetches with an ETag-conditional GET, and dynamic-section changes fan out — enrolments to the enrolment manager (CLI mode), RefreshManager, WatchManager, and the web enrolment runner (deferred while an enrolment is mid-run); rules and sync interval to `sync.Engine.UpdateConfig` (state entries for removed rules pruned, ticker reset, immediate sync trigger) and the web server's locked snapshots. The loop also runs a pass immediately on a manual reload request (SIGHUP, or the tray's "Reload config" entry on Windows) instead of waiting for the next tick, and warns — naming the sections — when a reload finds static sections changed, since those need a restart.
10. On Windows, install a system-tray icon (`internal/tray/`) with "Reload config", Exit, and (when web is enabled) "View web UI" entries; the tray owns the main goroutine because the Win32 message pump must run on a locked OS thread, while the sync loop moves to a goroutine. On non-Windows the same call simply blocks on ctx.

The daemon watches `~/.dotvault-token` for replacement and re-reads it immediately via `LifecycleManager.Reload` — handy for picking up a token freshly written by `dotvault login` without waiting for the 5-minute lifecycle tick. On Linux this uses inotify on the token file's parent directory (`internal/tokenwatch/`, watching the directory rather than the inode because atomic writers replace it via temp-file+rename); creation and write-completion events trigger a reload, deletes are ignored so the daemon keeps using its current in-memory token until a new one is written. On non-Linux platforms the watcher is a no-op. This replaces the previously shipped `dotvault-token-watch.path`/`.service` systemd units, which forwarded token-file changes to the daemon via SIGHUP out-of-process. SIGHUP remains the daemon's manual reload trigger on every platform where it is delivered (not Windows): it re-reads the token file (`LifecycleManager.Reload`) **and** nudges the config-refresh loop to re-run the loader immediately. The packaged systemd unit wires it as `ExecReload=`, so `systemctl --user reload dotvault.service` is the canonical gesture; that (like `systemctl --user kill --signal=SIGHUP dotvault.service`) targets the unit's MainPID rather than scanning the process table for anything named `dotvault`, so a developer running `go run ./cmd/dotvault` or `dotvault sync` from a shell while the daemon also happens to be running won't have those side processes SIGHUP'd (their default disposition for SIGHUP is *terminate*).

Config reload via SIGHUP is **dynamic sections only**. The dynamic sections — rules, enrolments, and the sync interval — apply in place, exactly as they do on the config-refresh tick they already converge on in every daemon mode (whether the change came from the remote overlay or an edited local config); the signal just skips the wait. `remote_config` is dynamic too: the withRemote loader rebuilds the overlay fetcher when the section changes and the loop re-derives its tick cadence (explicit `remote_config.refresh_interval`, else the sync interval) after every pass — though a *remote* document still cannot carry the section, which stays local-only. The static sections (vault, web, api, agent, observability, and the top-level `bypass_system_config` flag) configure subsystems constructed once at startup and still require a full restart — a reload that finds them changed logs a WARN naming the changed sections rather than half-applying them (`staticSections`/`changedStaticSections`, `cmd/dotvault/main.go`; the comparison reduces `observability.headers` to a SHA-256 digest so the snapshot doesn't re-retain the scrubbed bearer tokens). The deliberate non-choice: exiting with a magic code for systemd to restart would only work under a supervisor — a manually-run daemon, macOS launchd without `KeepAlive`, or dotvaultw would simply die — and would discard in-memory-only state (borrowed peer tokens, web sessions). On Windows, where SIGHUP is never delivered, the tray's "Reload config" entry drives the same token re-read + immediate refresh pass for both `dotvault.exe run` and `dotvaultw.exe`. Known cadence limitations: the WatchManager poll interval and the RefreshManager check interval are fixed at construction.

## Authentication

### Methods

- **OIDC** — Requests auth URL from Vault (passing a `redirect_uri` Vault forwards straight through to the identity provider — the callback lands directly on dotvault, not proxied via Vault), opens browser, listens on `127.0.0.1:<vault.oidc_callback_port>` (default `8250`, matching the `vault` CLI's own default, so a role/IdP already allow-listing the `vault` CLI's redirect URI typically works unchanged) for the callback, falling back to a random port only when that one is already in use (`syscall.EADDRINUSE`) — any other bind failure, e.g. a privileged port or a firewall block, is a hard login error rather than a silently-degraded fallback, since it won't clear itself on the next login — then exchanges the code for a Vault token. Both Vault's `allowed_redirect_uris` and the IdP must allow-list the exact URI in use — Vault's matcher ignores only the port on a loopback host (scheme/host/path must match, and `127.0.0.1` ≠ `localhost`), but not every IdP is as lenient. A 200 response from Vault's `auth_url` endpoint with no `auth_url` field means the redirect_uri was rejected; the error names the exact URI sent plus the mount/role rather than the historical opaque `"no auth_url in OIDC response"`. See `docs/authentication/oidc.md` for the full redirect-URI reference across the CLI and daemon web UI flows.
- **LDAP** — Prompts for password; supports MFA (Duo push and TOTP) via the LoginTracker async state machine
- **Token** — Reads from DOTVAULT_TOKEN env var or `~/.dotvault-token`. The upstream `VAULT_TOKEN` variable is deliberately ignored everywhere — including the Vault SDK's automatic pickup, which `internal/vault.NewClient` neutralises by setting the token unconditionally — so a concurrent `vault` CLI session's environment never leaks into the daemon or external `client/` consumers
- **mTLS** / **mTLS+TPM** / **mTLS+OS** — A TLS client certificate authenticates against Vault's `cert` auth method instead of a human credential; LDAP/OIDC is demoted to a one-time bootstrap that mints the first certificate via the PKI engine (`pki/sign/<role>`). Orchestration is `internal/auth/mtls.go` (`Manager.authenticateMTLS`: load-or-seed → cert login), the on-disk envelope `internal/auth/mtls_envelope.go` (`{cache_dir}/mtls/credential.json`, 0600 — for `mtls+tpm` the private key is never in plaintext, only the sealed blob; for `mtls+os` the key lives in the OS cert store and the envelope's handle just records the CNG container). The private key sits behind the platform-agnostic `internal/securestore` seam: a `file` backend (software key, plain `mtls`), a build-tagged TPM backend (Linux `/dev/tpmrm0`, Windows TBS — EC P-256 only, sealing the scalar via go-tpm-tools), and a build-tagged **`os` backend** (`securestore.ModeForMethod("mtls+os")` → `"os"`; `osstore_windows.go` via `google/certtostore`, `osstore_other.go` returns `ErrUnsupported`). The `os` backend opens `OpenWinCertStoreCurrentUser(ProviderMSSoftware, …)` — the per-user CNG software key store (no admin) — generates the key there, and (through the optional `securestore.CertStorer` capability, mirroring `DataSealer`) installs the issued cert into `CurrentUser\My` so browsers can present it for mTLS. Windows-only today; `mtls+os` rejects BYO (CNG has no key-import path) and defaults `ttl` to 30d. The `WinCertStore` is held open for the backend's lifetime because the returned `crypto.Signer` borrows its CNG provider handle during the cert-login handshake. The SRK is derived as a *transient* primary (`client.NewKey` + `SRKTemplateECC`, `loadSRK` in `tpm.go`) rather than `client.StorageRootKey*`: the latter persists via `TPM2_EvictControl`, an owner-hierarchy op Windows TBS denies to standard users (`0x80280400`) even on a healthy TPM; primary keys are deterministic, so re-deriving each operation costs nothing and unseals prior blobs. `seal_to_pcrs` binds to PCRs 0/2/4/7 on Linux but **excludes PCR7 on Windows** (`pcrSelectionFor`) because BitLocker claims it there. macOS Secure Enclave is a stub returning `ErrUnsupported` until the binary is code-signed, so `mtls+tpm` errors there rather than silently degrading to a plaintext key. `tls.Certificate.PrivateKey` only needs `crypto.Signer`, so one assembly path serves every backend. Cert presentation is wired through `vault.Config.ClientCert` (a `GetClientCertificate` callback that invokes the signer lazily). Re-issuance is proactive: at auth time a cert inside `reissue_before` is rotated using the still-valid cert. The `vault.mtls` block round-trips through YAML, the registry (`Vault\MTLS` + `Vault\MTLS\BYO`), and `.reg`. See `docs/authentication/mtls.md` (certificate auth) and `docs/authentication/tpm.md` (the TPM hardware backend, shared with token sealing). First-run bootstrap is the only step needing a human, and **when the web UI is enabled it runs through the SPA**: `cmd/dotvault` sets `auth.Manager.BootstrapLogin` to `web.Server.BootstrapLogin`, and `runBootstrap` takes the transient token from that hook instead of dispatching the CLI oidc/ldap flow — so no TTY and no dotvault-opened browser is required, which is what makes bootstrap work under `dotvaultw.exe` (GUI subsystem, no console). The hook is a plain func, deliberately, so `internal/auth` gains no dependency on `internal/web` (the import direction is web→auth). The seam is variant-agnostic — `runBootstrap` never touches the store or `p.Method` — so one path serves all three variants. **The security crux:** the bootstrap token carries `pki/sign`, so `web.Server.BootstrapLogin` returns it *raw* and the adoption sites in `handleAuthCallback`/`handleLDAPStatus` divert before `Downscope`/`SetToken`/`WriteTokenFile`/`authDone` (`internal/web/bootstrap.go`); it never reaches the shared client, the token file, or `GET /api/v1/token`, which returns `s.vault.Token()` verbatim to any loopback caller. Without the web UI the CLI bootstrap flow still applies (browser for OIDC, TTY for LDAP, or a BYO cert). Known v1 limits: the bootstrap token is never revoked (no `auth/token/revoke-self`), so it stays valid at Vault until its own TTL expires — keep the bootstrap policy narrow and short-lived; and the TPM backend is not hardware-tested in CI.

### Peer-socket token borrow (`vault.token_socket`)

When `vault.token_socket` names a Unix-domain socket served by a peer dotvault daemon's web API, `Manager.Login` (and therefore every login and the recovery side of token refresh) first tries to **borrow a live token from the peer** before running the configured auth flow — the programmatic equivalent of `curl --unix-socket <path> http://localhost/api/v1/token` against the web UI's existing `GET /api/v1/token` endpoint. This is the dotvault-to-dotvault sharing seam: a machine with no browser or TTY (a headless Linux box reached over SSH) borrows the token from a workstation that authenticated interactively, with the workstation daemon's loopback web listener exposed on the remote as a socket via an SSH `RemoteForward`. The borrow logic is `auth.FetchTokenFromSocket` (`internal/auth/socket.go`): it stats the socket first (a missing file is the common "peer not connected" case and skips the dial), dials over a unix `http.Transport`, sends `Host: localhost` (on the web server's DNS-rebinding allowlist), and decodes `{"token": …}`. It is **best-effort and never fatal** — empty path, missing/stale socket, non-200 (peer holds no token), or malformed body all resolve to `("", nil)` and the caller carries on with its normal flow. The borrowed token is validated via `LookupSelf` at the call site (exactly like the file/env candidates) and is held **in memory only**, never written to `~/.dotvault-token`: the peer stays the single owner, so the "+tpm" sealing question never arises and the remote re-borrows on its next login/refresh rather than caching a copy that could go stale. The lifecycle manager wires it as a third `tryReload` candidate (after file and env, so a locally-written token wins), so an invalid token recovers by borrowing instead of forcing re-auth. The `token_socket` field is local-only data and round-trips through YAML, the registry (`Vault\TokenSocket` REG_SZ), and `.reg` like every other Vault field; a leading `~` is expanded at fetch time. The exported `client/` facade carries it too (`client.VaultConfig.TokenSocket`). The same socket carries traffic the other way: `dotvault browse` posts URLs to the peer's `POST /api/v1/remote/browse` endpoint so browser-driven flows on the headless box open in the workstation's browser, `dotvault notify` posts to `POST /api/v1/remote/notify` so notifications appear there, and `dotvault clipboard` posts to `POST /api/v1/remote/clipboard` so a value to paste (a one-time token for a page browse just opened) lands on the workstation's clipboard (see CLI). See `docs/configuration/config-reference.md` for the SSH `RemoteForward` wiring.

The borrow is wired into every code path that needs a token, not just interactive `Manager.Login`. **Daemon startup borrows directly:** `cmd/dotvault` attempts a socket borrow centrally right after the initial token-file/env reuse check (before the web/headless/interactive method branching), so a headless box whose `.dotvault-token` is absent borrows from the peer instead of falling into the `waitForHeadlessToken` idle and blocking forever — the bug this seam previously had, since the headless idle only ever watched the token *file*. **The headless idle also watches the socket:** `waitForHeadlessToken` registers a second `tokenwatch` (inotify on Linux, no-op elsewhere) on the socket's parent directory alongside the token-file watch, and its acquire loop tries the file first then borrows from the socket — so a socket that materialises after startup (an SSH `RemoteForward` connecting late) triggers an immediate borrow rather than waiting out the 10s poll. **The running daemon watches the socket too:** a third `tokenwatch` on the socket directory nudges `LifecycleManager.Reload()` on creation/replacement *only when `lm.NeedsReauth()` is set* (the daemon's borrowed token expired while the socket was stale), and `tryReload` re-borrows — so a forwarder that reconnects after the token died is picked up the moment it returns instead of waiting out the 10s recovery poll. The gate is deliberate: `tryReload` adopts any *different* valid candidate, so an unconditional nudge would demote a still-healthy token to a borrowed one every time the forwarder flapped. **The `client/` facade borrows on the cached path:** `AuthenticateCached` (the side-effect-free, never-prompt entry point used by `doctor`-style preflight *and the Python bindings*) tries a socket borrow after env+file come up empty, before returning `ErrLoginRequired`. A plain HTTP GET over a Unix socket has no browser/prompt side effect, so it stays within the cached contract; this means a Go or Python consumer on a host with no local token but a live peer socket authenticates without an interactive `Login`. **`dotvault status` borrows read-only to report state:** `runStatus` resolves env+file first and, when both are empty and a socket is configured, borrows from the peer before calling `LookupSelf`, so a host authenticated purely by borrowing (no token file at rest) reports `authenticated` — with a `source: borrowed from peer socket` line — instead of the misleading `not authenticated (no token)`; it never writes the borrowed token, matching the in-memory-only ownership contract.

### Local API socket (`api.enabled`)

`vault.token_socket` solves "this host has no browser or TTY" but not "this host's SSH session went away". The forwarded socket dies with the connection, so a process started inside that session and outliving it (a tmux job, a service) borrows successfully at first and then fails the moment it next needs a token — its only source is gone. `api.enabled` closes that gap by making the long-lived per-user daemon serve the *same* borrow endpoint from a path no disconnect can remove: `$XDG_RUNTIME_DIR/dotvault/api.sock` (`paths.DefaultAPISocket`, cache-dir fallback like `DefaultAgentSocket`). The daemon keeps its own token alive and re-borrows across the forwarded socket when the SSH session returns; local clients borrow from the daemon instead of from the forward. The daemon is then the single place that has to survive a disconnect.

**One mux, two listeners.** `web.Server.Start` binds a list (`Server.listen`): the loopback TCP listener when `web.enabled`, the Unix socket when `api.enabled`, either or both, all sharing one `http.Server` and one mux — a request means the same thing whichever way it arrived. Start reports the *first* listener failure immediately rather than waiting for the others (a dead TCP listener must not go unreported while the socket keeps the daemon looking healthy), and `Shutdown` unlinks the socket node only when `socketBound` says this Server actually bound it — the losing side of an `ErrAlreadyListening` race runs its deferred `Shutdown` too, and unlinking there would delete the *winning* daemon's socket, leaving it serving an unreachable inode. Routes are split: `registerAPIRoutes` (health, status, rules, config, config download, token, secrets, sync, the peer actions) runs on every listener, while `registerUIRoutes` (the auth/OAuth routes, the enrolment routes the SPA drives, and the SPA itself) is registered **only** when `web.enabled`. That split is not tidiness: the auth and OAuth handlers build redirect URIs from the bound TCP address, so on a socket-only daemon they would hand the IdP a URI pointing nowhere — publishing a login surface whose only possible outcome is a confusing failure. Consequences wired accordingly: `URL()` returns `""` with no TCP listener (so the daemon's browser-open paths can tell there is nowhere to point), `cmd/dotvault` gates web-driven auth on `cfg.Web.Enabled` rather than merely on the server existing, and `originAllowed` rejects *any* `Origin` on a socket-only daemon (a browser cannot reach a Unix socket, so an Origin there is a proxied request — and the check's no-known-port fallback is hostname-only, which would admit a page from any other loopback listener).

**Enabled separately from `web` on purpose.** The TCP listener is a browser UI reachable by every uid on the box; the socket is `0600` in a `0700` dir and reachable only by its owner. A headless host should not have to stand up a web UI to get the borrow endpoint, and enabling the socket widens nothing `web.enabled` already exposes — it is the tighter surface of the two. Bind hygiene is `internal/uds.Listen`, shared with the SSH agent listener so the owner-only invariant (0700 parent, stale-socket removal that refuses to clobber a live instance, bind-then-chmod rather than a umask swap) has exactly one implementation; only the already-running message is per-surface (`uds.ErrAlreadyListening`, wrapped by each caller). The whole probe-remove-bind sequence runs under an advisory `flock` on a `<socket>.lock` file beside the socket (`withBindLock`): without it two processes racing from cold can both pass the liveness probe, and the loser then unlinks the *winner's* freshly-bound socket and binds its own on top — both believe they succeeded and the winner serves an inode no client can reach. The lock is held only across the bind (the bound socket is thereafter its own evidence of ownership) and the lock file is never unlinked, since removing a file others hold flocked is how you end up with two holders of one lock.

**Borrow order is local-first.** `config.TokenBorrowSockets()` returns `[api socket, vault.token_socket]` — most-stable-first, since the forwarded peer is the one that disappears. The seam is `auth.FetchTokenFromSockets(ctx, paths) (token, source)`; the carriers are `auth.Manager.TokenSockets`, `LifecycleManager.SetTokenSockets`, and `client.VaultConfig.APISocket` + `TokenSocket` (the facade keeps both as exported strings and orders them in `borrowSockets()`). The daemon excludes its **own** socket (`daemonBorrowSockets`, `cmd/dotvault/apisocket.go`) — borrowing from itself would either return the token it already holds, muddying the log line that says where a token came from, or 401 against its own listener before it has authenticated. `dotvault login` excludes it too (`freshLoginBorrowSockets`): the command exists to run the fresh-auth flow and ignore cached tokens, and the local socket is exactly a cache of what this host already holds, so borrowing there would make it a silent no-op. A *peer* socket is different in kind — the workstation at the far end is a separate authentication authority where a human really did log in — so that borrow stays. The Windows gate lives in `config.apiSocketCandidate`, not just at the bind site, so every consumer (borrow lists, `dotvault status`, the `client/` facade) agrees that no socket exists there rather than carrying a permanently dead candidate. **Direction matters and the orders differ:** the peer actions (`browse`/`notify`/`clipboard`) deliberately keep using `vault.token_socket` alone, because their purpose is to reach the workstation where a human is looking — routing them to the local daemon would open a browser on the headless host nobody is sitting at.

**Two supporting behaviours.** `/api/v1/token` declines (401) once the daemon knows its own token is dead, via a `SetReauthGate` wired to the lifecycle manager: with a local daemon acting as the authority for a machine's worth of clients, lending out a known-bad token just relocates the failure to a borrower that cannot recover on its own. And a *renewal* failure on a still-valid token (`auth.IsRenewFailed`, the tagged `RenewSelf` error) now triggers a `tryReload` before the normal backoff — a lease at its max TTL can never be extended, so the only way to stay authenticated without an interactive login is to pick up a peer's fresher token, and waiting for the recovery path would mean running to expiry first.

**systemd socket activation (optional, Linux).** The packaged `dotvault-api.socket` / `dotvault-agent.socket` units (shipped, not enabled) let systemd bind either socket and hold the fd across daemon restarts, so clients queue in the backlog instead of failing while the daemon is down. The consumption seam lives in `internal/uds` (`activation*.go`); the sd_listen_fds *protocol* layer — env parsing, LISTEN_PID matching, CLOEXEC on the inherited fds, env scrubbing — comes from `github.com/coreos/go-systemd/v22/activation` (the same library's `daemon` package provides sd_notify: READY/STOPPING/WATCHDOG, which replaced the former hand-rolled `internal/sdnotify`; only the half-interval watchdog ticker remains ours, in `cmd/dotvault/watchdog.go`). `ActivatedListener(name)` claims the inherited fd matching the unit's `FileDescriptorName=` ("api"/"agent"; requires systemd ≥227) via a once-guarded snapshot that runs whether or not any surface consumes a listener — dotvault execs children (clipboard writers, enrolment engines) that must inherit neither live listening sockets nor the LISTEN_* variables. Library semantics adopted knowingly: a garbled `LISTEN_PID`/`LISTEN_FDS` reads as "no activation" (the daemon then self-binds and trips over systemd's live socket with an "already serving" error — symptom named, not the garbled env), a garbled name list degrades to placeholder names that end up drained with a warning, and an unnamed fd arrives as `LISTEN_FD_<n>` rather than the protocol's "unknown". The fds are retained as process-lifetime masters and every claim hands out a fresh dup: that is what lets the SSH agent's supervision loop re-listen after a failure instead of finding the fd consumed and self-binding against the systemd-owned path (an "already running" loop). Invariants are *verified on what systemd hands over*, never assumed from the unit: the socket node's filesystem mode (what actually gates `connect()`; fstat on a socket fd reports 0777 regardless) must be ≤0600, the parent directory must be owner-only and same-uid (the half of 0600-in-0700 a node check misses — a writable parent lets the node be swapped for an impostor), abstract-namespace sockets are refused outright (no file permissions at all), and the fd must be a unix stream listener — a violation is a fatal refusal, never a self-bind fallback. This validation layer is exactly what the library deliberately does not do, and is why `internal/uds` still exists on top of it. The unit's `ListenStream=` path wins over the configured path (getsockname is the source of truth, adopted so `status` reports the socket that actually exists); `socketBound`/`Listener.activated` stay false/set so shutdown never unlinks a node the socket unit keeps serving; the service unit sets `RuntimeDirectoryPreserve=yes` because without it systemd deletes `%t/dotvault` — socket nodes included — on every service stop, breaking activation on the first restart it exists to smooth. Config stays the master switch: an activated fd for a disabled surface is *drained* (accept-and-close, `DrainUnclaimedActivation` with a keep-list since the agent claims only after first auth) — closing our dup would refuse nobody, as systemd retains its own fd and clients would hang in an unaccepted backlog. This is fd-passing, not start-on-demand: the service remains `WantedBy=default.target`. Off Linux the calls are inert stubs and the self-bind path runs unchanged. The wiring seams are injectable vars (`activatedAPIListener` in `internal/web`, `activatedAgentListener` in `internal/agent`) because the snapshot is process-global and unfakeable in-process.

**Deployment note.** `$XDG_RUNTIME_DIR` is torn down when the user's last session ends unless `loginctl enable-linger` is set — which is required anyway for a user service meant to outlive an SSH session. The packaged `dotvault.service` declares `RuntimeDirectory=dotvault` (0700) so systemd owns the directory's lifecycle and a killed daemon leaves no stale socket. The section round-trips through YAML, the registry (`API` subkey: `Enabled` REG_DWORD + `UnixPath` REG_SZ), and `.reg`.

### Least-privilege token policies (`vault.policies` / `vault.no_default_policy`)

By default a login token carries every policy the auth role grants the user, which over-provisions a credential cached on disk. When `vault.policies` is non-empty (or `vault.no_default_policy` is true), each fresh login is **downscoped**: right after obtaining the broad login token, dotvault exchanges it for a child token restricted to exactly the configured policies (and, with `no_default_policy`, without the implicit `default` policy), then adopts and persists the child. Vault enforces the child's policies are a subset of the parent's, so this can only drop privilege. The seam is `auth.PolicyConstraint` + `auth.Downscope` (`internal/auth/downscope.go`), which mints the child on an *isolated* sibling client (`vault.Client.NewSibling` → `CreateChildTokenFor` → `auth/token/create`, renewable, `DisplayName: "dotvault"`) so the shared client is never set to the broad token — a failed downscope can't leave the broad token installed on (or retrievable via `/api/v1/token` from) the web server, and there's no window where a concurrent reader sees it. The sibling inherits the connection's client certificate, so on a Vault listener that requires a client cert on every request the mint still presents it. It is called at every fresh-mint site — the CLI oidc/ldap/mtls flows pass the configured `Manager.Policy` (the mtls flow downscopes through the cert-presenting client), the web login paths pass `Server.policyConstraint()` — but **not** on token reuse (reusing a downscoped token must not create a grandchild) nor for the `token` auth method (user-supplied) nor the mtls bootstrap login (it needs `pki/sign`; the bootstrap also runs on its own isolated sibling client, so its broad PKI token never touches the shared client and only the final cert-auth token is adopted). Downscoping **fails closed**: a failed child-token mint is a login error, never a silent fallback to the broad token. `Downscope` is a pure "maybe exchange the token" helper; the one-line transition WARN for an unconfigured constraint lives in `auth.WarnUnrestrictedPolicy`, called only at the sites that adopt a final operational token from a downscopeable login (the CLI oidc/ldap dispatch in `Manager.Login`, `authenticateMTLS` once per operational login, and the web oidc/ldap handlers; the `token` method / web token-login is exempt, like downscoping itself) — never on the mtls bootstrap sub-login (which dispatches `authenticateOIDC`/`authenticateLDAP` directly, bypassing `Login`), so a transient bootstrap token does not trigger the notice even when the outer mtls config has policies set. The fields round-trip through YAML, the registry (`Vault\Policies` REG_MULTI_SZ + `Vault\NoDefaultPolicy` REG_DWORD), and `.reg`, and are projected onto the public `client` facade. **Operator requirement:** any policy named in `vault.policies` must grant `auth/token/create` (Downscope mints the child), `auth/token/lookup-self` (the lifecycle manager's 5-minute check) and `auth/token/renew-self` (renewal at 75% TTL) — stripping `default` strips all three. The `lookup-self` case is the dangerous one: a 403 there is read as "token invalid", so a daemon holding a perfectly good token re-authenticates in a permanent loop. Found by `test/integration/mtls_test.go` against a real Vault; the dev stack's policy is a working reference. **Staged rollout:** `no_default_policy` defaults false today (backwards-compatible); a future release flips the default to true, and 1.0 removes the ability to disable it. See `docs/configuration/config-reference.md` and the tracking GitHub issues.

### No token at rest (`mtls+os`)

`mtls+os` writes no token file. `auth.PersistTokenAtRest(method)` is false for the literal `mtls+os` and true for everything else, including any other base wearing the `+os` suffix — the suffix parses on any base, but no-persist is implemented only off `mtls`, and since there is no `auth_method` allowlist an `oidc+os` config loads and routes to `authenticateOIDC`, which writes the token file unconditionally and never consults the predicate. The predicate's godoc is the canonical statement of that reasoning; the gate's call sites point at it rather than restating it. `certLogin` consults it and, instead of writing, calls `auth.RemoveTokenFile` — escalating a removal failure to a login error, because a token that could not be removed is a token still on disk. Removal is the load-bearing half: a host upgraded from plain `mtls` already holds a valid plaintext token, so declining to write a new one would leave the old one in place. The daemon's startup reuse-check also excludes the file for this method (`resolveTokenForMethod`), since reuse runs *before* login and would otherwise adopt the stale credential before `certLogin` ever got the chance to delete it. Startup deliberately does not *delete* it: `mtls+os` is Windows-only, so on Linux/macOS the login fails later at `securestore.Open`, and deleting first would destroy a working token to enforce a guarantee that login was never going to reach.

The removal is ordered *before* the minted token is adopted onto the shared client, so a login that cannot honour the guarantee installs no new token — adopting first and erroring afterwards would leave a live token on the client that `GET /api/v1/token` would serve, in the name of a login the operator was told had failed. Ordering it first needs no rollback and so has none to forget. The claim is narrow, and the docs state it as such: on a re-login or an automatic re-issue the client already holds an earlier token and that one survives, and the new token has already been minted at Vault and is never revoked. The error also wraps `auth.ErrTokenAtRest`, which `authenticateMTLS` checks before its re-seed fallthrough — without it an undeletable file reads as an unusable credential and triggers a full interactive bootstrap plus a wasted PKI issuance on every startup, which then meets the same file and fails identically.

This is viable because the token is not load-bearing under this method: the certificate is the credential, and `CertLoginFromStore` re-derives an operational token from it with no human involved, so the file was only ever a latency optimisation. Sealing (the `+tpm` approach) is not available here — the CNG key is non-exportable and sign-oriented, and `mtls+os` accepts EC P-256 as well as RSA, so no single decrypt primitive covers both.

Every reader of the token file needed its own answer, and they differ by call site. **Daemon startup** skips the file and falls through to the cert login it would have run anyway. **`dotvault status`** reports the *certificate* (via `auth.InspectCertCredential`) rather than a token — verifiable from disk and side-effect free, where minting a token to answer an informational question would make an observation command mutating. **`dotvault login-check`** returns immediately while the certificate is valid (no interactive login is possible or needed, and a cert login has no place in a shell-startup latency budget) — but a **missing or expired** certificate is precisely what it exists to surface: re-issuance needs a still-valid certificate, so a lapsed one cannot self-heal and needs a fresh bootstrap, which it warns about and then performs. **`dotvault enrol`** derives a token from the certificate rather than refusing, since that needs no human and so does not breach its rule against interactive login. **`Manager.Authenticate`** — the sixth reader, and the one that made the guarantee false until review caught it: it read the file unconditionally, so `dotvault sync` adopted a stale plaintext token and returned before `Login`, meaning `certLogin` never ran and never removed it. It now excludes the file under a no-persist method. **`client.AuthenticateCached`** — the seventh, and the one Copilot's review surfaced: it already falls through to `CertLoginFromStore` after env/file/socket, but it also read the file unconditionally, and a library consumer cannot rely on the daemon's next login ever removing a leftover one (the daemon may be stopped, or the consumer may be the only dotvault on the host), so a stale token stayed silently usable for the rest of its TTL. It now applies the same `PersistTokenAtRest` gate; `DOTVAULT_TOKEN` is unaffected, being caller-supplied and never at rest. The **SSH agent** signs against the daemon's in-memory token and never reads the file.

Two *runtime* readers were missed by that enumeration and found by a later review, which is why removal-at-login alone was not the whole guarantee: `LifecycleManager.tryReload` and the headless idle's `tryPromote` both read the file unconditionally, and the `tokenwatch` inotify nudge fires `Reload` on file *creation*. So a file appearing after login — restored from a backup, written by an older build, or dropped by anything running as this user — was adopted as the daemon's working credential, and ahead of the `RecoverCertLogin` hook that is the correct source of a replacement under this method. The fix is at the wiring, not in the readers: `cmd/dotvault` declines to call `lm.SetTokenFilePath` and skips registering the token-file watch under a no-persist method, and passes `headlessTokenPath(method, tokenPath)` — which returns `""` for `mtls+os` — into `waitForHeadlessToken`, so the idle watches and borrows from the socket alone. Gating at the wiring rather than inside each reader means a future reader inherits the guarantee instead of having to remember it.

The property is deliberately narrow, and `docs/authentication/mtls.md` states it in full: no usable token in plaintext at rest, the only durable secret being the non-exportable CNG key. It is **not** process isolation — the OS store's access control is per-user, so any process running as the same user can drive the key and mint its own token. `GET /api/v1/token`, the peer socket, `DOTVAULT_TOKEN`, and the daemon's process memory are all unchanged.

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
2. If no usable token is available anywhere, try **unattended recovery**:
   the optional `SetRecover` hook mints a fresh token from a credential
   this host already holds, with no human involved. Certificate auth is
   the motivating case and currently the only registrant — the client
   certificate *is* the credential, so `Manager.RecoverCertLogin`
   (load credential → cert login, deliberately **never** falling back to
   bootstrap, since a background goroutine has no user attached) fixes an
   expired token on the spot. This runs *before* step 3 specifically so a
   recovery the daemon healed itself never fires `OnReauth` and never
   bounces the SPA to a login screen. Methods whose credential is a human
   (oidc, ldap) leave the hook nil and fall straight through.
3. If recovery is unavailable or fails, signal re-auth: fire the registered
   `OnReauth` callback (web mode clears the in-memory token, invalidating
   any browser session sitting on a stale "logged-in" view), push an
   error on the error channel, and switch to a 10-second recovery poll
   so a subsequent token write is picked up quickly. The recovery hook is
   retried on those polls, so a cert-auth daemon that could not recover
   immediately (Vault briefly unreachable, say) still heals without a
   restart once the cause clears — but with **exponential backoff after
   the second consecutive failure** (doubling from the recovery interval
   to the 5m cap). An attempt is not cheap: for `mtls+tpm`,
   `securestore.Open` derives the SRK with a `TPM2_CreatePrimary`
   (hundreds of ms to seconds on real hardware) purely to verify the
   backend, and `Load` derives it again — so at full rate a sustained
   outage would mean hundreds of primary-key derivations an hour
   contending on `/dev/tpmrm0`, and anyone able to revoke tokens could
   sustain that churn indefinitely. The *first* failure is deliberately
   not penalised, since the poll is already the retry, so a brief blip
   still heals at the normal cadence.

Why this matters for certificate auth: the daemon performs its cert login
once at startup, and `ReissueIfDue` rotates the *certificate*, not the
token. Without the recovery hook a Vault token that expired mid-session —
or reached its `max_ttl` and could no longer be renewed — left the daemon
unauthenticated until someone restarted it, despite the credential needed
to fix it sitting right there on disk. That defeats the purpose of an auth
method whose whole point is needing no human.

In web mode the daemon also re-opens the browser to the web UI root when
the lifecycle manager signals re-auth, subject to a 10-minute cooldown
to avoid flapping during transient errors.

## Public client API

`client/` (`github.com/goodtune/dotvault/client`) is the only supported import boundary for other Go modules. It is a thin facade over `internal/config`, `internal/auth`, and `internal/vault` that exposes dotvault's connectivity, token-resolution order, login flow, and `kv/users/<user>/...` path convention so a consumer reads from exactly where dotvault writes instead of re-deriving any of it. The surface is deliberately generic — it makes no assumptions about the calling tool. The internals stay internal; the facade lets them be refactored freely. See `client/README.md` for the consumer-facing write-up.

Surface: `LoadConfig(path)` (projects the validated system config onto a connectivity-and-auth-only `Config`; `DefaultConfigPath()` / `DefaultTokenFile()` give the canonical locations), `New(cfg, ...Option)`, and on `*Client`: `Authenticate` (env → file → interactive login, short-circuiting `ErrUnreachable` without prompting), `AuthenticateCached` (env → file → peer socket → this host's client certificate under an `mtls*` method, with the file skipped under `mtls+os`; never prompts — for side-effect-free `doctor`-style preflight, returns `ErrLoginRequired` when no token is usable), `Login` (unconditional fresh login, `= dotvault login`; **refuses under an `mtls*` method** — see certificate auth below), `IdentityName`, `Token`, `ReadKVField(ctx, mount, path, field)`, and `ReadUserSecret(ctx, service, field)` (composes `{kv_mount}/{user_prefix}{identity}/{service}`). Reads return `(value, found, err)` so a missing path/field is `found == false` with `err == nil`, never conflated with a transport failure. The facade also exposes the socket-forwarded **peer actions** `Browse(ctx, url)`, `Notify(ctx, level, title, body, actionURL)`, and `Clipboard(ctx, text)` (`client/remote.go`; `actionURL` is the optional clickable link): they POST to the peer named by `vault.token_socket` (`auth.PostFormToPeer`, the shared transport with the CLI) so a headless consumer hands a URL, a notification, or a value to paste back to the workstation over the same socket it borrows tokens from. Unlike the `dotvault browse`/`notify`/`clipboard` CLIs they have **no local fallback** (a headless library has no local browser/notifier/clipboard), and they do **no local validation** — the peer endpoint validates and sanitizes authoritatively (that is where the action and the security boundary are), so the facade stays a thin transport and the `.so` never pulls in `internal/web`, `internal/notify` (beeep), or `internal/clipboard`. Error categories are `errors.Is`-able sentinels: `ErrLoginRequired`, `ErrAuthFailed`, `ErrDenied`, `ErrUnreachable`, and `ErrPeerUnavailable` (peer not configured / unreachable / reported an action failure; a peer *400* — request rejected as invalid — surfaces as a plain uncategorised error carrying the peer's message). `New` takes functional `Option`s (extension point kept open so future inputs don't break callers); `WithIdentity(name)` overrides the path-identity segment. The exported `Reader` interface (`IdentityName`/`ReadKVField`/`ReadUserSecret`, which `*Client` satisfies) is the seam consumers depend on and fake in tests — auth is excluded from it because it has side effects that belong in `main`.

**Certificate auth is consumption-only through the facade.** `AuthenticateCached` gains a fourth candidate under an `mtls*` method: after env, file, and peer socket come up empty it calls `auth.Manager.CertLoginFromStore` to present the certificate this host already holds. That stays inside the never-prompt contract (no browser, no terminal, no user) and is what makes cert auth usable from a library at all — otherwise a consumer whose daemon is stopped, or whose cached token expired, would get `ErrLoginRequired` with the fixing credential on the same disk. It is tried **last** (a cached token is cheaper than a Vault round trip plus a hardware key op) and the minted token is held **in memory only**, never written to the token file, which belongs to the daemon — the same ownership rule as the peer borrow. Conversely `Login` **refuses** under an `mtls*` method with `ErrLoginRequired`: a fresh cert login would run the bootstrap (OIDC browser or LDAP TTY, then mint a certificate onto this host), which no library embedded in someone else's process should do. The projection enforces this structurally — `client.VaultConfig.MTLS` carries only `CertMount`/`CertRole`/`StorageDir`, with no PKI mount/role, bootstrap method, or BYO paths, so the issuance flows cannot run even if reached. `CertLoginFromStore` itself never bootstraps and never rotates (rotation belongs to the startup path and the hourly re-issue check, which must not race a second writer), and is shared with the daemon's unattended token recovery.

**Identity is the OS user, not the token.** `IdentityName` (deliberately ctx-less — a local OS lookup, no Vault call) returns `paths.Username()` (the OS account, `DOMAIN\` prefix stripped) — the same value the sync engine and enrolment manager use to lay out `kv/users/<user>/...`. It is deliberately *not* derived from the Vault token's `display_name`/entity/metadata, because that is not what dotvault writes under. Consumers must therefore run as the same OS user as the dotvault that populated the secrets (normally true for a per-user daemon) or pass `WithIdentity(name)` to set the segment explicitly when they can't (a service account, a container) — `WithIdentity` also makes downstream tests deterministic. This is the one place the public API contradicts a naive "identity comes from the token" assumption, and it is load-bearing — changing the *default* derivation would be a path-layout migration, not a facade tweak.

The facade legally imports `internal/*` because it lives inside the same module; external modules import only `client`, never the internals. When the connectivity/auth shape of the system config changes, update the `client.Config` projection (`client/config.go`) in lockstep so the public surface doesn't silently drift from what the daemon parses.

## Python bindings

`python/` packages the Go `client` facade for Python consumers (`pip install dotvault`). The architecture is a cgo `c-shared` bridge (`python/bridge/`, `package main`) wrapped by a pure-`ctypes` Python package (`python/src/dotvault/`). The bridge imports **only** `github.com/goodtune/dotvault/client` — never any `internal/*` package — so the same single-source-of-truth boundary the Go facade enforces holds for Python: token precedence, the OS-user identity convention, and the `kv/users/<user>/...` layout all come from the one Go implementation rather than being re-derived in Python.

Scope is the **read-only + cached-auth** subset of the facade plus the socket-forwarded **peer actions**: `AuthenticateCached` (never prompts), `IdentityName`, `Token`, `ReadKVField`, `ReadUserSecret`, `browse`, `notify`, and `clipboard`. Interactive `Login`/`Authenticate` (OIDC browser, LDAP terminal) are deliberately excluded — driving them across an FFI boundary from inside a Python process is awkward and not what a library caller wants; such callers provision a token out of band (`dotvault login`, or the daemon) and the bindings consume it. `browse`/`notify`/`clipboard` are in scope precisely because they need **no** local token — they post over the peer socket — so a headless Python program can surface a URL, a notification, or a value to paste on the workstation.

ABI contract (`python/bridge/bridge.go` ⇄ `python/src/dotvault/_ffi.py` + `_errors.py`): a `*client.Client` lives entirely on the Go side in a handle table addressed by an opaque `int64` (cgo forbids passing Go pointers that contain Go pointers to C); `0` is never a valid handle and signals failure. Owned out-strings are malloc'd by Go (`C.CString`) and freed by Python via `dotvault_free` — `_ffi.take_str` does read-then-free at one site. Fallible calls return an integer category code mirrored verbatim on both sides (`catOK`/`catLoginRequired`/`catDenied`/`catUnreachable`/`catAuthFailed`/`catOther`/`catPeerUnavailable` = 0..6) which `_errors.error_for` maps to the `DotvaultError` hierarchy (`LoginRequired`/`Denied`/`Unreachable`/`AuthFailed`/`PeerUnavailable`, base for everything else); reads return `Optional[str]` (`None` = not-found, never conflated with a transport error). **When extending the surface, change the category codes on both sides together** and add a matching exception class. (The `catPeerUnavailable` code and `PeerUnavailable` exception were added in lockstep for the `browse`/`notify` surface — the worked example of this rule.)

Env-var gotcha the bridge handles: the Go runtime snapshots `os.Environ` at load, so a var the host (Python) sets *after* the `.so` loads is invisible to `os.Getenv`. `syncEnv` re-reads the facade's vars (`DOTVAULT_TOKEN`, `VAULT_NAMESPACE` — `VAULT_TOKEN` stays ignored) straight from libc with `C.getenv` at every entry point that resolves a token or builds a Vault client, so `os.environ["DOTVAULT_TOKEN"] = ...` after import behaves as expected.

Build: the Python tooling is **uv**. `make python-lib` compiles the bridge into the package for local pytest/editable installs; `make python-wheel` (`uv build --wheel`) builds the wheel (`setup.py` rebuilds the bridge during the build, locating the Go module root by walking up for `go.mod`, so it works from a clean checkout). This is the **one** place dotvault builds with `CGO_ENABLED=1` — c-shared requires cgo — and it is a separate artefact, so the main binaries stay `CGO_ENABLED=0` pure-Go static builds. The wheel is tagged **`py3-none-<platform>`**, not `cpXY`: it bundles a native shared library (so it is platform-specific) but contains no CPython C-extension — it is pure ctypes linking libc, not the Python C-API — so one wheel per OS serves every supported Python (a `bdist_wheel.get_tag` override in `setup.py` forces this; the default would mislabel it `cp311-cp311`). The wheel **version** is derived by `setuptools-scm` from the repo's git tags (`[tool.setuptools_scm]` with `root = ".."`), the same v-prefixed tags that version the Go build — an exact tag gives a clean `0.23.0`, commits past a tag give a PEP 440 dev version (`0.23.1.dev8+g<sha>`), and `__version__` reads it back via `importlib.metadata`. CI checks out with `fetch-depth: 0` so the tags are present at build time. Tests run on both sides: `go test ./python/bridge/...` (handle table, category mapping, `syncEnv`) and `uv run --no-project --with pytest python -m pytest python/tests` (offline — points at a closed Vault port and asserts error categorisation). CI is `.github/workflows/python.yml`: per-OS wheels — macOS (arm64, no Intel) and Windows build natively via `uv build`; Linux builds inside a `manylinux_2_28_x86_64` container (Go installed in it so the cgo `.so` links glibc ≤2.28) and `auditwheel repair` retags it from the PyPI-rejected `linux_x86_64` to `manylinux_2_28_x86_64`. When a GitHub Release is published (the `release: published` event, the same one that drives the Go release in `release.yml`, so both artefacts ship from one gesture and a stray pushed tag can't leak wheels) the `publish` job collects all wheels and uploads them to PyPI via the official `pypa/gh-action-pypi-publish` action using **Trusted Publishing (OIDC)** — no stored token, scoped to the `pypi` GitHub environment; a matching pending publisher must be configured on PyPI once (project `dotvault`, this repo, workflow `python.yml`, environment `pypi`) before the first release. Wheels only — no sdist, because the sdist can't build standalone (the Go module lives in the parent repo, not under `python/`). The `python/` directory has its own `dependabot.yml` pip entry. See `python/README.md` for the consumer write-up.

## Sync Engine

Hybrid event-driven + polling model (`internal/sync/`):

- **Enterprise Vault:** subscribes to `kv-v2/data-write` events via WebSocket (Events API), filters by user prefix, syncs affected rule immediately
- **Community Vault:** poll-only at configured interval
- **Graceful degradation:** if WebSocket fails, falls back to polling with exponential backoff (1s-5m)

Per-rule sync logic:
1. Read secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}` — *skipped entirely for a keyless rule* (no `vault_key`), which proceeds with an empty data context
2. Skip only if vault version unchanged AND the rule's render-affecting definition is unchanged AND file checksum unchanged. The rule fingerprint (`ruleRenderHash`: vault key + target path/format/template/merge, length-prefixed) is stored in state and is what makes a template edit re-apply on an otherwise-unchanged secret — without it, editing only `target.template` would skip forever because neither the secret version nor the on-disk file moved. Empty `rule_hash` in state written by an older version forces a one-time reconciling re-sync on upgrade. A keyless rule has no secret version, so for it the fingerprint and file checksum alone carry the skip decision (a never-synced rule's empty stored `rule_hash` can't match the computed one, forcing the first sync).
3. Render template (if present) with Vault data map as dot context (empty for a keyless rule; `{{ username }}` still resolves)
4. Parse rendered output through handler to get incoming structured data
5. Read existing file via handler (missing file is empty state, not error; missing parent dir created at 0755)
6. Merge incoming into existing via handler
7. Write atomically (temp file + rename)
8. Update state (version, timestamp, checksum, rule hash)

Per-rule isolation: one rule failing does not block others.

### State Store

Persists to `{cache_dir}/state.json`. Per-rule: vault version, last synced timestamp, SHA-256 file checksum, and `rule_hash` (the render-affecting rule fingerprint that gates re-sync on a template edit). Atomic writes via temp file + rename.

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
| ssh_config | Custom parser (no external dep) | Surgical directive-level merge within each Host/Match section; comments and unmanaged directives preserved verbatim. Template-only (no raw-data path). Repeatable keywords (forwards, `IdentityFile`, `SetEnv`, …) merge by a discriminator drawn from the first argument, so the discriminator *is* the directive's identity: changing it renders a new line (old one orphaned), not a rewrite — a deliberate coexistence trade-off, documented in `docs/configuration/sync-rules.md` |

The `merge` field exists in rule config but is not dispatched on. Each handler always uses its native merge strategy, which is the only sensible strategy for that format.

All writes are atomic (temp file with target permissions + rename). Permissions: all managed files use 0600.

## Template Processing

`internal/tmpl/` wraps `text/template` with custom functions:

- `env(key)` — environment variable lookup
- `base64encode(s)` / `base64decode(s)` — credential encoding
- `default(fallback, val)` — Sprig convention (fallback first)
- `quote(s)` — shell-safe single quoting
- `username` — the OS account dotvault runs under, i.e. the same `paths.Username()` identity the `kv/users/<username>/…` layout is built from (`DOMAIN\` stripped). It is a function rather than a dot-context field so it is available regardless of the secret's contents and cannot be shadowed by a secret field named `user`. Bound by `tmpl.RenderWithUsername` (the sync engine passes `e.username`); plain `tmpl.Render` leaves it bound to `""`. This is the seam that lets a rule template build per-user paths like `/home/{{ username }}/.ssh/dotvault.sock` without the username being stored in Vault.

Templates receive the Vault KV data map as dot context. The rendered output is parsed by the target format's handler to produce structured incoming data. The dot context is *only* the secret's fields — there is no implicit `.user`; per-user values that aren't secret data come from the `username` function instead.

## Enrolment

Automated credential acquisition from external services (`internal/enrol/`). Enrolments are declared in config under a top-level `enrolments` map keyed by Vault KV path segment.

Enrolment keys support one level of grouping (`group/name`, e.g. `databricks/prod`) so related enrolments cluster under a shared prefix. The key is treated as an opaque segment everywhere it flows: the Vault path nests naturally (`users/<you>/databricks/prod`); the web UI groups by the prefix-before-slash and renders an expandable folder (`internal/web/frontend/src/components/enrol-page.jsx`); the web API serves grouped keys through both a percent-encoded `{key}` segment and parallel `{group}/{name}` routes (`enrolKeyFromRequest`, `server.go`); and the Windows registry / `reg-import`/`reg-export` round-trip stores the key as one subkey literally named `databricks/prod` (a forward slash is legal in a registry key *name* — only backslash is the separator — so no nesting is introduced and the GPO-parity contract holds). `validateEnrolmentKey` (`internal/config/config.go`) enforces the one-level limit.

### Engine Interface

Engines implement `Name()`, `Run(ctx, settings, io)`, and `Fields()`. Registered in a package-level map. Currently implemented: GitHub (OAuth device flow), JFrog (browser-based web login), Databricks (OAuth U2M authorization-code + PKCE), ghp (CLI device-authorization flow against a self-hosted ghp server), SSH (Ed25519 key generation), Copy (mirror an existing KVv2 secret).

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

The Manager checks Vault for missing/incomplete secrets, then runs the Wizard for any pending enrolments. The Wizard runs engines sequentially with terminal progress display and best-effort clipboard support (via `internal/clipboard`, shared with the remote-clipboard peer action). On success, credentials are written to Vault KVv2, and the sync engine is triggered.

Config changes to the enrolments section are detected on each polling tick without requiring a daemon restart.

### Browser-based enrolment in the web UI

Several engines drive an interactive browser login (GitHub device flow, JFrog web login, Databricks OAuth U2M). These present an **actionable URL** to the user and then block on a result — a poll (GitHub/JFrog) or a loopback redirect listener (Databricks). The contract that makes these render correctly in the web UI, and the bug class to avoid:

- The web enrol runner (`internal/web/enrol_runner.go`) deliberately builds `enrol.IO` **without** a `Browser` opener (unlike the CLI paths in `cmd/dotvault/`, which set `Browser: browser.OpenURL`). The daemon must not pop a browser on a possibly-headless host, and the loopback web UI is the user's actual surface — so each engine's `io.Browser == nil` branch fires and it writes the login URL to `io.Out` rather than opening anything server-side.
- The enrolment card (`internal/web/frontend/src/components/enrol-card.jsx`) parses the engine's line-oriented output and renders one of: a **device-code card** when a `! First, copy your one-time code: X` line **and** an `https://` URL are present (GitHub/JFrog); a **redirect card** when only an `https://` URL is present with no code (Databricks); a **passphrase prompt** (ssh); or a raw-output fallback. Both the device-code and redirect cards expose a real **clickable "Open <service> →" anchor** — a genuine user gesture, so it isn't swallowed by pop-up blockers the way a programmatic `window.open` would be. The user clicks it, authenticates, and the card flips to the progress/complete state as the engine's output advances.
- **The failure mode this guards against:** a browser-login engine whose output the card doesn't recognise falls through to the raw-output branch and the user just sees the bare URL dumped into a code block with nothing to click — a "terminal flow in the browser". This was fixed for GitHub/JFrog (the device-code card) and then again for Databricks (the redirect card, which exists precisely because a pure authorization-code+PKCE flow has no user code to key the device-code card on).
- **When adding a new browser-driven engine,** emit the actionable URL to `io.Out` in a form the card already recognises (a line containing an `https://` URL, plus the `! First, copy your one-time code: X` line if and only if there is a user code), and attempt `io.Browser` only inside the non-nil branch. If the new flow has a genuinely new shape, add a matching branch to `enrol-card.jsx` rather than letting it land in the raw-output fallback. Verify the web experience, not just the CLI — the CLI path opens a real browser via `io.Browser` and can mask a missing web card.

## SSH Agent

`internal/agent/` exposes a read-only SSH agent backed by the live Vault token, served over a Unix domain socket (Linux/macOS) or a named pipe (Windows). Disabled by default (`agent.enabled: true`). The two platform listeners serve one shared, platform-neutral `Backend` that implements `golang.org/x/crypto/ssh/agent.ExtendedAgent`.

- **Backend (`backend.go`).** `List` aggregates identities from every configured `Source` and caches the result briefly (default 8s) so repeated `ssh-add -l` doesn't hammer Vault; a source whose `Identities` errors is skipped rather than blanking the whole agent. `Sign`/`SignWithFlags` route the requested key to the owning source and honour `rsa-sha2-256`/`rsa-sha2-512` — mirroring `List`'s per-source isolation, a source whose `Sign` errors is skipped and the next source is tried, so one source unable to produce a signature (e.g. a vault-ca role that can't currently mint) never blocks signing for a key owned by a different, healthy source; the per-source errors are only surfaced (joined) when no source ends up matching the key. `Add`/`Remove`/`RemoveAll`/`Lock`/`Unlock`/`Signers` return `ErrReadOnly` — dotvault is one-way, so the agent is too. Concurrency-safe: each connection is serviced in its own goroutine. If the lifecycle manager reports a re-auth in progress, `Sign` blocks on a bounded wait (`WithReauthTimeout`, default 30s) via the `ReauthGate` interface (`*auth.LifecycleManager` satisfies it) rather than failing spuriously. The gate is stored in an `atomic.Value` (wrapped in a `gateHolder`) so the daemon's post-construction `SetReauthGate` never races a concurrent `Sign`.
- **Sources (`agent.go` interface; `kv.go`, `vaultca.go`, `factory.go`).** A `Source` provides `Identities` and `Sign`. The **KV source** discovers keys under `kv/data/users/<you>/<path_prefix>` (the `public_key`/`private_key` schema the SSH enrolment engine writes), reads+parses+discards the private key per `Sign`; passphrase-protected keys are rejected (the agent can't prompt — enrol agent keys with `passphrase: unsafe`, since Vault is the at-rest protection). The **Vault-CA source** (ephemeral mode) generates an in-memory Ed25519 key at startup, mints a certificate via `<mount>/sign/<role>` (behind the `certSigner` interface so it's unit-testable without a live SSH CA), caches it until shortly before expiry (shared `defaultCertTTL` = 15m), and re-mints transparently on the next `List`/`Sign`. `Sign` first checks `mayOwn` — the requested key must match the stable ephemeral base key or the currently cached cert — before minting, so a key this source plainly doesn't own never triggers a (possibly failing) mint attempt; a cold cache (no cert minted yet) can't be ruled out this way and still falls through to a mint, which is why the `Backend`-level per-source skip above is the fix that actually prevents a source that can't mint from blocking other sources. Principals are Go templates over `{{.vault_username}}`. A source that can't be constructed (unknown engine, non-ephemeral vault-ca) becomes an `errSource` that reports its reason through `Status` without aborting the daemon.
- **Transport (`listener.go` + `listener_unix.go` / `listener_windows.go`).** Common `Serve(ctx)`/`Close` logic with platform-specific endpoint creation. `Serve` accepts in a loop, dispatches each connection to `agent.ServeAgent`, and treats post-`ServeAgent` `io.EOF` as a normal disconnect (debug log, not fatal). Context cancellation closes the endpoint and returns cleanly; `Close` is idempotent. **Endpoint permissions are a hard invariant** (the `0600`-equivalent): the Unix socket is bound then `chmod 0600` inside a `0700` dir (no process-global umask swap — that would race other daemon goroutines' file creation; the 0700 dir closes the brief window), with stale-socket removal that refuses to clobber a live instance ("already running"); the Windows pipe is created in byte mode with a protected-DACL SDDL (`D:P(A;;GA;;;OW)(A;;GA;;;SY)`) granting access only to the owning user and LocalSystem. dotvault never sets `SSH_AUTH_SOCK` or PuTTY registry values on the user's behalf. On Linux the Unix listener first tries a systemd-activated fd (`FileDescriptorName=agent`) before self-binding — see "systemd socket activation" under Authentication for the shared mechanics, including why shutdown must not unlink an activated node. On Windows with `agent.windows.putty` (default true), `listener_windows.go` additionally derives the Pageant-convention pipe name — `\\.\pipe\pageant.<user>.<sha256-hex>`, where the suffix is the hex SHA-256 of the `CryptProtectMemory(CROSS_PROCESS)`-obfuscated string `"Pageant"`, reproducing PuTTY's `capi_obfuscate_string` (per-boot key, so it must be computed at runtime; non-Windows builds carry a stub). The obfuscated bytes are fed to SHA-256 through PuTTY's length-prefixed `put_string` encoding — a four-byte big-endian length ahead of the bytes — not hashed raw; current PuTTY (`windows/utils/cryptoapi.c`) adds that prefix and a clone that omits it derives the stale pre-CMake-refactor name no live PuTTY client dials (`pageantSuffixHash`, `internal/agent/pageant_hash.go`). A pipe carries one name, so this is served as a *second parallel listener* over the same backend rather than an alias; failure to derive it is logged and skipped (the primary pipe always stands).
- **Service + lifecycle (`service.go`).** `agent.Service` bundles the backend and its listener(s). `resolveServeEndpoints` builds the endpoint list — the primary (configured/default) endpoint plus, on Windows with PuTTY enabled, the Pageant pipe — and `Run` supervises one listener goroutine per endpoint, all sharing the single backend. `Endpoint()` reports the primary (the one `dotvault status` queries); `Endpoints()` reports all. The backend is constructed before auth (side-effect-free) so the web server can surface its status; the listeners `Run` only after the first successful Vault auth, supervise themselves (restart-on-terminate after a short backoff), and stop on context cancellation. The backend persists across token refreshes without a listener restart. `Status(ctx)` returns listed identities, per-cert TTL, and per-source resolution errors — surfaced on `/api/v1/status` (web dashboard, parallel to per-rule sync state).
- **Status as a client (`query.go`).** `dotvault status` does not stand up a backend. When `agent.enabled`, it dials the resolved endpoint via `QueryListening` (the platform-split `dialEndpoint`: `net.Dial("unix", …)` / `winio.DialPipeContext`) and runs `agent.NewClient(conn).List()` — the `ssh-add -l` equivalent — so it reports what the live daemon actually serves, including a cert's true remaining validity parsed from the advertised blob. It never creates the endpoint. A dial failure when the agent is enabled is surfaced as unexpected (daemon not running / not yet authenticated), not papered over with a config-derived view.

Cert mode is the documented recommendation: the private key never lands on disk, rotation is automatic, and remote hosts trust only the CA public key (`TrustedUserCAKeys`). See `docs/guide/ssh-agent.md` for the user-facing write-up (client wiring, agent-forwarding caveat, passphrase-mode guidance). When the connectivity/auth shape changes, the source factory in `factory.go` is the wiring seam. The `agent` section round-trips through the Windows registry and `reg-export`/`reg-import` (see "Windows Registry / Group Policy"). The Vault-CA signing engine internals (advanced cache/re-mint timing, non-ephemeral keys) remain a follow-up work item.

## Managed SSH Forwards

`internal/sshfwd/` (design: `docs/superpowers/specs/2026-08-09-managed-ssh-forwards-design.md`) has the daemon maintain its own SSH connection to each configured remote and remote-forward a Unix socket on that remote back to its own local API — the same shape a hand-wired `ssh -R` produces (see `token_socket`'s "Why it exists" in the config reference), minus the external process that dies with the terminal session. Out of scope by design: local forwards, per-remote SSH usernames, `known_hosts` file interop, non-`streamlocal` forward types.

Two preconditions, neither fatal to the daemon (`sshForwardDeps`, `cmd/dotvault/sshwire.go`): `agent.enabled` with a usable key source (the SSH identity comes from the same `agent.Backend` that serves the SSH agent — `identity.go` adapts `Backend.List()`/`SignWithFlags` into `[]ssh.Signer` without touching the backend's read-only contract), and a local API surface to forward to — `api.enabled` (preferred: `0600` in a `0700` dir) or `web.enabled` (fallback: reachable by every uid on the box). A remote whose preconditions aren't met, or whose config can't load, resolves to a WARN-logged skip of the whole subsystem, in the same spirit as an agent `errSource`.

**Config split by owner.** The admin-owned `ssh:` system-config section (`config.SSHConfig`) holds only trust material — `certificate_authorities` and `insecure_ignore_host_key` — consulted per connection attempt via an `atomic.Value` (`sshPolicyConfig` in `sshwire.go`) the config-refresh loop updates in place, so a changed CA list applies on the next reconnect without a restart (an already-connected forward keeps the `HostKeyPolicy` it dialled with). The remotes themselves live in a **user-level** file, `ssh.yaml` (`paths.SSHConfigPath()`, sibling of the per-user env file: `${XDG_CONFIG_HOME:-~/.config}/dotvault/ssh.yaml` on Linux, `~/Library/Application Support/dotvault/ssh.yaml` on macOS, `%APPDATA%\dotvault\ssh.yaml` on Windows) — never resolved from a system location, never in the registry, never carried by the remote-config overlay. Each entry (`host`, `port` default 22, `remote_socket` default `~/.ssh/dotvault.sock`, `host_key`, `enabled` default true) is written atomically at 0600 in a 0700 dir (`sshfwd.Save`), with unknown top-level keys preserved across a rewrite. A leading `~/` in `remote_socket` is expanded at **connect time** against the remote account's `$HOME` (probed once per connection, cached for its lifetime), not at `add` time, so the entry survives the remote home moving; `~user/` and anything neither absolute nor `~/`-prefixed are rejected at validation (`ValidateRemoteSocket`).

**Registry is the one writer.** `sshfwd.Registry` (`registry.go`) is the single service layer every mutation passes through — the CLI is a thin client of the daemon's web API and never writes `ssh.yaml` itself, because the verifying login `add` performs needs the daemon's agent identity, and a single writer removes the CLI-versus-daemon write race outright. `Add` is transactional: before persisting anything it resolves signers, dials, authenticates, verifies the host key, probes `$HOME` if needed, and requests the forward, tearing the whole dry run down afterward — this is what turns "no agent identity" / an unauthorised principal / `AllowStreamLocalForwarding no` / an unwritable remote directory into an immediate `add` failure instead of a silent `offline` row an hour later. `--force`/`Force: true` skips the dry run for a host known to be offline right now. `List` reads directly and needs no daemon-side verification; `Remove` is idempotent.

**Host-key trust (`hostkey.go`) has exactly three outcomes, never a fourth, and no runtime trust-on-first-use.** A `certificate_authorities` entry signing the host's certificate, or the `ssh.yaml` `host_key` pin matching, is accepted; anything else is rejected into the terminal `host-key-error` state. Pinning happens exactly once, during `dotvault ssh add`, an explicit human gesture — an unpinned key surfaces as `ErrHostKeyUnknown` carrying the fingerprint rather than being silently trusted, and a *changed* key is `ErrHostKeyMismatch`, a hard error never re-offered as a confirmable prompt. **A host presenting a certificate with zero configured CAs is a hard rejection, not a fall-back-to-pinning** (`checkCert`'s `len(p.CAs)==0` branch): there is nothing to validate the certificate against, and pinning its underlying key would never be consulted on a later connection anyway (a certificate never reaches the raw-key comparison branch), so treating it as "just needs confirming" would let an expired, wrong-principal, or even user certificate sail through. An empty `ValidPrincipals` on an accepted certificate is OpenSSH-standard wildcard-hostname behaviour inherited from `ssh.CertChecker` — worth remembering when sizing CA trust. `insecure_ignore_host_key` short-circuits all of this and logs a WARN naming the host on **every** connection attempt made under it, never just once.

**Connection lifecycle (`remote.go`, `manager.go`).** States: `connecting`, `connected`, `reconnecting`, `offline`, `authentication-error`, `host-key-error`, `disabled`. Backoff is exponential with jitter (500ms → 30s cap, resetting after 60s connected); `authentication-error`/`host-key-error` retry from a much higher floor since they typically need a human to clear. `Manager.Reconcile(ctx, []Remote)` diffs desired-vs-actual and is the single entry point every trigger (daemon startup, the config-refresh tick, a `Registry` mutation) goes through, so a remote's connection never has two owners.

**Forwarding (`forward.go`).** `ServeForward` binds the remote socket via `cl.ListenUnix` and relays each accepted connection to the local API dialer. Because `x/crypto/ssh` never unlinks a stale socket and `sshd` won't bind over an existing path, a bind failure alone doesn't prove the path is free — `liveListenerAt` proves nothing is actually listening there (a real `ssh -R` session's live socket is never evicted) before a single `rm -f` + one retry. `dotvault ssh remove` (or a config edit) run against a host reached only through the very forward being changed still commits, but drops the connection carrying the request mid-response as the old connection is torn down — inherent to changing a connection out from under its own in-flight request, not a bug; re-run over a different path to confirm.

**Surfaces.** `GET /api/v1/status`'s `ssh` block and `dotvault ssh list` both report live per-remote state (host, state, expanded remote socket, reconnect count, last error) — none of it written back to `ssh.yaml`. `dotvault status` itself does not render this (unlike the SSH agent section above); use `ssh list`. See "CLI" and "Web UI" for the command and route surface.

## Web UI

Preact SPA embedded via `embed.FS`. Disabled by default (`web.enabled: true` to enable). Loopback-only binding is a hard invariant — the daemon refuses to start if `web.listen` resolves to a non-loopback address.

### Server-rendered UI (`/ui/`)

A parallel, bookmarkable server-rendered surface alongside the SPA (which remains untouched at `/`). Every page is Go `html/template` (`internal/web/uitmpl/*.tmpl`, embedded) with real URLs; interactivity comes from [datastar](https://data-star.dev) (`internal/web/uiassets/datastar.js`, vendored + embedded; Go side uses `github.com/starfederation/datastar-go`) patching server-rendered fragments over SSE. The look and feel deliberately reuses the SPA's `/style.css` classes plus a small `/ui/assets/ui.css` overlay; layout differs by design — a left accordion nav (Enrolments / Remotes / Secrets, one section expanded per route) replaces the SPA's header-button navigation, and the config page keeps the nav instead of a "back to dashboard" button.

Pages: `/ui/` (dashboard: header status bar + `secret_view_text` markdown), `/ui/secrets/` (+ `/ui/secrets/<key>` detail with reveal/copy, `/ui/secrets/<folder>/` listing; trailing-slash spellings accepted), `/ui/enrolments/` (+ `/ui/enrolments/<engine>/<key>/` where the enrolment runs — the card states port `enrol-card.jsx`'s output parsing to Go in `ui_enrol.go`, and a running card polls its own fragment every 2s), `/ui/remotes/` (+ `/ui/remotes/<host>/` edit form; add/save/delete are plain form POSTs through the same `sshfwd.Registry`, including the 409-fingerprint confirm gesture; both pages subscribe to `/ui/sse/ssh`, a change-diffed SSE stream that live-patches the nav dots plus the page's own region (the table on the index, the state line on the detail page), so state changes from any writer — the page itself, another tab, the CLI via the daemon's API, or the reconnect loop — appear without a refresh), `/ui/config/` (same `buildConfigViewModel` the JSON `/api/v1/config` serves — one builder, two surfaces).

Conventions that must hold when extending it:

- **Request posture.** Page GETs redirect unauthenticated browsers to the SPA at `/` (the SPA owns every login flow). Fragment GETs 401. All `/ui/` POSTs go through `requireUIWrite`: a **present, same-origin `Origin` header is required** — this is the surface's CSRF control (browsers attach Origin to every POST; server-rendered forms and multi-tab use make the SPA's one-shot CSRF store a poor fit). Unlike the peer-action endpoints, an absent Origin is rejected: these endpoints have no curl consumer.
- **Secrets never ride in page HTML.** The detail table renders masked cells; the eye button `@get`s a reveal fragment (which re-masks itself after 30s via `data-init__delay.30s`), and the clipboard button copies **server-side** via the shared `guardedLaunch` + `clipboard.Set` path — the value never reaches the browser. The "copy token" header button works the same way.
- **CSP.** `/ui/` responses get `script-src 'self' 'unsafe-eval'` (datastar compiles attribute expressions with the Function constructor) and `style-src 'self' 'unsafe-inline'` (the `style="display: none"` anti-flicker idiom on `data-show` elements); both surfaces carry `frame-ancestors 'none'` — the Origin CSRF check cannot see framing, so clickjacking of gestures like "Trust and add" is closed off here. Inline *scripts* stay forbidden on both surfaces; do not use datastar's `ExecuteScript`/`Redirect` SSE helpers, which inject inline `<script>` tags the CSP blocks — use HTTP 303 redirects from form POSTs instead.
- **Metrics.** All `/ui/` paths collapse to the `/ui/*` route label (they embed secret keys and hostnames).
- html/template treats `data-on:*` attributes as JavaScript context and escapes interpolated URLs as JS strings (`\/`, `&`) — correct, since datastar evaluates them as JS; don't "fix" the escaping. But `data-init*` and other non-`on` datastar attributes get plain HTML-attribute escaping even though datastar evaluates them as JS too, so the only safe interpolation in ANY datastar attribute is a strictly URL-encoded value (`url.Values.Encode` output) — pinned by `TestUIFragmentURLsAreQueryEncoded`.
- The vendored browser bundle's provenance and re-vendor procedure live on the `uiAssetsFS` embed comment in `internal/web/ui.go`; the Go SDK versions independently and is dependabot-covered via `gomod`.

The same server can additionally (or instead) serve its API over a per-user Unix socket when `api.enabled` — see "Local API socket" under Authentication for the route split, the Origin consequence, and why the two surfaces are enabled independently.

### Routes

(The server-rendered `/ui/` routes are described in the subsection above; this list is the SPA + JSON API surface.)

**Auth (not CSRF-protected where noted):**
- `GET /auth/oidc/start` — redirect to Vault OIDC auth URL
- `GET /auth/oidc/callback` — handle OIDC callback
- `POST /auth/ldap/login` — start async LDAP login (CSRF-protected)
- `GET /auth/ldap/status` — poll login status
- `POST /auth/ldap/totp` — submit TOTP passcode (CSRF-protected)
- `POST /auth/token/login` — validate and set token (CSRF-protected)

**Health probes** (served on every enabled HTTP surface — the loopback web listener and/or the local API socket; a daemon with neither has nothing to probe):
- `GET /healthz` — liveness, always 200 while serving
- `GET /readyz` — readiness, 200 once the daemon holds a Vault token AND has marked the initial sync complete (mirrors the `sd_notify(READY=1)` contract). 503 otherwise. Token check reflects the cached in-memory state, not a per-probe Vault round-trip.

**API:**
- `GET /api/v1/csrf` — issue CSRF token (one-time use, max 1000 in memory)
- `GET /api/v1/status` — server status (auth, vault version, token TTL, sync state, vault address, kv_mount, user_prefix, username). Also carries `bootstrap: {active, method}` **unauthenticated**, alongside `auth_method`: the SPA needs it to choose a login form *before* any token exists, which is the whole point of a bootstrap. `active` is true only while a `BootstrapLogin` is waiting; the token itself is never exposed here or anywhere else. Note `auth_method` is the *base* method (`auth.BaseMethod` strips `+tpm`/`+os`), so all three cert variants arrive as `mtls` and the SPA dispatches on that single string
- `GET /api/v1/rules` — configured sync rules
- `GET /api/v1/config` — redacted view of the running config for the UI
- `GET /api/v1/config/download?format=yaml|reg` — full config download for the Effective Configuration screen
- `GET /api/v1/secrets/{path}` — list or reveal secret (reveal requires `?reveal=true`)
- `POST /api/v1/sync` — trigger immediate sync (CSRF-protected)
- `POST /api/v1/remote/browse` — open a form-posted `url` (body only; query string ignored) in this host's default browser (`internal/web/browse.go`). The outbound counterpart of `GET /api/v1/token` over the same forwarded socket: a headless peer (or `dotvault browse`) hands a URL back to the workstation so browser-driven flows open where a browser exists. **Deliberately NOT CSRF-protected** — the consumer is a bare curl/form POST over a forwarded Unix socket with no practical way to run the issue-then-spend CSRF handshake, and the handler reads no state and returns nothing sensitive. Cross-site browser traffic (which the loopback Host check alone would pass, since a cross-origin form POST is a CORS "simple request") is rejected by an **Origin check** instead: a present `Origin` header must name the daemon's own origin — a loopback hostname (`originAllowed` → `loopbackHostname`, the same allowlist as the Host check) **on the daemon's own listener port** (bound `listenAddr` preferred, `cfg.Listen` pre-Start), because an Origin names whichever server served the page and a hostname-only check would admit pages from any other loopback-served origin; curl and the CLI send none and pass, hostile pages always send theirs (or `null`) and are 403'd. The other load-bearing control is the strict allowlist (`ValidateBrowseURL`: http/https with a host, no embedded `user:pass@` credentials), which keeps `file://` and custom-protocol strings away from xdg-open/ShellExecute. The opener runs under a bounded wait (`browseOpenTimeout`, 8s < the CLI's 10s POST timeout) so a hung launcher can't strand the handler, and behind a single-flight gate (`browseOpenMu.TryLock`, concurrent requests get 503) because an abandoned hung launcher can't be killed and unbounded requests would pile up stuck goroutines. Log lines carry scheme+hostname only, at every level — query strings and even path segments can be capability-bearing, and the requester already knows the URL it posted. Browser launch is injected via `ServerConfig.OpenBrowser` (defaults to `browser.OpenURL`; tests fake it); the middleware's loopback Host check applies as on every route.
- `POST /api/v1/remote/notify` — raise a native desktop notification from a form-posted `level`/`title`/`body`/`action_url` (`internal/web/notify.go`). Optional `action_url` (http/https, same allowlist as browse) makes the notification open the URL on click (Windows) or appends it to the body (macOS/Linux). The sibling of `remote/browse` with the identical no-CSRF / Origin-check / bounded-single-flight posture (both share `guardedLaunch` in `internal/web/launcher.go`). Input validation is `notify.NewMessage` (known level set; title/body sanitized — control chars stripped and Windows-toast-backend metacharacters neutralized: the XML CDATA terminator and the PowerShell here-string `$`/backtick that the fallback would otherwise evaluate as a subexpression → RCE; macOS `%q` and Linux D-Bus argv need no such handling). Delivery is injected via `ServerConfig.SendNotification` (defaults to `notify.Send`; tests fake it). Log lines carry the level and title/body *lengths* only — never the text, which is arbitrary user content that may name secret paths (the same never-log-content posture browse applies to URLs).
- `POST /api/v1/remote/clipboard` — put a form-posted `text` value on this host's clipboard (`internal/web/clipboard.go`). The third peer action, same no-CSRF / Origin-check / bounded-single-flight posture as browse and notify. Input validation is `clipboard.ValidateText` — deliberately a validator, not a sanitizer: clipboard content is data, never interpolated into an evaluated context, and the typical payload is a credential that must arrive byte-for-byte intact, so only content no clipboard can carry (interior NUL, invalid UTF-8) or that signals a caller bug (empty, >64 KiB) is rejected and the text is otherwise written verbatim. The payload is the most secret-bearing of the three peer actions, so the never-log-content posture is strict: log lines carry the text's *length* only, and writer errors are scrubbed of the exact text before logging *and* before being returned in the 502 body (unlike browse, which returns its opener error unredacted) — a best-effort exact-substring scrub layered on writers that never embed their input in errors, not the primary control. Delivery is injected via `ServerConfig.SetClipboard` (defaults to `clipboard.Set`; tests fake it).
- `GET /api/v1/ssh/remotes` / `POST /api/v1/ssh/remotes` / `PATCH /api/v1/ssh/remotes/{host}` / `DELETE /api/v1/ssh/remotes/{host}` — CRUD over the daemon's managed SSH forwards (`internal/web/ssh.go`; see "Managed SSH forwards" below). Unlike the three peer-action routes above, these are **ordinary CSRF-protected mutations**: the Origin-check exemption those use exists because a bare curl over a forwarded socket can't run the issue-then-spend CSRF handshake, and both consumers here (the SPA and `dotvault ssh`) can. `POST` performs a live verifying SSH login before persisting; an unpinned host key returns `409` with `{host, fingerprint}`, and the caller must re-`POST` echoing `accept_fingerprint` to commit — the same confirmation gesture the CLI's `--accept-host-key` prompt uses, so a browser session can't degrade the trust decision into blind trust-on-first-use. `PATCH`/`DELETE` validate the unescaped `{host}` path parameter with `sshfwd.ValidateHost` before it reaches the registry (the mux hands wildcards unescaped, so `foo%2Fbar`/`foo%00bar` would otherwise arrive as raw `/`/NUL bytes). All four are thin handlers over `sshfwd.Registry`, so validation, the trust gesture, and the write path are shared with the CLI by construction. `GET /api/v1/status` additionally carries an `ssh` block (per-remote state, reconnect count, last error) fed by the same registry's live status query.

**Security headers:** `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`. The `/ui/` surface gets the relaxed CSP variant described under "Server-rendered UI" above.

**DNS-rebinding defence:** the middleware rejects any request whose `Host` header is not a loopback alias (`127.0.0.1`, `::1`, `localhost`) or the configured `web.listen` hostname. Loopback binding alone doesn't stop a hostile origin from resolving its own DNS name to `127.0.0.1` and using a victim's browser as a relay; the Host check ensures the daemon refuses such requests before any handler runs.

Configurable markdown content via `web.login_text` and `web.secret_view_text` fields rendered by `internal/web/markdown.go`.

## Windows Registry / Group Policy

When HKLM registry keys exist at `SOFTWARE\Policies\goodtune\dotvault`, the daemon loads all config from registry and ignores the YAML file. The `registryLayer` struct reads Vault, Sync, Web (`Enabled`, `Listen`, `LoginText`, `SecretViewText`), Observability (`Enabled`, `Endpoint`, `Protocol`, `Insecure`, `ExportInterval`), Agent (scalar transport: `Enabled`, `UnixPath`, `WindowsPipe`, and the tri-state `WindowsPutty` REG_DWORD — absent leaves the `*bool` nil so the default-true applies), and API (`Enabled`, `UnixPath`) settings from typed subkeys (REG_SZ, REG_DWORD). Rules are subkeys under `Rules\{RuleName}` with an optional `OAuth` subkey. Enrolments are subkeys under `Enrolments\{Name}` with an optional `Settings` subkey. Wiring up the Observability subkey matters beyond config fidelity: without it a GPO-managed daemon would have `Observability.Enabled=false`, `observability.Init` would short-circuit, and `LogRegistryConfigManaged`'s WARN record would vanish into the no-op global logger.

**Coverage is total: every YAML field has a registry equivalent and round-trips losslessly through `reg-import`/`reg-export` and the live loader — including `observability.headers`.** Header values carry OTLP bearer tokens, but conversion is lossless in every direction with no stripping: the regfile renderer emits each header as a REG_SZ value under `Observability\Headers` (header-name case preserved verbatim, unlike the lowercased enrolment `Settings` names), deleting the subtree before re-creation so a removed header clears on re-import — the same idempotency pattern as Rules / Enrolments / `Agent\Keys`. The live loader (`readRegistryObservabilityHeaders`) and the `.reg` parser read those values back. The recommended way to keep tokens out of a checked-in config remains leaving `headers` empty and using `OTEL_EXPORTER_OTLP_HEADERS` in the per-user `EnvironmentFile`. When adding a new config field, extend all three surfaces in lockstep — `internal/config/registry_windows.go` (live loader), `internal/regfile/regfile.go` (render), and `internal/regfile/parse.go` (parse) — and add a round-trip test; the `internal/regfile` tests are platform-neutral and run everywhere, while the `registry_windows*` loader tests are `//go:build windows`.

The `agent.keys[]` list is **ordered**, unlike the name-keyed rules/enrolments maps. It is stored under `Agent\Keys\{N}` where `{N}` is the zero-based list index (`Agent\Keys\0`, `\1`, …); both the live registry loader (`readRegistryAgentKeys`) and the regfile parser sort those subkey names numerically to rebuild the slice in order, and reject a non-integer subkey name as a hard error rather than silently reordering or dropping a key. `Principals` round-trips as a REG_MULTI_SZ (like OAuth `Scopes`); an explicit empty list is preserved as a non-nil empty slice.

This means a Windows GPO deployment can configure rules, enrolments, the SSH agent, and the observability exporter end-to-end, and `reg-export` / `reg-import` (plus the web `GET /api/v1/config/download`) round-trip every section through both the YAML and `.reg` forms. dotvault does **not** ship an ADMX administrative template and there is no plan to — it was never adequately tested and has been removed entirely. Admins author the registry values directly (e.g. via `reg-import` from a YAML config); the registry surface is the supported Group Policy integration.

## File Permissions & Security

- Managed files (all sync rule targets): written at 0600
- Token file (`~/.dotvault-token`): written at 0600, warns if permissions differ
- Config file: warns if group or world writable
- Secret values are never logged, even at DEBUG level
- All file writes are atomic (temp file + rename)
- Local API socket (`api.enabled`): created 0600 inside a 0700 directory via `internal/uds`, refusing to clobber a socket a live instance owns
- Web UI: loopback only, CSRF on all mutating endpoints (documented exceptions: the peer-action endpoints `POST /api/v1/remote/browse`, `POST /api/v1/remote/notify`, and `POST /api/v1/remote/clipboard`, which use an Origin check instead — see Web UI routes for the rationale), strict CSP
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
| `github.com/gen2brain/beeep` | Cross-platform desktop notifications (pure Go, no cgo) |
| `git.sr.ht/~jackmordaunt/go-toast` | Windows clickable toast (protocol activation) for notify `--action-url`; Windows-only path |
| `nhooyr.io/websocket` | WebSocket client (Vault Events API) |
| `github.com/Microsoft/go-winio` | Windows named-pipe listener (SSH agent transport) |
| `github.com/coreos/go-systemd/v22` | systemd sd_listen_fds (socket activation; linux-tagged import) + sd_notify (READY/STOPPING/WATCHDOG; imported everywhere, inert outside systemd) |
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
