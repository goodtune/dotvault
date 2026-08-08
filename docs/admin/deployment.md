# Deployment Guide

This guide covers how system administrators deploy and configure dotvault across an organisation.

## Architecture overview

dotvault runs as a **per-user daemon**. Each user has their own instance, their own Vault identity, and their own secrets. The administrator's role is to:

1. Set up the Vault infrastructure (KV engine, auth methods, policies)
2. Deploy the dotvault binary to machines
3. Distribute a configuration file (or Group Policy on Windows)
4. Arrange for dotvault to start in each user's session

## Vault infrastructure

### KV engine

Enable KVv2 and create the user prefix namespace:

```sh
vault secrets enable -version=2 -path=kv kv
```

### Policies

Create a template policy that scopes each user to their own secrets. See [KV Engine & Policies](../vault/policies.md) for the full policy file.

### Auth method

Enable and configure at least one auth method. [OIDC](../authentication/oidc.md) is recommended for desktop environments as it integrates with existing SSO.

## Configuration distribution

### Linux

Place the config file at the system-wide location:

```
/etc/xdg/dotvault/config.yaml
```

dotvault also checks paths listed in `$XDG_CONFIG_DIRS`.

Deploy with your existing configuration management (Ansible, Puppet, NixOS, etc.):

=== "Ansible"

    ```yaml
    - name: Deploy dotvault config
      copy:
        src: dotvault/config.yaml
        dest: /etc/xdg/dotvault/config.yaml
        owner: root
        group: root
        mode: "0644"
    ```

=== "NixOS"

    ```nix
    environment.etc."xdg/dotvault/config.yaml".text = ''
      vault:
        address: "https://vault.example.com:8200"
        auth_method: "oidc"
      rules:
        - name: gh
          vault_key: "gh"
          target:
            path: "~/.config/gh/hosts.yml"
            format: yaml
            template: |
              github.com:
                oauth_token: "{{ "{{" }} .oauth_token {{ "}}" }}"
    '';
    ```

### macOS

Place the config file at:

```
/Library/Application Support/dotvault/config.yaml
```

Deploy via MDM (Jamf, Munki) or configuration management.

### Windows

Place the config file at:

```
%ProgramData%\dotvault\config.yaml
```

Or use [Group Policy](windows-gpo.md) to manage configuration centrally via the registry.

!!! warning "Registry takes precedence"
    On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\goodtune\dotvault`, dotvault loads all configuration from the registry and **ignores the YAML file entirely**. The `--config` CLI flag is **refused** while a policy is present unless that policy opts in with a `BypassSystemConfig` REG_DWORD of `1` (the `bypass_system_config: true` equivalent); see [Windows Group Policy](windows-gpo.md).

## Running as a user service

### systemd (Linux)

!!! warning "Upgrading from a manually-created unit"
    Previous versions of this guide showed an example `~/.config/systemd/user/dotvault.service` snippet. If you created one, **remove it** before enabling the packaged unit — the per-user path shadows `/usr/lib/systemd/user/` and your hand-rolled unit (which lacks `Type=notify`, `WatchdogSec`, the env-file paths, etc.) will silently take precedence:

    ```sh
    rm ~/.config/systemd/user/dotvault.service
    systemctl --user daemon-reload
    systemctl --user enable --now dotvault.service
    ```

    Behavioural change to be aware of: services declaring `After=dotvault.service` now block until dotvault completes its initial sync (the packaged unit uses `Type=notify` and delays `READY=1` until secrets are on disk). The previous hand-rolled unit had no readiness gate, so dependents started in parallel. If a dependent's startup ordering matters to you, this is the change to plan for.

The RPM, DEB, and APK packages all ship a `dotvault.service` **user unit** (a `Type=notify` service with `WatchdogSec=120` and the OpenTelemetry-friendly logging settings) at the canonical `/usr/lib/systemd/user/` path. dotvault is a per-user daemon — it authenticates to Vault with the OS user's identity and writes secrets into that user's `$HOME` — so installing it as a system service that runs as root would write to root's `$HOME` and authenticate to Vault as root, which is almost never what you want.

Enable per-user once the package is installed:

```sh
systemctl --user enable --now dotvault.service
```

The daemon watches `~/.dotvault-token` itself (via inotify on Linux), so subsequent rewrites of the file (typically from an interactive `dotvault login` in another shell) trigger an immediate token re-read on the running daemon within seconds — no extra unit to enable. See [Config reload](#config-reload) for the full mechanism.

Or enable globally for every login session on the machine:

```sh
sudo systemctl --global enable dotvault.service
```

`--global` enables the unit in every user's session; each user runs their own instance and authenticates with their own Vault identity.

#### Socket activation (optional)

The packages also ship two **socket units**, installed but not enabled: `dotvault-api.socket` (the [local API socket](../configuration/config-reference.md#api-section)) and `dotvault-agent.socket` (the [SSH agent](../guide/ssh-agent.md) socket). Without them the daemon binds its sockets itself, and each socket disappears whenever the daemon does — `systemctl --user restart dotvault.service` is a brief outage for anything borrowing a token or requesting a signature at that moment. With a socket unit enabled, **systemd binds the socket and holds the listening fd across daemon restarts**, so clients queue in the backlog and are served when the daemon returns; the socket also exists from `sockets.target` at session start, before the daemon has authenticated.

```sh
systemctl --user enable --now dotvault-api.socket
systemctl --user enable --now dotvault-agent.socket   # optional, independent
```

Things to know:

- **The config is still the master switch.** `api.enabled` / `agent.enabled` decide whether the surface exists; the socket unit only decides who binds it. If systemd passes a socket the daemon is not configured to serve, the daemon *drains* it — connections are accepted and closed immediately, so clients fail fast with EOF — and logs a warning naming the mismatch. (Merely closing the daemon's copy would refuse nobody: systemd retains its own listening fd, so clients would hang in a backlog no one accepts.) Enabling the socket unit is not a substitute for enabling the feature.
- **This is fd-passing, not start-on-demand.** The service stays `WantedBy=default.target` and runs regardless of connections — it is syncing files and keeping a token alive. Enable both the `.socket` and the `.service`; enabling only one is a half-configured state.
- **Owner-only is verified, not assumed.** The units set `SocketMode=0600`, and the daemon independently checks the inherited socket's filesystem mode and **refuses** anything wider — `SocketMode` defaults to `0666`, so a hand-edited unit that drops the line fails loudly instead of silently exposing the token endpoint to every uid on the box.
- **The socket unit's path wins.** Under activation the socket lives wherever `ListenStream=` says; if that differs from `api.unix.path` / `agent.unix.path`, the daemon logs the divergence and reports the activated path in `dotvault status`.
- **Owner-only covers the directory too.** Alongside the socket-node mode, the daemon verifies the parent directory is owner-only and owned by the same user (`DirectoryMode=0700` in the units) — a socket in a directory someone else can write to can be swapped for an impostor, which no node check catches.
- Requires systemd ≥ 227 (`FileDescriptorName=` support). On older systemd the fds arrive unnamed, and the daemon drains them with a warning rather than serving them.
- Not applicable on macOS (launchd has its own, incompatible mechanism) or Alpine/OpenRC; on those the daemon's self-bind path runs unchanged.

!!! tip "Enable lingering if the daemon must outlive a login session"
    A `--user` service normally stops when the user's last session ends, and `$XDG_RUNTIME_DIR` (where the SSH agent and [local API socket](../configuration/config-reference.md#api-section) live) is torn down with it. For a machine people reach over SSH — where a `tmux` job or the local API socket is expected to survive a disconnect — enable lingering so the user manager keeps running:

    ```sh
    sudo loginctl enable-linger <user>
    ```

Environment-variable overrides (e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`) can be set via four optional `EnvironmentFile=` paths referenced by the unit:

- `~/.config/dotvault/env` (preferred for per-user secrets)
- `~/.config/dotvault.env`
- `/etc/default/dotvault`
- `/etc/sysconfig/dotvault`

The system-wide paths are typically world-readable, so the per-user `~/.config/dotvault/env` is the right place for anything sensitive (e.g. an OTLP bearer token in `OTEL_EXPORTER_OTLP_HEADERS`). Create the file with `chmod 600`; all four are silently ignored if absent.

!!! note "`%h` vs `~` in custom unit drop-ins"
    The packaged unit references the per-user paths as `%h/.config/dotvault/env` and `%h/.config/dotvault.env`. `%h` is systemd's home-directory specifier — equivalent to `~` when you're creating the file at the shell. If you reference the file from a `systemctl --user edit` drop-in or a custom unit, write `%h` (or `${HOME}`); systemd does **not** expand `~` in `EnvironmentFile=` directives, so a literal `~/.config/...` would be silently skipped.

The unit hard-codes a couple of system paths that the package owns: `ExecStart=/usr/bin/dotvault run`, plus the `EnvironmentFile=` paths listed above. If you install dotvault into a non-standard location (e.g. `/usr/local/bin`), copy the unit out to `~/.config/systemd/user/dotvault.service` and adjust those lines.

!!! warning "Slow initial sync and the systemd startup window"
    With `Type=notify`, two different deadlines govern dotvault's lifecycle:

    - **`TimeoutStartSec`** — the pre-`READY=1` window. systemd waits this long for the daemon to finish auth + initial sync and signal ready. The packaged unit sets it to **300 seconds**; the systemd default of ~90s is too tight for resource-constrained hosts (many rules, slow Vault, cold TLS handshake). If the daemon doesn't reach `READY=1` in time, systemd marks the start a failure and restarts — causing a boot loop on chronically slow hosts.
    - **`WatchdogSec`** — the post-`READY=1` liveness check. The daemon kicks the watchdog at half this interval after becoming ready; if the kicks stop, systemd restarts the unit. The packaged unit sets it to **120 seconds**.

    `WatchdogSec` does **not** extend the startup window — only `TimeoutStartSec` does. To raise the startup window (or the watchdog) on a host where the defaults are too tight, use a drop-in:

    ```sh
    systemctl --user edit dotvault.service
    # Under [Service], one or both of:
    #   TimeoutStartSec=600
    #   WatchdogSec=300
    ```

    `TimeoutStartSec=infinity` disables the pre-ready timeout entirely if your environment can't bound the first sync.

    Note also that anything declaring `After=dotvault.service` now blocks until the first sync completes — a behavioural change from the previous manually-created unit which had no `Type=notify` gate.

### launchd (macOS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.goodtune.dotvault</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/dotvault</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/dotvault.err</string>
</dict>
</plist>
```

Deploy to `/Library/LaunchAgents/` (all users) or `~/Library/LaunchAgents/` (single user).

### Windows Task Scheduler

Create a scheduled task that runs at user logon:

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Program Files\dotvault\dotvault.exe" -Argument "run"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "dotvault" -Action $action -Trigger $trigger -Settings $settings
```

Or deploy via Group Policy as a scheduled task.

## Logging

dotvault writes all logs to stderr:

- **Text format** when stderr is a TTY (interactive use)
- **JSON format** otherwise (service/daemon use)

Control verbosity with `--log-level`:

```sh
dotvault run --log-level debug
```

Available levels: `debug`, `info` (default), `warn`, `error`.

Override the auto-selected format with `--log-format`:

```sh
dotvault run --log-format json   # force structured logs
dotvault run --log-format text   # force human-readable logs
dotvault run --log-format auto   # default — text on TTY, JSON otherwise
```

This is useful when running under a service manager that captures stderr but is connected to a TTY for debugging, or when forcing structured logs for ingestion into a log collector regardless of how the daemon was launched.

dotvault itself never writes a log file — integrate with your platform's log collection (journald, syslog, Windows Event Log via a wrapper, etc.), or use the OTel mirror described next. On systemd hosts the packaged unit routes stderr to the journal, so the OpenTelemetry collector's `journaldreceiver` can filter on `_SYSTEMD_USER_UNIT=dotvault.service` (or `_SYSTEMD_UNIT` when the unit was enabled with `systemctl --global`) to pick logs up directly.

Separately, every log record is also mirrored to the OTel LoggerProvider alongside stderr (see [Observability](#observability) below) — this is additive, not a replacement: stderr/journald keeps working exactly as before, so a collector outage or `observability.enabled: false` never loses the local copy. When observability is enabled, the mirrored records flow to your collector as OTLP log records, which lets the collector fan them out to a `file` exporter, a syslog/journald forwarder, or — via a collector build that includes a Windows Event Log exporter (not a stock component of the core OTel Collector distribution, so this typically means a custom/contrib collector build) — the Event Log. dotvault ships none of that collector-side configuration; the fan-out target is entirely operator-authored.

**Security note:** because every record now leaves the process once a collector endpoint is configured, treat `observability.endpoint`/`insecure`/`headers` as part of the logging trust boundary, not just the metrics one — a call site that logs something sensitive is no longer contained to local stderr/journald.

## Observability

dotvault can export OpenTelemetry **metrics and logs** to an OTel collector. Each signal is configured in its own nested block — `metrics:` and `logs:` — so the two can go to **separate backends** or one can be switched off independently. Disabled by default; enable with:

```yaml
observability:
  enabled: true                  # master switch for both signals
  export_interval: "15s"         # metric export cadence
  metrics:
    endpoint: "127.0.0.1:4317"
    protocol: "grpc"             # or "http/protobuf"
    insecure: true               # disable TLS for the local hop
  logs:
    endpoint: "https://logs.vendor.example"
    protocol: "http/protobuf"
    headers:
      X-Api-Key: "logs-backend-key"
```

The top-level `endpoint` / `protocol` / `insecure` / `headers` fields still work as shared defaults that the per-signal blocks layer onto — the model deliberately mirrors the OTel SDK's own env-var convention (generic `OTEL_EXPORTER_OTLP_*` plus signal-specific `OTEL_EXPORTER_OTLP_METRICS_*` / `_LOGS_*`) — but they are **deprecated** and being retired in stages:

!!! warning "Shared exporter fields are deprecated"
    Setting `observability.endpoint`, `protocol`, `insecure`, or `headers` at the top level (with observability enabled) logs a startup WARN naming the fields and increments the `dotvault.config.deprecated` counter once per field per process start, so a fleet's collector can measure migration progress. Everything keeps working for now; a later release makes the warning louder and 1.0 removes the shared fields. Move the settings into the per-signal `metrics:` / `logs:` blocks — or, for values shared across both signals (a common bearer token, a common collector), use the standard `OTEL_EXPORTER_OTLP_*` environment variables, which remain fully supported. Tracked in [#140](https://github.com/goodtune/dotvault/issues/140).

Field semantics: `enabled` (unset = on whenever `observability.enabled` is; explicit `false` switches that signal off — the top-level flag remains the master switch and a per-signal `true` cannot resurrect a disabled subsystem), `endpoint` / `protocol` (non-empty overrides), `insecure` (set overrides), and `headers`, which **replace the shared map wholesale** rather than merging — merging credential maps invites sending one backend's bearer token to the other. An explicitly empty `headers: {}` therefore means "this signal sends no headers" even when the shared map is populated. Watch the inverse case, too: a signal that overrides `endpoint` but leaves `headers` unset inherits the shared map — shared bearer token included — and sends it to the new backend. The daemon warns at startup when it sees that combination; set an explicit per-signal `headers:` (`{}` for none) to state the intent and silence it. Enabling `observability.enabled` with both signals explicitly off is rejected at config load as the contradiction it is.

For `http/protobuf`, set `endpoint` to a *base* URL like `https://otel.example` — the SDK appends `/v1/metrics` and `/v1/logs` itself. A URL that already includes a signal-specific path (e.g. ending in `/v1/metrics`) routes that signal to the wrong route.

Disabling the `logs` signal leaves the global LoggerProvider on the OTel no-op implementation, so the `Log*` helpers emit nothing for that daemon — `metrics.enabled` alone gives you series without shipping any log records.

!!! note "Windows Group Policy"
    The `observability` block round-trips through the GPO/registry layer like every other section — author it under `SOFTWARE\Policies\goodtune\dotvault\Observability` (or generate the values with `dotvault reg-import`), with the per-signal overrides as `Observability\Metrics` / `Observability\Logs` subkeys (tri-state `Enabled`/`Insecure` DWORDs, and their own `Headers` subkeys — a present-but-empty per-signal `Headers` key means "no headers for this signal", distinct from an absent key meaning inherit). Header values round-trip too (as REG_SZ values under the respective `Headers` keys), so a `.reg` export carries the live tokens — treat the artefact as a secret. To keep tokens out of the policy hive and out of any exported config, leave `headers` empty and set them via the standard `OTEL_EXPORTER_OTLP_HEADERS` environment variable (through a machine-wide environment policy) instead. See [Windows Group Policy](windows-gpo.md#registry-schema) for the full registry schema.

The standard `OTEL_*` environment variables (generic `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS`, and the signal-specific `_METRICS_*` / `_LOGS_*` variants) are honoured by the SDK whenever the corresponding config field is empty, so endpoint and header configuration can live entirely outside the config file. Put credential-bearing values (`OTEL_EXPORTER_OTLP_HEADERS`) in the per-user `EnvironmentFile` (`~/.config/dotvault/env`, mode 0600) rather than a world-readable location — this is the recommended way to share a token across both signals without it appearing in any config artefact, and it is where the shared-field deprecation steers that use case.

The exporter emits a bounded set of instruments:

| Metric                          | Type      | Attributes                                           |
| ------------------------------- | --------- | ---------------------------------------------------- |
| `dotvault.sync.ticks`           | counter   | `outcome={ok,error}`                                 |
| `dotvault.sync.duration`        | histogram | `outcome`                                            |
| `dotvault.vault.calls`          | counter   | `op={read,write,lookup_self,renew_self}`, `status`   |
| `dotvault.token.renewals`       | counter   | `outcome={renewed,reauth_required,failed}`           |
| `dotvault.token.ttl_remaining`  | histogram | (no attrs)                                           |
| `dotvault.enrol.attempts`       | counter   | `engine`, `outcome={completed,error}`                |
| `dotvault.web.requests`         | counter   | `route`, `status_class={1xx…5xx}`                    |
| `dotvault.config.reloads`       | counter   | `outcome={no_change,applied,error}`                  |
| `dotvault.sighup.received`      | counter   | (no attrs) — each SIGHUP forces an immediate `~/.dotvault-token` re-read and config reload |
| `dotvault.config.deprecated`    | counter   | `field` — deprecated config fields in active use, one increment per field per process start; sum by `field` to measure fleet migration progress |
| `dotvault.build_info`           | gauge     | `version`, `go_version`, `os`, `arch` — constant `1`, one series per build, following the Prometheus `*_build_info` convention. `version` is the v-stripped release semver on tagged builds and `dev` on untagged/hand-rolled ones (same value as `dotvault version`), so a `dev` series in a fleet view means an unofficial build, not missing data. Join other series against it to slice by build — e.g. `dotvault.config.deprecated` joined by `version` shows whether deprecated-config stragglers are just old builds. The same identity also rides every series as OTel resource attributes (`service.version`, `os.type`, `host.arch`, `process.runtime.*`) for backends that surface `target_info` |

### Log records

`log/slog` to stderr / journald is still the primary logging path, but every record handled through it is also mirrored to the OTel LoggerProvider — the mirror is additive, not a replacement, so a collector outage or `observability.enabled: false` never loses the stderr/journald copy. This is what lets a collector fan dotvault's operational log stream (not just deployment-fact records) out to a `file` exporter, a syslog/journald forwarder, or the Windows Event Log — see [Logging](#logging) above.

One record is emitted directly through the OTel logger rather than via the slog mirror, because it must reach a central collector without ever printing to an end user's terminal:

- **`configuration loaded from Windows Registry (Group Policy); file-based config is ignored`** — WARN severity, attribute `path=<would-be config file>`. Fires once per daemon/sync startup on a GPO-managed Windows box. Routing this through slog would print an INFO line on every CLI invocation on a GPO-managed install, which is exactly the noise this record avoids.

Health probes are served on **whichever HTTP surfaces the daemon has**: the loopback listener when `web.enabled: true`, and/or the per-user Unix socket when [`api.enabled: true`](../configuration/config-reference.md#api-section). A deployment with neither enabled has nothing to probe; enable one of them, or rely on the systemd `sd_notify(READY=1)` signal instead. The OTel `httpcheckreceiver` speaks TCP, so it needs `web.enabled`; a socket-only daemon is probed with `curl --unix-socket <path> http://localhost/readyz`, which is the way to get a readiness check without opening a port at all.

- `GET /healthz` — liveness, always 200 while serving
- `GET /readyz` — readiness, 200 once the daemon is authenticated to Vault AND has completed its initial sync cycle, 503 otherwise. Mirrors the `sd_notify(READY=1)` contract so a Kubernetes `readinessProbe` or the OTel `httpcheckreceiver` never observes a green daemon before secrets exist on disk. The auth check reflects the cached in-memory token, not a per-probe Vault round-trip; a revoked token flips `/readyz` back to 503 within the lifecycle check cadence (default 5 min).

Both return JSON and are loopback-only, suitable for the OTel `httpcheckreceiver`.

## Security considerations

- **File permissions** — all managed files are written with `0600`. dotvault warns if the config file is group or world writable.
- **Token security** — `~/.dotvault-token` is written with `0600`. Secret values are never logged, even at debug level. dotvault uses this dotvault-specific filename rather than Vault's default `~/.vault-token` so a concurrent `vault` CLI session cannot clobber the daemon's cached token.

<!-- TRANSITIONAL: added in v0.20.0 for the ~/.vault-token -> ~/.dotvault-token move. Remove this admonition around v0.23.0 (≈3 minor releases) once upgrading installs are unlikely. -->
!!! note "Transitional — upgrading from v0.19.0 or earlier"
    Releases before v0.20.0 used Vault's default `~/.vault-token`. There is no migration: dotvault re-authenticates once on first start, and any token it previously wrote to `~/.vault-token` lingers at `0600` until it expires. If dotvault was the only writer of that file, delete it after upgrading. This note will be removed in a future release (around v0.23.0).
- **Atomic writes** — all file writes use temp file + rename to prevent partial writes.
- **Web UI** — loopback only, CSRF-protected, strict Content Security Policy.
- **Windows** — DACL-based permission checks via the Windows Security API.

## Config reload

SIGHUP is the running daemon's reload trigger. It does two things at once: re-reads `~/.dotvault-token` immediately (picking up a token freshly written by `dotvault login`), and re-runs the configuration loader immediately instead of waiting for the next config-refresh tick.

What a reload can and cannot apply:

- **Applied in place** — the *dynamic* sections: `rules`, `enrolments`, `sync.interval`, and `remote_config` itself (the overlay fetcher is rebuilt and the refresh cadence re-derived on the next pass; note that a *remote* document still cannot carry `remote_config` — the section is local-only). These are the same sections the daemon already re-reads periodically on its config-refresh tick (default: the sync interval; see `remote_config.refresh_interval`), whether the change came from an edited local config or the remote overlay. The signal just skips the wait.
- **Restart required** — the *static* sections: `vault`, `web`, `api`, `agent`, `observability`, and the top-level `bypass_system_config` flag. These configure subsystems constructed once at startup (the Vault client, the web listener, the local API socket, the SSH agent, the OTel exporter). A reload that finds them changed logs a warning naming the changed sections; restart the daemon (`systemctl --user restart dotvault.service`) to apply them.

The packaged systemd unit wires SIGHUP as `ExecReload=`, so the canonical gesture on Linux is:

```sh
systemctl --user reload dotvault.service
```

This targets the unit's MainPID specifically — preferable to `kill -HUP $(pgrep -x dotvault)`, which would also signal any unrelated `dotvault sync` or `go run ./cmd/dotvault` invocation the user happens to be running (SIGHUP's default disposition is to *terminate*, so those side processes would die). On macOS the equivalent targeted form is `launchctl kill SIGHUP gui/$(id -u)/com.goodtune.dotvault`.

On **Windows**, SIGHUP is never delivered to processes. The system-tray icon (installed by both `dotvault.exe run` and `dotvaultw.exe`) carries a **Reload config** menu entry that performs exactly the same token re-read + immediate config reload; static-section changes log the same restart-required warning. Alternatively, changes to the dynamic sections still converge on the next config-refresh tick with no action at all.

!!! note "Token re-read is automatic on Linux"
    On Linux the daemon also watches `~/.dotvault-token` directly with inotify and re-reads it the moment the file is created or replaced — so when an interactive `dotvault login` writes a fresh token, the running daemon picks it up within seconds without any signal. This is built into the daemon (`internal/tokenwatch`); there is no separate unit to enable, and it works regardless of how dotvault was started. Deletes are ignored — the daemon keeps using its current in-memory token until a replacement is written. The watcher is a no-op off Linux; operators who want automatic re-read on macOS should script the `launchctl kill` form above on a launchd `WatchPaths` trigger.

    Earlier releases shipped a `dotvault-token-watch.path` user unit that achieved the same nudge by SIGHUP-ing the daemon. It has been removed; the package upgrade deletes the unit files, but an enabled symlink left in `~/.config/systemd/user/` by a previous `systemctl --user enable` will persist and keep firing a (now redundant, but harmless) SIGHUP. After upgrading, clear it with `systemctl --user disable --now dotvault-token-watch.path`.
