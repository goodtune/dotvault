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
    On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\goodtune\dotvault`, dotvault loads all configuration from the registry and **ignores the YAML file entirely**. The only way to bypass this is the `--config` CLI flag, which always takes precedence.

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

This pulls in the bundled `dotvault-token-watch.path` user unit too — via the service unit's `[Install] Also=` directive — so subsequent rewrites of `~/.vault-token` (typically from an interactive `dotvault login` in another shell) trigger a SIGHUP-driven token re-read on the running daemon within seconds. See [Config reload](#config-reload) for the full mechanism.

Or enable globally for every login session on the machine:

```sh
sudo systemctl --global enable dotvault.service
```

`--global` enables the unit in every user's session; each user runs their own instance and authenticates with their own Vault identity.

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

There is no file-based logging — integrate with your platform's log collection (journald, syslog, Windows Event Log via a wrapper, etc.). On systemd hosts the packaged unit routes stderr to the journal, so the OpenTelemetry collector's `journaldreceiver` can filter on `_SYSTEMD_USER_UNIT=dotvault.service` (or `_SYSTEMD_UNIT` when the unit was enabled with `systemctl --global`) to pick logs up directly.

## Observability

dotvault can export OpenTelemetry metrics to a local OTel collector. Disabled by default; enable by adding an `observability:` block to `config.yaml`:

```yaml
observability:
  enabled: true
  endpoint: "127.0.0.1:4317"  # local OTel collector
  protocol: "grpc"            # or "http/protobuf"
  insecure: true              # disable TLS for the local hop
  export_interval: "15s"
  # headers:
  #   authorization: "Bearer …"
```

!!! note "Windows Group Policy"
    The `observability` block is configured via the YAML config file only — the GPO/registry layer (and the ADMX template) does not yet expose it. On a GPO-managed Windows install, point the collector via the standard `OTEL_*` environment variables (set through a machine-wide environment policy) until the registry surface is extended.

The standard `OTEL_*` environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, …) are also honoured by the SDK, so the `endpoint`/`headers` fields can be left empty and managed centrally via `/etc/default/dotvault`.

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
| `dotvault.sighup.received`      | counter   | (no attrs) — each SIGHUP forces an immediate `~/.vault-token` re-read |

Health probes are served on the same loopback listener as the web UI and are therefore **only available when `web.enabled: true`**. A deployment with the OTel metrics block enabled but the web UI disabled has nothing to probe; point the `httpcheckreceiver` only at hosts where `web` is also enabled, or rely on the systemd `sd_notify(READY=1)` signal instead.

- `GET /healthz` — liveness, always 200 while serving
- `GET /readyz` — readiness, 200 once the daemon is authenticated to Vault AND has completed its initial sync cycle, 503 otherwise. Mirrors the `sd_notify(READY=1)` contract so a Kubernetes `readinessProbe` or the OTel `httpcheckreceiver` never observes a green daemon before secrets exist on disk. The auth check reflects the cached in-memory token, not a per-probe Vault round-trip; a revoked token flips `/readyz` back to 503 within the lifecycle check cadence (default 5 min).

Both return JSON and are loopback-only, suitable for the OTel `httpcheckreceiver`.

## Security considerations

- **File permissions** — all managed files are written with `0600`. dotvault warns if the config file is group or world writable.
- **Token security** — `~/.vault-token` is written with `0600`. Secret values are never logged, even at debug level.
- **Atomic writes** — all file writes use temp file + rename to prevent partial writes.
- **Web UI** — loopback only, CSRF-protected, strict Content Security Policy.
- **Windows** — DACL-based permission checks via the Windows Security API.

## Config reload

!!! note
    dotvault does **not** support full config reload via SIGHUP. The daemon must be fully restarted to pick up configuration changes (the exception is the `enrolments` section, which is re-read on each polling tick).

    SIGHUP **does** trigger an immediate `~/.vault-token` re-read — so when an interactive `dotvault login` writes a fresh token, the running daemon picks it up within seconds instead of waiting for the next five-minute lifecycle tick. The RPM/DEB/APK package ships a `dotvault-token-watch.path` user unit that watches `~/.vault-token` and forwards changes to the daemon via `systemctl --user kill --signal=SIGHUP dotvault.service`. The path unit is pulled in automatically by `dotvault.service`'s `[Install] Also=` directive, so enabling the daemon enables the watcher; if you installed dotvault some other way and want the same behaviour, `systemctl --user enable --now dotvault-token-watch.path`.

    The macOS launchd plist has no equivalent path-watcher today. Manual re-read works via `launchctl kill SIGHUP gui/$(id -u)/com.goodtune.dotvault`, which targets the labelled agent specifically — preferable to `kill -HUP $(pgrep -x dotvault)` because that would also signal any unrelated `dotvault sync` or `go run ./cmd/dotvault` invocation the user happens to be running (SIGHUP's default disposition is to *terminate*, so those side processes would die). Operators who want automatic re-read should script the `launchctl kill` form on a launchd `WatchPaths` trigger.
