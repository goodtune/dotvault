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

The RPM and DEB packages ship a `dotvault.service` **user unit** (a
`Type=notify` service with `WatchdogSec=120` and the OpenTelemetry-
friendly logging settings). The install path depends on the
distribution: the RPM installs to `/usr/lib/systemd/user/`, the DEB
to `/lib/systemd/user/`. Both directories are part of the standard
systemd user-unit search path, so the enablement commands below are
the same regardless of packaging format. dotvault is a per-user
daemon — it authenticates to Vault with the OS user's identity and
writes secrets into that user's `$HOME` — so installing it as a
system service that runs as root would write to root's `$HOME` and
authenticate to Vault as root, which is almost never what you want.

Enable per-user once the package is installed:

```sh
systemctl --user enable --now dotvault.service
```

Or enable globally for every login session on the machine:

```sh
sudo systemctl --global enable dotvault.service
```

`--global` enables the unit in every user's session; each user runs
their own instance and authenticates with their own Vault identity.

Environment-variable overrides (e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`)
can be set via `/etc/default/dotvault` or `/etc/sysconfig/dotvault`
— both paths are referenced by the unit and ignored if absent.

The unit hard-codes a couple of system paths that the package owns:
`ExecStart=/usr/bin/dotvault run`, plus the `EnvironmentFile=` paths
listed above. If you install dotvault into a non-standard location
(e.g. `/usr/local/bin`), copy the unit out to
`~/.config/systemd/user/dotvault.service` and adjust those lines.

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

This is useful when running under a service manager that captures stderr
but is connected to a TTY for debugging, or when forcing structured logs
for ingestion into a log collector regardless of how the daemon was
launched.

There is no file-based logging — integrate with your platform's log
collection (journald, syslog, Windows Event Log via a wrapper, etc.). On
systemd hosts the packaged unit routes stderr to the journal, so the
OpenTelemetry collector's `journaldreceiver` can filter on
`_SYSTEMD_USER_UNIT=dotvault.service` (or `_SYSTEMD_UNIT` when the
unit was enabled with `systemctl --global`) to pick logs up directly.

## Observability

dotvault can export OpenTelemetry metrics to a local OTel collector.
Disabled by default; enable by adding an `observability:` block to
`config.yaml`:

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
    The `observability` block is configured via the YAML config file
    only — the GPO/registry layer (and the ADMX template) does not yet
    expose it. On a GPO-managed Windows install, point the collector
    via the standard `OTEL_*` environment variables (set through a
    machine-wide environment policy) until the registry surface is
    extended.

The standard `OTEL_*` environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_EXPORTER_OTLP_HEADERS`, …) are also honoured by the SDK, so the
`endpoint`/`headers` fields can be left empty and managed centrally via
`/etc/default/dotvault`.

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
| `dotvault.sighup.received`      | counter   | (no attrs)                                           |

Health probes are exposed on the web UI listener when it's enabled:

- `GET /healthz` — liveness, always 200 while serving
- `GET /readyz` — readiness, 200 once authenticated to Vault, 503 otherwise

Both return JSON and are loopback-only, suitable for the OTel
`httpcheckreceiver`.

## Security considerations

- **File permissions** — all managed files are written with `0600`. dotvault warns if the config file is group or world writable.
- **Token security** — `~/.vault-token` is written with `0600`. Secret values are never logged, even at debug level.
- **Atomic writes** — all file writes use temp file + rename to prevent partial writes.
- **Web UI** — loopback only, CSRF-protected, strict Content Security Policy.
- **Windows** — DACL-based permission checks via the Windows Security API.

## Config reload

!!! note
    dotvault does **not** support config reload via SIGHUP. The daemon must be fully restarted to pick up configuration changes.

    The exception is the `enrolments` section, which is re-read on each polling tick.
