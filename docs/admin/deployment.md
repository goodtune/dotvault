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
    On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\dotvault`, dotvault loads all configuration from the registry and **ignores the YAML file entirely**. The only way to bypass this is the `--config` CLI flag, which always takes precedence.

## Running as a user service

### systemd (Linux)

Create a user service unit:

```ini
# ~/.config/systemd/user/dotvault.service
[Unit]
Description=dotvault secret sync daemon
After=network-online.target

[Service]
ExecStart=/usr/local/bin/dotvault run
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

Enable for all users by placing the unit in `/etc/systemd/user/`:

```sh
sudo cp dotvault.service /etc/systemd/user/
sudo systemctl --global enable dotvault.service
```

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

There is no file-based logging — integrate with your platform's log collection (journald, syslog, Windows Event Log via a wrapper, etc.).

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
