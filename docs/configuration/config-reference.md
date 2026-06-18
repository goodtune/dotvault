# Configuration Reference

dotvault uses a YAML configuration file. The file location depends on your platform:

| Platform | Path |
|----------|------|
| Linux    | `/etc/xdg/dotvault/config.yaml` (also checks `$XDG_CONFIG_DIRS`) |
| macOS    | `/Library/Application Support/dotvault/config.yaml` |
| Windows  | `%ProgramData%\dotvault\config.yaml` |

You can override the config path with `--config`:

```sh
dotvault run --config /path/to/config.yaml
```

!!! warning "`--config` is gated by the system-wide configuration"
    `--config` is honoured only when there is **no system-wide configuration**, or the system-wide configuration explicitly opts in with `bypass_system_config: true`. If a system config is present and does not set the flag, dotvault refuses the override and exits with an error rather than silently loading the command-line file. This is identical on every platform; the "system-wide configuration" is the Windows Group Policy registry policy when present, otherwise the system YAML file. See [`bypass_system_config`](#bypass_system_config) below.

!!! warning "Windows Group Policy"
    On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\goodtune\dotvault`, dotvault loads all configuration from the registry and **ignores the YAML file entirely**. Pointing dotvault at a different file with `--config` requires `bypass_system_config: true` in that policy (the registry equivalent is a `BypassSystemConfig` REG_DWORD of `1` directly under the policy key). See [Windows Group Policy](../admin/windows-gpo.md) for details.

## Full example

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"
  auth_role: "default"
  auth_mount: "oidc"
  kv_mount: "kv"
  user_prefix: "users/"
  ca_cert: "/etc/ssl/certs/internal-ca.pem"
  tls_skip_verify: false

sync:
  interval: "15m"

web:
  enabled: true
  listen: "127.0.0.1:9000"
  login_text: |
    Welcome to dotvault. Click **Login** to authenticate via SSO.
  secret_view_text: |
    These secrets are synchronised from Vault to your local machine.

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{ .oauth_token }}"

  - name: ssh-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519"
      format: text

  - name: netrc
    vault_key: "netrc"
    target:
      path: "~/.netrc"
      format: netrc

enrolments:
  gh:
    engine: github
    settings:
      scopes:
        - repo
        - read:org
        - gist
```

## Top-level options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bypass_system_config` | bool | `false` | Permit the `--config` command-line override on this machine (see below) |

### `bypass_system_config`

By default, when a system-wide configuration is present, the `--config` command-line flag is **refused** — a managed deployment (a Windows Group Policy registry policy, or a system config file shipped by configuration management) cannot be sidestepped from the command line. Setting `bypass_system_config: true` in the **system-wide** config re-enables the override on that machine.

The intended workflow: an administrator normally pins the system config, but flips this flag when they need to trial a hand-edited config without un-deploying the policy. It only has an effect when set in the authoritative system config — setting it inside a file passed to `--config` is meaningless, because that file is only loaded once the override has already been allowed.

The behaviour is identical on every platform. On Windows GPO the equivalent registry value is a `BypassSystemConfig` REG_DWORD of `1` directly under `HKLM\SOFTWARE\Policies\goodtune\dotvault`.

## Vault section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | string | *(required)* | Vault server URL |
| `auth_method` | string | — | Authentication method: `oidc`, `ldap`, or `token` |
| `auth_mount` | string | — | Vault auth mount path (e.g. `oidc`, `ldap`) |
| `auth_role` | string | — | Vault auth role to request |
| `kv_mount` | string | `kv` | KVv2 secrets engine mount path |
| `user_prefix` | string | `users/` | Prefix for per-user secret paths (trailing slash enforced) |
| `ca_cert` | string | — | Path to CA certificate for TLS verification |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |

Secret paths are constructed as: `{kv_mount}/data/{user_prefix}{username}/{vault_key}`

For example, with defaults and username `jane`, the rule `vault_key: "gh"` reads from `kv/data/users/jane/gh`.

## Sync section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interval` | string | `15m` | Polling interval as a Go duration (e.g. `5m`, `1h`, `30s`) |

On Enterprise Vault, dotvault also subscribes to the Events API via WebSocket for near-instant sync on secret changes. The polling interval serves as a fallback.

## Web section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the local web UI |
| `listen` | string | — | Listen address (must be loopback, e.g. `127.0.0.1:9000`) |
| `login_text` | string | — | Markdown text displayed on the login page |
| `secret_view_text` | string | — | Markdown text displayed on the secret view page |

!!! danger "Loopback only"
    The `listen` address **must** resolve to a loopback address (`127.0.0.1`, `[::1]`, or `localhost`). dotvault will refuse to start if a non-loopback address is configured. This is a hard security invariant.

## Remote config section

See [Remote Configuration](remote-config.md) for details. When `remote_config.url` is set, the local file/registry config becomes a base that is overlaid with dynamic sections (`rules`, `enrolments`, `sync`) fetched from a `dotvault-config` service.

## Rules section

See [Sync Rules](sync-rules.md) for details.

## Enrolments section

See [Service Onboarding](../services/overview.md) for details.

## Validation

dotvault validates the configuration on startup and exits with an error if:

- `vault.address` is missing
- No rules are defined (waived when `remote_config.url` is set — the remote document may supply them)
- Rule names are not unique
- A `target.format` is not one of: `yaml`, `json`, `ini`, `toml`, `text`, `netrc`, `ssh_config`
- `web.listen` resolves to a non-loopback address (when web is enabled)
- An enrolment entry has an empty `engine` field
