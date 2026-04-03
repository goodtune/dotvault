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

!!! warning "Windows Group Policy override"
    On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\dotvault`, dotvault loads all configuration from the registry and **ignores the YAML file entirely**. The `--config` CLI flag is the only way to bypass this behaviour. See [Windows Group Policy](../admin/windows-gpo.md) for details.

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

## Rules section

See [Sync Rules](sync-rules.md) for details.

## Enrolments section

See [Service Onboarding](../services/overview.md) for details.

## Validation

dotvault validates the configuration on startup and exits with an error if:

- `vault.address` is missing
- No rules are defined
- Rule names are not unique
- A `target.format` is not one of: `yaml`, `json`, `ini`, `toml`, `text`, `netrc`
- `web.listen` resolves to a non-loopback address (when web is enabled)
- An enrolment entry has an empty `engine` field
