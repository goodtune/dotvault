# `dotvault`

A cross-platform daemon that runs in user context, authenticates to [HashiCorp Vault](https://www.vaultproject.io/), and performs one-way synchronisation of KVv2 secrets into local configuration files. It is intended to run as a long-lived daemon but can also be run interactively for one-off syncs.

## Overview

`dotvault` bridges the gap between centralised secret management and the dotfiles that CLI tools expect on disk. Define rules mapping Vault KV paths to local files, and `dotvault` keeps them in sync — polling for changes, merging safely, and re-syncing if files are modified or deleted externally.

## Features

- **Multiple auth methods** — OIDC (browser-based), LDAP, or token-based authentication to Vault
- **Four output formats** — Write secrets as YAML, JSON, INI, or netrc, with deep merge support to preserve existing file content
- **Go templates** — Optionally reshape secret data before writing, with helpers like `env`, `base64encode`, `default`, and `quote`
- **Daemon mode** — Runs in the foreground with configurable polling intervals and automatic token refresh
- **Web UI** — Optional local dashboard to view sync status, inspect secrets, and trigger manual syncs
- **Dry-run mode** — Preview what would change without writing any files
- **Cross-platform** — Builds for Linux, macOS, and Windows (amd64/arm64), with platform-native file permission checks (Unix mode bits / Windows ACLs)

## Quick start

Create a config file (see [Configuration](#configuration) below) and run:

```sh
dotvault run --config path/to/config.yaml
```

Or run a single sync cycle and exit:

```sh
dotvault sync --config path/to/config.yaml
```

Check connection and sync status:

```sh
dotvault status
```

## Configuration

`dotvault` uses a YAML config file. A minimal example:

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"

sync:
  interval: "15m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{.token}}"
```

### Vault

| Field | Description | Default |
|-------|-------------|---------|
| `address` | Vault server URL (required) | — |
| `auth_method` | `oidc`, `ldap`, or `token` | — |
| `kv_mount` | KVv2 mount path | `kv` |
| `user_prefix` | Prefix for per-user secret paths | `users/` |
| `ca_cert` | Path to CA certificate for TLS | — |
| `tls_skip_verify` | Skip TLS verification (dev only) | `false` |

### Rules

Each rule maps a Vault secret to a local file:

| Field | Description |
|-------|-------------|
| `name` | Unique rule identifier |
| `vault_key` | Key in Vault (e.g. `gh` resolves to `kv/data/users/<you>/gh`) |
| `target.path` | Local file path (supports `~`) |
| `target.format` | One of: `yaml`, `json`, `ini`, `netrc` |
| `target.template` | Optional Go template for formatting |

### Optional sections

**`web`** — Enable a local web dashboard:

```yaml
web:
  enabled: true
  listen: "127.0.0.1:9000"
```

**`sync`** — Control polling behaviour:

```yaml
sync:
  interval: "5m"
```

## How it works

1. `dotvault` authenticates to Vault using the configured auth method
2. On each sync cycle, it reads each rule's secret from Vault
3. If the secret version has changed (or the target file was modified/deleted), it renders the data through the optional template, merges with existing file content, and writes the result
4. Sync state is persisted locally so unchanged secrets are skipped efficiently

## License

MIT
