# Quick Start

This guide walks you through a minimal dotvault setup that syncs a GitHub CLI token from Vault to your local machine.

## Prerequisites

- A running [HashiCorp Vault](https://www.vaultproject.io/) instance with the KVv2 secrets engine enabled
- A user account that can authenticate to Vault
- The `dotvault` binary installed (see [Installation](installation.md))

## 1. Store a secret in Vault

Using the Vault CLI, write a secret under your user path:

```sh
vault kv put kv/users/jane/gh oauth_token="ghp_xxxxxxxxxxxx"
```

This stores the GitHub token at the path `kv/data/users/jane/gh` (the `data/` segment is implicit with `vault kv` commands).

## 2. Create a config file

Create `config.yaml`:

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
          oauth_token: "{{ .oauth_token }}"
```

## 3. Run a one-shot sync

Test your configuration with a dry run:

```sh
dotvault sync --config config.yaml --dry-run
```

If everything looks correct, run the actual sync:

```sh
dotvault sync --config config.yaml
```

## 4. Run as a daemon

For ongoing synchronisation, run dotvault as a daemon:

```sh
dotvault run --config config.yaml
```

dotvault will:

1. Authenticate to Vault using OIDC (opening a browser window)
2. Perform an initial sync of all rules
3. Poll for changes at the configured interval (15 minutes)
4. Automatically renew the Vault token before it expires

## 5. Check status

In another terminal:

```sh
dotvault status --config config.yaml
```

This shows authentication state, token TTL, and per-rule sync status.

## Next steps

- [Configuration Reference](../configuration/config-reference.md) — full list of config options
- [Authentication](../authentication/overview.md) — set up OIDC, LDAP, or token auth
- [Vault Policies](../vault/policies.md) — configure per-user KV access in Vault
- [Service Onboarding](../services/overview.md) — automate credential acquisition for services like GitHub
