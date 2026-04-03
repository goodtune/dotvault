# dotvault

A cross-platform daemon that runs in user context, authenticates to [HashiCorp Vault](https://www.vaultproject.io/), and performs one-way synchronisation of KVv2 secrets into local configuration files.

## What does dotvault do?

If you distribute system-level configuration to a fleet of machines — via NixOS, Ansible, Puppet, or similar — you can manage the _structure_ of dotfiles centrally. But when those files need personal secrets (API tokens, OAuth credentials, private keys), there is a gap.

**Template tools own the whole file.** Tools like `vault agent` and `consul-template` render a complete file from a template on every pass. If a user adds a genuinely useful entry to their `config.yaml`, the next render obliterates it.

**dotvault takes a surgical approach.** Instead of owning the file, it _merges_ secret values into the coordinates where they're needed, leaving the rest of the file intact. Sysops define the rules; users remain free to customise their own dotfiles without fear of losing changes.

## Key features

- **Surgical merging** — secrets are merged into existing files, not templated over the top of them
- **Multiple auth methods** — OIDC (browser-based SSO), LDAP with MFA, or direct token
- **Six output formats** — YAML, JSON, INI, TOML, text, and netrc with format-appropriate merge strategies
- **Go templates** — reshape secret data before writing, with helpers for encoding and defaults
- **Daemon or one-shot** — runs as a long-lived service with automatic token refresh, or a single sync cycle
- **Web UI** — optional local dashboard for login, status, and secret inspection
- **Service onboarding** — automated credential acquisition via OAuth device flows (e.g. GitHub)
- **Cross-platform** — Linux, macOS, and Windows with platform-native permission checks
- **Enterprise Vault support** — event-driven sync via the Vault Events API (WebSocket), with fallback to polling

## How it works

1. dotvault authenticates to Vault using the configured auth method
2. On each sync cycle, it reads each rule's secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}`
3. If the secret version has changed (or the target file was modified externally), it renders data through an optional template, merges with existing file content, and writes the result atomically
4. Sync state is persisted locally so unchanged secrets are skipped efficiently

## Designed as a user service

dotvault is intended to run as a per-user service. Sysops configure desktops and remote Linux machines to launch it in a user context so that each person has their own daemon, their own Vault identity, and their own secrets.

On desktop environments it runs a local web service. If the current session is unauthenticated, dotvault launches a browser at its login page, triggering an OIDC authentication flow against Vault. When this is wired into an SSO provider, users are authenticated more or less transparently — no manual token juggling required.
