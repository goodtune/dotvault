# Service Onboarding

dotvault can automate credential acquisition from external services using OAuth device flows and other interactive enrolment processes. Instead of manually obtaining tokens and writing them to Vault, dotvault handles the flow and persists the credentials automatically.

## How enrolments work

Enrolments are declared in the configuration under the `enrolments` key. Each entry maps a Vault KV path segment to an enrolment engine:

```yaml
enrolments:
  gh:                        # Vault KV path segment (secret stored at users/{username}/gh)
    engine: github           # enrolment engine to use
    help_text: |             # admin-authored markdown shown in the web UI (optional)
      Mints a GitHub OAuth token via a device flow. You'll sign in with
      GitHub in your browser and approve a short code.
    settings:                # engine-specific settings (optional)
      scopes:
        - repo
        - read:org
```

`help_text` is free-form Markdown (headers, bold/italic, links, inline code, and unordered lists) rendered to sanitized HTML and shown alongside the enrolment card in the web UI, explaining what the engine will do before the user runs it. It has no effect on the CLI picker (`dotvault enrol`). Like every other config field it round-trips through YAML, the Windows registry, and `.reg` files.

## Grouping enrolments

An enrolment key may use a single-level `group/name` form to organise related enrolments under a shared prefix — useful when one engine is used for several targets (multiple Databricks workspaces, multiple AWS accounts, several GitHub hosts):

```yaml
enrolments:
  databricks/prod:
    engine: databricks
    settings: { host: "https://prod.cloud.databricks.com" }
  databricks/dev:
    engine: databricks
    settings: { host: "https://dev.cloud.databricks.com" }
  aws/account-a:
    engine: copy
    # …engine-specific settings…
```

The group segment becomes a nested Vault path segment (`users/<you>/databricks/prod`) and an expandable **folder** in the web UI's enrolment screen, with each `name` shown as a separate entry. Flat keys (`gh`, `jfrog`) stay top-level. The grouping is purely organisational — each entry is still an independent enrolment with its own settings, refresh cycle, and sync rule(s).

Exactly **one** level of grouping is supported. A second slash (`a/b/c`), a leading/trailing slash, an empty segment, or a backslash is rejected at config load.

## Enrolment lifecycle

1. On each sync cycle, dotvault checks Vault for missing or incomplete secrets for each enrolment
2. If credentials are missing, the **enrolment wizard** runs the engine's interactive flow
3. On success, credentials are written to Vault KVv2 at the user's path
4. The sync engine is triggered to sync the new credentials to local files

The wizard runs engines sequentially, with terminal progress display and best-effort clipboard support (pbcopy on macOS, xclip on Linux, clip.exe on Windows).

## Enrolment detection

Enrolment configuration changes are detected on each polling tick without requiring a daemon restart. If you add a new enrolment to the config, dotvault will pick it up on the next cycle and prompt the user to complete the flow.

## Available engines

| Engine | Service | Flow type |
|--------|---------|-----------|
| `github` | GitHub / GitHub Enterprise | OAuth device flow |
| `jfrog` | JFrog Platform / Artifactory | Browser-based web login + token rotation |
| `databricks` | Databricks workspace / account | OAuth U2M (authorization code + PKCE) + token rotation |
| `ghp` | Self-hosted ghp server (GitHub proxy) | CLI device-authorization flow |
| `ssh` | SSH key generation | Ed25519 key pair |
| `copy` | Mirror an existing Vault KVv2 secret | Non-interactive; template-driven copy with periodic re-evaluation |

See the individual engine pages for details:

- [GitHub CLI](github.md)
- [JFrog Platform](jfrog.md)
- [Databricks](databricks.md)
- [ghp](ghp.md)
- [SSH Keys](ssh.md)
- [Copy](copy.md)

## Engine interface

Engines implement a simple interface:

- **`Name()`** — human-readable provider name for display
- **`Run(ctx, settings, io)`** — execute the credential acquisition flow
- **`Fields()`** — Vault KV field names this engine writes (used to check completeness)

Engines that need extra behaviour layer it on through optional interfaces the manager probes for at run time:

- **`SettingsFielder`** — for engines whose written-field set is determined by per-enrolment settings rather than being static (used by `copy`, where the JSON template decides the keys)
- **`Refresher`** — for engines whose credentials expire and can be rotated without user interaction (used by `jfrog` and `databricks`); driven by the daemon's `RefreshManager`
- **`Watcher`** — for engines whose output is derived from upstream Vault data and must track source changes (used by `copy`); driven by the daemon's `WatchManager`, which polls on every sync interval and reacts to `kv-v2/data-write` events on Vault Enterprise

This means new engines can be added to support additional services without changes to the core enrolment system.
