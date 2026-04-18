# Service Onboarding

dotvault can automate credential acquisition from external services using OAuth device flows and other interactive enrolment processes. Instead of manually obtaining tokens and writing them to Vault, dotvault handles the flow and persists the credentials automatically.

## How enrolments work

Enrolments are declared in the configuration under the `enrolments` key. Each entry maps a Vault KV path segment to an enrolment engine:

```yaml
enrolments:
  gh:                        # Vault KV path segment (secret stored at users/{username}/gh)
    engine: github           # enrolment engine to use
    settings:                # engine-specific settings (optional)
      scopes:
        - repo
        - read:org
```

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
| `ssh` | SSH key generation | Ed25519 key pair |

See the individual engine pages for details:

- [GitHub CLI](github.md)
- [JFrog Platform](jfrog.md)
- [SSH Keys](ssh.md)

## Engine interface

Engines implement a simple interface:

- **`Name()`** — human-readable provider name for display
- **`Run(ctx, settings, io)`** — execute the credential acquisition flow
- **`Fields()`** — Vault KV field names this engine writes (used to check completeness)

This means new engines can be added to support additional services without changes to the core enrolment system.
