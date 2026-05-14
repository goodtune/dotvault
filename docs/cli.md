# CLI Reference

## Commands

### `dotvault`

Running `dotvault` with no subcommand prints help. The daemon is no
longer the default; use `dotvault run` to start it explicitly.

### `dotvault run`

Run the daemon in the foreground.

```sh
dotvault run [flags]
```

The daemon:

1. Loads configuration
2. Authenticates to Vault (reusing cached token if valid)
3. Starts the web UI if enabled
4. Runs the enrolment wizard for any missing credentials
5. Starts the sync engine (initial sync, then hybrid event + poll loop)

`dotvault run --once` redirects to the sync path — a one-shot cycle
followed by exit. This is the only place `--once` is accepted (it is
no longer a global flag).

### `dotvault sync`

Run a single sync cycle and exit.

```sh
dotvault sync [flags]
```

Useful for cron jobs, testing, or one-off synchronisation.

### `dotvault login`

Force a fresh Vault login via the configured auth method (OIDC, LDAP),
ignoring any cached token. The dotvault-config-driven analogue of
`vault login -address <vault.address> -method <vault.auth_method>` —
use it when a running daemon needs a new token after expiry without
re-typing the address and method.

```sh
dotvault login [flags]
```

### `dotvault login-check`

Intended to be wired into shell rc / login-profile scripts.

```sh
dotvault login-check [flags]
```

- If stdout is not a TTY, the command exits silently with status 0 so
  non-interactive callers (cron, sshd ForceCommand, scp) never see a
  prompt.
- If the cached token is valid and still within the first half of its
  creation TTL, exit clean.
- If the cached token is valid but past the halfway mark, attempt
  renewal. On success, exit clean. If renewal fails but the token is
  still valid, warn with the absolute expiry time and exit 0.
- If the cached token is missing or invalid, run the configured login
  flow. Transient Vault/TLS/network errors warn and exit clean rather
  than prompting. Ctrl-C exits without fanfare so the user can dismiss
  the prompt on a fresh terminal session.

### `dotvault status`

Display authentication state, token TTL, and per-rule sync status.

```sh
dotvault status [flags]
```

### `dotvault version`

Print the build version and exit.

```sh
dotvault version
```

### `dotvault reg-export` / `dotvault reg-import`

Convert between dotvault YAML configuration and the Windows .reg file
format used to deploy configuration via Group Policy. See the
project README and the Windows admin docs for details.

## Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | *(system default)* | Override the config file path |
| `--log-level <level>` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--dry-run` | `false` | Show what would change without writing files |

`--once` is scoped to `dotvault run` only.

## Environment variables

| Variable | Description |
|----------|-------------|
| `VAULT_TOKEN` | Vault token (takes precedence over `~/.vault-token`) |

## Logging

Logs are written to stderr:

- **Text format** when stderr is a TTY
- **JSON format** otherwise

This means you can redirect logs to a file or pipe to a log collector:

```sh
dotvault run 2>/var/log/dotvault.log
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (config validation, auth failure, etc.) |
