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

Intended to be wired into shell rc / login-profile scripts via a thin
wrapper that gates on interactivity, TTY, and daemon state. The binary
trusts those preconditions and never re-checks them.

```sh
dotvault login-check [flags]
```

- A suppression marker at
  `${XDG_STATE_HOME:-$HOME/.local/state}/dotvault/login-check-suppress`
  is checked first (override path with `DOTVAULT_SUPPRESS_MARKER`,
  primarily for testing). If its mtime is within
  `DOTVAULT_SUPPRESS_HOURS` (default `6`), the command exits silently.
  A future mtime is treated as stale so clock skew or backup restores
  cannot lock suppression on indefinitely.
- Otherwise: if the cached token is valid and still within the first
  half of its creation TTL, exit clean. Past halfway, attempt renewal;
  if renewal fails but the token is still valid, warn with the
  absolute expiry time and exit 0. If no valid token, print a one-line
  explanation of why an authentication prompt is about to appear ("no
  cached Vault token was found", "the cached Vault token has expired",
  or "the cached Vault token is no longer valid") and then run the
  configured login flow. The line is yellow on a colour-capable TTY
  (ANSI SGR 33; honours `NO_COLOR`) and plain text otherwise — without
  it, a profile-script invocation would surface a context-free password
  prompt the user did not ask for.
- The marker is refreshed on every exit past the suppression check
  (success, decline, failure, Ctrl+C, internal errors), so concurrent
  shell startups only ever prompt once per window and a single Ctrl+C
  is enough — no second Enter required.
- Pass `--quiet` to suppress just the explanation line — the prompt
  still appears. Use this from wrappers that already surface their
  own context (a Window Manager indicator, a desktop notification,
  etc.) and don't want a duplicate message on stderr.
- Exit `0` on suppressed, success, decline, cancellation, or expected
  authentication failure. Exit `1` only on invalid
  `DOTVAULT_SUPPRESS_HOURS` or genuine internal errors. The shell
  wrapper does not branch on exit code; signalling is via the marker
  state and stderr output.

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
| `VAULT_TOKEN` | Vault token (takes precedence over `~/.dotvault-token`) |
| `DOTVAULT_SUPPRESS_HOURS` | `dotvault login-check` suppression window in whole hours (default `6`). Zero, negative, or non-integer values cause `login-check` to exit `1`. |
| `DOTVAULT_SUPPRESS_MARKER` | Override path for the `login-check` suppression marker. Primarily used by tests; the default location is `${XDG_STATE_HOME:-$HOME/.local/state}/dotvault/login-check-suppress`. |

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
