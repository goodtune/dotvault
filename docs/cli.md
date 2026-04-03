# CLI Reference

## Commands

### `dotvault` / `dotvault run`

Run the daemon in the foreground. This is the default command.

```sh
dotvault run [flags]
```

The daemon:

1. Loads configuration
2. Authenticates to Vault (reusing cached token if valid)
3. Starts the web UI if enabled
4. Runs the enrolment wizard for any missing credentials
5. Starts the sync engine (initial sync, then hybrid event + poll loop)

### `dotvault sync`

Run a single sync cycle and exit.

```sh
dotvault sync [flags]
```

Useful for cron jobs, testing, or one-off synchronisation.

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

## Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config <path>` | *(system default)* | Override the config file path |
| `--log-level <level>` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--dry-run` | `false` | Show what would change without writing files |
| `--once` | `false` | Run one sync cycle and exit (alias for `sync`) |

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
