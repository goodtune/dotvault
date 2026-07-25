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
- Pass `--no-passwd` to exit `0` immediately when the current user has
  an entry in `/etc/passwd`. In corporate fleets where human accounts
  come from a directory service (SSSD, LDAP, AD), a passwd entry means
  a local machine account with no Vault credentials to check — a
  fleet-wide `profile.d` script can pass the flag unconditionally and
  login-check stays silent for local accounts. The file is parsed
  directly rather than via `getent`, which merges every NSS source and
  cannot say which source an entry came from. The flag is ignored with
  a warning on Windows; a passwd read failure warns and falls through
  to the normal check (fail open — a directory user must not be locked
  out by a broken local file). The early exit refreshes the suppression
  marker, so subsequent shells in the window stop at the freshness
  check without re-parsing the file. The heuristic is Linux-targeted:
  on macOS local accounts live in Open Directory rather than
  `/etc/passwd`, so the flag never matches a human account there and
  safely degrades to the normal check.
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

### `dotvault browse`

Open a URL in a browser, preferring a browser on the machine at the other end of the [`vault.token_socket`](configuration/config-reference.md#token_socket-dotvault-to-dotvault-token-sharing) peer socket.

```sh
dotvault browse <url>
```

When `vault.token_socket` names a reachable peer dotvault (typically an SSH `RemoteForward` from a workstation running the web UI), the URL is form-posted to the peer's `POST /api/v1/remote/browse` endpoint and the browser opens **on the workstation** — the machine that actually has one. When the socket is not configured, missing, or the peer errors, the URL is opened in this host's default browser instead. Only `http` and `https` URLs without embedded `user:pass@` credentials are accepted; the same allowlist is enforced by the peer endpoint.

This makes it a natural `BROWSER` target on a headless box, so tools that launch OAuth flows (`gh auth login`, dotvault's own enrolment engines) land their login pages on the workstation's browser:

```sh
export BROWSER="dotvault browse"
```

!!! note "Some tools don't word-split `BROWSER`"
    Tools that shell out via `xdg-open`, `gh`, or git honour a multi-word `BROWSER` value. Python-based tools (`az login`, anything using Python's `webbrowser` module) exec the whole value as a single program name and fail. For those, point `BROWSER` at a one-line wrapper script instead:

    ```sh
    #!/bin/sh
    exec dotvault browse "$1"
    ```

The raw endpoint is also curl-able over the forwarded socket:

```sh
curl --unix-socket ~/.ssh/dotvault.sock http://localhost/api/v1/remote/browse -d url=https://example.com
```

The command is silent on success (exit `0`), matching `BROWSER` conventions. Config-load failures downgrade to the local browser with a warning rather than failing, so the command still works on a host with no dotvault config at all. On a truly display-less host the local fallback depends on what `xdg-open` resolves to — often a console browser — so on machines that should only ever delegate to the peer, treat a fallback as a sign the SSH `RemoteForward` is down.

### `dotvault notify`

Raise a native desktop notification — a Windows toast, a macOS Notification Center panel, or a Linux D-Bus notification — preferring the machine at the other end of the [`vault.token_socket`](configuration/config-reference.md#token_socket-dotvault-to-dotvault-token-sharing) peer socket.

```sh
dotvault notify <level> <title> [description]
```

`<level>` is one of `info`, `warning`, `error`, `attention`. It sets the notification's urgency — `error` and `attention` are delivered as audible alerts, `info` and `warning` as quiet notifications — and, on Linux/BSD where the notification daemon accepts a named stock icon, the icon shown (`dialog-information`, `dialog-warning`, `dialog-error`, `dialog-question`). On macOS and Windows a stock icon name is not a valid file path, so no custom icon is set there and the level is conveyed by urgency alone.

!!! note "macOS delivery"
    On macOS, notifications are delivered via `osascript` (or `terminal-notifier` if installed). An unsigned CLI binary driving `osascript display notification` is attributed to "Script Editor" and may be suppressed by Notification Center's per-app settings. The peer-preferring design largely sidesteps this — the workstation typically runs the daemon (web UI), which is the more reliable delivery path.

When `vault.token_socket` names a reachable peer dotvault, the notification is form-posted to the peer's `POST /api/v1/remote/notify` endpoint and appears **on the workstation** — where a human is actually looking. When the socket is not configured, missing, or the peer errors, the notification is raised on this host instead. This is the natural way for a long-running job on a headless box to get the operator's attention:

```sh
dotvault notify info "Sync complete" "all rules applied"
dotvault notify error "Backup failed" "see /var/log/backup.log"
```

Pass `--action-url <http/https URL>` to attach a link the user is taken to when they **click** the notification — e.g. straight to the failing CI build or the page where they resolve the problem:

```sh
dotvault notify error "Backup failed" "click for the run" --action-url https://ci.example/build/42
```

The click behaviour is platform-dependent, and the flag degrades gracefully:

- **Windows** — the toast is protocol-activated, so clicking it opens the URL in the default browser.
- **macOS / Linux** — a one-shot notification cannot register a click handler (macOS `osascript` has no open action; a Linux D-Bus click is delivered back to a sender that has already exited), so the URL is appended to the notification body instead, staying visible and copyable.

The URL must be `http`/`https` with a host and no embedded credentials — the same allowlist `dotvault browse` enforces — and is rejected locally (exit `1`) before anything is sent.

The raw endpoint is curl-able over the forwarded socket too:

```sh
curl --unix-socket ~/.ssh/dotvault.sock http://localhost/api/v1/remote/notify \
     -d level=error -d title='Backup failed' -d body='see the logs'
```

The title is required; the description is optional. An unknown level or an empty title fails locally (exit `1`) before anything is sent. Config-load failures degrade to a local notification, like `browse`.

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
| `--config <path>` | *(system default)* | Override the config file path. Refused when a system-wide config is present unless that config sets `bypass_system_config: true` (see the [Configuration Reference](configuration/config-reference.md#bypass_system_config)). |
| `--log-level <level>` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--log-format <format>` | `auto` | Log format: `auto` (text on a TTY, JSON otherwise), `text`, `json` |
| `--dry-run` | `false` | Show what would change without writing files |

`--once` is scoped to `dotvault run` only.

## Environment variables

| Variable | Description |
|----------|-------------|
| `DOTVAULT_TOKEN` | Vault token (takes precedence over `~/.dotvault-token`). Earlier releases honoured the standard `VAULT_TOKEN` variable; it is now deliberately ignored — it belongs to the `vault` CLI and must not leak into dotvault's session. See the [upgrade note](authentication/token.md#upgrading-from-earlier-releases). |
| `DOTVAULT_SUPPRESS_HOURS` | `dotvault login-check` suppression window in whole hours (default `6`). Zero, negative, or non-integer values cause `login-check` to exit `1`. |
| `DOTVAULT_SUPPRESS_MARKER` | Override path for the `login-check` suppression marker. Primarily used by tests; the default location is `${XDG_STATE_HOME:-$HOME/.local/state}/dotvault/login-check-suppress`. |
| `DOTVAULT_PASSWD_FILE` | Override path for the passwd file consulted by `login-check --no-passwd`. Primarily used by tests; defaults to `/etc/passwd`. |

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
