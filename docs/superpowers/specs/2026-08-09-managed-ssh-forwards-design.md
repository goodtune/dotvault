# Managed SSH forwards

Status: design, approved 2026-08-09. Branch `feat/managed-ssh-forwards`.

## Problem

`vault.token_socket` lets a headless host borrow a Vault token — and drive `browse` / `notify` / `clipboard` — from a workstation that authenticated interactively. The socket on the headless side is created by an OpenSSH `RemoteForward`, wired by hand or by a keyless sync rule that renders `~/.ssh/config`:

```
RemoteForward /home/{{ username }}/.ssh/dotvault.sock 127.0.0.1:9000
```

That works, and it is fragile in the ways an external process always is. The forward exists only while someone is sitting in an `ssh` session. It dies with the laptop lid, a Wi-Fi handover, a VPN transition, or a remote `sshd` restart, and nothing brings it back until a human opens a new terminal. `docs/configuration/config-reference.md:219` already documents the sharpest edge: a process started inside that session but outliving it — a job in `tmux`, a long-running service — succeeds at first and then fails the moment it next needs a token, because the only socket it knew about is gone.

dotvault is a long-lived daemon that already owns an SSH identity. It should maintain those forwards itself.

## Scope

The daemon maintains an SSH connection to each configured remote and remote-forwards a Unix socket on that remote back to its own loopback web listener — the same shape `RemoteForward` produces, minus the external process. It reconnects on failure with backoff, and its state is inspectable.

Explicitly **not** in scope: local forwards (`direct-streamlocal`, local TCP listeners, local port allocation), per-remote SSH usernames, `known_hosts` file interop, and non-`streamlocal` forward types. The spec that motivated this work described local forwarding; that direction has no consumer in dotvault today and is not built.

## Preconditions

Two, and both are hard:

- **`web.enabled`** — the forward's target is the web listener. Without it there is nothing on the other end of the socket, and `GET /api/v1/token` and the peer actions are the entire point.
- **`agent.enabled`** with at least one usable key source — the SSH identity comes from the agent backend.

Neither is fatal to the daemon. A configured remote whose preconditions are unmet resolves to a terminal `disabled` state carrying the reason, in the same spirit as the agent's `errSource` and the enrolment picker's `error: …` rows.

## Architecture

```
config-refresh loop ─┐
daemon startup ──────┼──► sshfwd.Manager.Reconcile(ctx, []Remote)
web/CLI mutation ────┘             │
                                   │  desired ∩ actual → keep
                                   │  desired − actual → start
                                   │  actual − desired → stop
                                   ▼
                            ManagedRemote (one per host, independent)
                                   │
                                   ├── connection manager  ──► *ssh.Client
                                   │     dial, auth, keepalive, backoff
                                   │
                                   └── forward supervisor
                                         client.ListenUnix(remoteSocket)
                                         accept ──► dial web.listen ──► pump
```

Reconciliation is deliberately isolated from every trigger that can cause it, so startup, the config tick, an API mutation, and a test all enter through the same door.

### Package layout

```
internal/sshfwd/
    config.go     ssh.yaml load / save / validate
    registry.go   Registry: the single mutation service layer
    manager.go    Reconcile, desired-vs-actual diff
    remote.go     ManagedRemote lifecycle and state machine
    dial.go       ssh.ClientConfig assembly
    identity.go   agent.Backend → []ssh.Signer adapter
    hostkey.go    CA list + pinned key verifier
    forward.go    ListenUnix accept loop, bidirectional pump
    home.go       remote $HOME probe and ~ expansion
    state.go      status snapshot for the API
cmd/dotvault/
    ssh.go        `dotvault ssh` parent command
    ssh_add.go    ssh_list.go  ssh_remove.go
internal/paths/
    UserConfigDir(), SSHConfigPath()
internal/web/
    ssh.go        CRUD handlers over Registry
```

Dependency direction: `cmd` and `web` both depend on `sshfwd`; `sshfwd` depends on `agent` (for the backend interface) and `config`. Nothing depends on `cmd`.

## Configuration

The settings split by who owns them.

### System config — trust material

A new `ssh:` section, admin-owned, subject to the usual lockstep rule (`internal/config`, `internal/config/registry_windows.go`, `internal/regfile/regfile.go`, `internal/regfile/parse.go`, plus a round-trip test):

```yaml
ssh:
  certificate_authorities:
    - "@cert-authority *.example.com ssh-ed25519 AAAA…"
  insecure_ignore_host_key: false
```

`insecure_ignore_host_key` lives here rather than in the user file because it is a security downgrade; on a personal machine the user is the admin anyway. It is dynamic — consulted per connection attempt — so a change applies on the next reconcile without a restart.

### User config — the remotes

A new file, `ssh.yaml`, sibling to the per-user env file already documented at `~/.config/dotvault/env`:

| OS | Path |
|----|------|
| Linux | `${XDG_CONFIG_HOME:-~/.config}/dotvault/ssh.yaml` |
| macOS | `~/Library/Application Support/dotvault/ssh.yaml` |
| Windows | `%APPDATA%\dotvault\ssh.yaml` |

It is **user-level only** and is never resolved from a system location, never read from the Windows registry, and never carried by the remote-config overlay. It holds `remotes:` and nothing else.

```yaml
remotes:
  - host: foo.example.com
    port: 22
    remote_socket: ~/.ssh/dotvault.sock
    host_key: "ssh-ed25519 AAAA…"
    enabled: true
```

`host` is the identity of an entry — `add` is idempotent on it, and `remove` keys on it. `port` defaults to 22 and `enabled` to true. Unknown top-level keys are preserved across a rewrite so a future field added by a newer build is not silently dropped by an older one.

Written at 0600 in a 0700 directory: the file records which hosts this user connects to and pins their keys.

### `remote_socket` and `~`

The default is the literal string `~/.ssh/dotvault.sock`. A leading `~/` is expanded **at connect time** against the remote account's home, discovered by running `echo $HOME` on an exec channel once per connection and cached for that connection's lifetime. An absolute path is used verbatim and never probes.

Storing `~` rather than resolving it at `add` time keeps the entry portable if the remote account's home moves, and reads the way a user expects. `~user/` is rejected at validation rather than silently mishandled, as is any path that is neither absolute nor `~/`-prefixed.

## The service layer

**Every mutation passes through `sshfwd.Registry`, which lives in the daemon.** The CLI is a thin client of the web API; it does not write `ssh.yaml` itself.

This falls out of two facts rather than being a preference. The identity lives in the daemon's agent backend, so the CLI cannot perform the verifying login on its own without standing up a second Vault client and a second cert source. And a single writer removes the CLI-versus-daemon write race outright — no advisory lock, no lost-update window, no second serialization path to keep consistent.

Consequences, stated plainly:

- `dotvault ssh add` / `remove` require a running daemon and fail with a clear "dotvault daemon is not running" otherwise. This is honest: without the daemon the operation cannot be verified, and an unverified entry is what the next section exists to prevent.
- `dotvault ssh list` degrades to config-only rows when the daemon is unreachable, reading `ssh.yaml` directly and reporting runtime state as `unavailable`. Reading is safe; writing is not.
- Hand-edits of `ssh.yaml` remain fully supported and converge on the config-refresh tick. The file is the source of truth; the Registry is just the only *writer* dotvault itself uses.
- No `POST /api/v1/reload` route is needed. A mutation reconciles in-process, immediately, because it happened inside the daemon.

`Registry` owns load → validate → verify → mutate → atomic write (temp file, fsync, rename) → reconcile, and is the only code path that does so.

## Adding a remote is transactional

`add` does not write a configuration entry it has not proven. Before persisting anything it runs the full path:

1. resolve signers from the agent backend
2. dial and authenticate
3. verify the host key (see below)
4. probe `$HOME` if the socket path needs expansion
5. request the forward via `ListenUnix`
6. tear the whole thing down

Only then is the entry written and the reconcile triggered. This catches the failures that would otherwise appear an hour later as a mute `offline` row: no agent identity, an unauthorised principal, `AllowStreamLocalForwarding no` on the remote `sshd`, a socket path in an unwritable directory.

`--force` (`force: true` on the API) persists without the dry run, for the laptop that is offline at the moment the user wants to register a host.

## Host-key trust

Three outcomes, no fourth:

1. A `certificate_authorities` entry from the system config signs the host's certificate → accepted, nothing pinned.
2. The entry's `host_key` matches → accepted.
3. Anything else → rejected, and the remote enters terminal `host-key-error`.

There is no runtime trust-on-first-use. Pinning happens exactly once, during `add`, which is an explicit human gesture: the login captures the key, and if no CA covers it the fingerprint is returned for confirmation rather than saved.

That confirmation is one protocol for both surfaces. `POST /api/v1/ssh/remotes` without a confirmed key performs the login and returns **409 with the fingerprint**; the client re-POSTs echoing it back to commit. The CLI renders that as a TTY prompt (`--accept-host-key` to skip, required when not a TTY); the SPA renders it as a confirm dialog. Neither can degrade into blind TOFU because neither can commit without echoing a fingerprint the daemon just observed.

`insecure_ignore_host_key` short-circuits all three and logs a WARN naming the host on every connection attempt.

## Identity

`agent.Backend` already aggregates key sources and does cert-aware `SignWithFlags`, but its `Signers()` returns `ErrReadOnly` — deliberately, because dotvault is one-way — so `ssh.PublicKeysCallback` cannot consume it directly.

`identity.go` adapts it: for each `Backend.List()` identity, wrap the blob in an `ssh.Signer` whose `Sign` delegates to `Backend.SignWithFlags`. The callback re-lists on each dial, so a Vault-CA certificate rotated since the last connection is picked up on the next reconnect without any cache of its own. The agent's read-only contract is untouched.

The SSH login username is the Vault username the agent already resolves for principal templating. Not configurable in v1.

## Connection lifecycle

```
        ┌──────────────┐
        │  CONNECTING  │◄──────────────┐
        └──────┬───────┘               │
               │ dial + auth + forward │
               ▼                       │
        ┌──────────────┐               │
        │  CONNECTED   │               │
        └──────┬───────┘               │
               │ transport failure     │
               ▼                       │
        ┌──────────────┐   backoff     │
        │ RECONNECTING ├───────────────┘
        └──────────────┘
```

States surfaced to the CLI and UI: `connecting`, `connected`, `reconnecting`, `offline`, `authentication-error`, `host-key-error`, `disabled`.

**Backoff** is exponential with jitter: 500 ms, 1 s, 2 s, 4 s, 8 s, 16 s, 30 s, then held at 30 s, each with ±20% jitter. It resets after a connection stays up for 60 s. `authentication-error` and `host-key-error` still retry — a Vault-CA cert can be reissued, a host key can be re-pinned — but from a 5-minute floor, because retrying them at 500 ms is noise against a condition only a human clears. Reconciliation cancels an in-flight backoff immediately.

**Keepalives** are SSH-level, not TCP: `keepalive@openssh.com` via `SendRequest` with `wantReply` every 15 s, three consecutive failures invalidating the client. TCP keepalive alone does not detect a wedged `sshd`, and a laptop resuming from sleep needs the failure surfaced in seconds rather than after the OS TCP timeout.

**Forwarding.** On `CONNECTED` the remote calls `client.ListenUnix(path)` and serves an accept loop, dialling `web.listen` per accepted connection and copying both directions with half-close where the transport supports it. Because `x/crypto/ssh` does not unlink a stale socket and `sshd` will not bind over one, a bind failure triggers **one** `rm -f <path>` over an exec channel and a single retry. Bind-first is the ordering that matters: unlinking pre-emptively would destroy a live socket belonging to a real `ssh -R` session the user is currently using.

**Concurrency.** Forwarding goroutines never own or mutate the client. The connection manager holds the current `*ssh.Client`; handlers ask for it through `remote.WaitForClient(ctx)`, which blocks up to a 10 s grace period while a reconnect is in flight rather than failing a connection that arrives during a Wi-Fi handover. Session-manager internals are not exposed.

## Runtime state

`GET /api/v1/status` gains an `ssh` block:

```json
{
  "ssh": {
    "remotes": [
      {
        "host": "foo.example.com",
        "state": "connected",
        "remote_socket": "/home/me/.ssh/dotvault.sock",
        "target": "127.0.0.1:9000",
        "connected_since": "2026-08-09T12:00:00+10:00",
        "reconnects": 2,
        "active_connections": 1,
        "last_error": null
      }
    ]
  }
}
```

`remote_socket` reports the **expanded** path once known, so the user sees what was actually bound. Runtime values are never written back to `ssh.yaml`.

## CLI

```
dotvault ssh add <host> [--force] [--accept-host-key] [--socket <path>] [--port N]
dotvault ssh list
dotvault ssh remove <host>
```

`add` is idempotent on `host` — a second add updates the existing entry rather than duplicating it. `remove` on an unconfigured host reports so and exits 0.

```
HOST                 STATUS         REMOTE SOCKET                    TARGET
foo.example.com      connected      /home/me/.ssh/dotvault.sock      127.0.0.1:9000
bar.example.com      reconnecting   /home/me/.ssh/dotvault.sock      127.0.0.1:9000
baz.example.com      host-key-error /home/me/.ssh/dotvault.sock      —
```

## Web UI

An SSH page in the SPA over CRUD endpoints, all CSRF-protected. The peer-action Origin-check exemption does not apply here: it exists because a bare `curl` over a forwarded socket cannot run the issue-then-spend handshake, and both a browser and the CLI can.

- `GET /api/v1/ssh/remotes` — config joined with live state
- `POST /api/v1/ssh/remotes` — add, with the 409-fingerprint handshake above
- `PATCH /api/v1/ssh/remotes/{host}` — `enabled`, `remote_socket`, `port`
- `DELETE /api/v1/ssh/remotes/{host}`

All four are thin handlers over `Registry`, so validation, the trust gesture, and the write path are shared with the CLI by construction.

## Errors

Classified internally, not collapsed into a generic `offline`: network unreachable, DNS failure, connection refused, handshake failure, authentication failure, certificate unavailable or expired, host-key failure, remote socket bind failure, remote `$HOME` probe failure, config failure. The class drives the reported state and the backoff floor; user-facing output stays one line.

## Observability

Logged on state transition, never per loop iteration: configured, connecting, connected, keepalive failed, connection lost, reconnecting, remote removed, forward listener started/stopped, forward failed, authentication failed, host-key validation failed.

Metrics, following the existing OTel wiring in `internal/observability`, with `host` as a label — bounded by the size of `remotes`, which is user-authored and small:

```
dotvault_ssh_connections            gauge
dotvault_ssh_reconnect_total        counter
dotvault_ssh_connect_failure_total  counter   (labelled by error class)
dotvault_ssh_keepalive_failure_total counter
dotvault_ssh_forward_connections_active gauge
dotvault_ssh_forward_connections_total  counter
dotvault_ssh_forward_failure_total      counter
```

Never logged: the socket path's contents, obviously, but also anything read from a forwarded stream. The pump copies bytes and counts them.

## Testing

**Unit.** `ssh.yaml` round-trip including unknown-key preservation and the atomic rewrite; validation of `~`, `~user/`, and relative paths; reconcile diffs for `[] → [foo]`, `[foo] → [foo, bar]`, `[foo, bar] → [bar]`, `[foo] → [modified foo]`, asserting removed remotes are cancelled promptly; backoff sequence and jitter bounds; the host-key verifier's three outcomes plus the `insecure_ignore_host_key` short-circuit; the `Backend` → `[]ssh.Signer` adapter against a fake backend.

**Integration**, against a containerised `sshd` added as a docker-compose profile (matching how the JFrog stack is opt-in), trusting a test CA and running the dotvault user:

1. connect, forward, and reach the web listener through the remote socket
2. kill the SSH transport; assert `reconnecting`
3. restore; assert reconnect and that a new connection through the socket succeeds
4. leave a stale socket file in place; assert the unlink-and-retry path binds
5. `AllowStreamLocalForwarding no`; assert `add` refuses to persist
6. an unknown host key; assert `add` returns the fingerprint and persists nothing

**Assertions must be load-bearing.** Each guard is verified by reverting it and confirming the corresponding test fails — the standard this repo already applies.

## Delivery sequence

1. `ssh.yaml` schema, `paths.UserConfigDir()`, load/save/validate with tests
2. System-config `ssh:` section across YAML, registry, `.reg`, with round-trip tests
3. `Registry` and the CRUD API endpoints
4. CLI `ssh add` / `list` / `remove` as API clients
5. Identity adapter over `agent.Backend`
6. Host-key verifier and the 409-fingerprint handshake
7. One managed connection: dial, auth, `ListenUnix`, pump
8. Reconcile, wired to startup and the config-refresh loop
9. Backoff, keepalives, `WaitForClient` grace period
10. `ssh` block on `/api/v1/status`; CLI rendering
11. SPA page
12. Integration tests
13. Observability and docs

## Open questions

None blocking. Deferred by choice: local forwards, per-remote username, `known_hosts` interop, a Vault SSH host-CA trust path that would remove the need for a `certificate_authorities` list entirely.
