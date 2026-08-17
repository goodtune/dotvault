# Managed SSH Forwards

dotvault can maintain its own SSH connections to remote hosts and forward its web API to each of them as a Unix socket — the same shape a hand-wired `ssh -R` produces, without the external process.

## What this replaces

[`vault.token_socket`](../configuration/config-reference.md#token_socket-dotvault-to-dotvault-token-sharing) lets a headless host borrow a Vault token — and drive `browse`/`notify`/`clipboard` — from a workstation that authenticated interactively, over a socket created by an OpenSSH `RemoteForward`. That works, but the forward only exists while someone is sitting in the `ssh` session that created it. It dies with the laptop lid, a Wi-Fi handover, a VPN transition, or a remote `sshd` restart, and nothing brings it back until a human opens a new terminal. The sharpest edge is a process that outlives the session that started it — a job in `tmux`, a long-running service — which succeeds at first and then fails the moment it next needs a token, because the only socket it knew about is gone.

dotvault is already a long-lived daemon with its own SSH identity (the [SSH agent](ssh-agent.md) backend). Managed forwards let it maintain the connection itself: it reconnects on failure with backoff, and its state is inspectable via `dotvault ssh list` or the web UI, instead of depending on an external process nobody is watching.

## Preconditions

Two, and both are hard requirements — a remote whose preconditions aren't met is not an error, it just never connects (see [Runtime state](#runtime-state) below):

- **A local API surface.** The forward's target is dotvault's own web API, so something has to be listening: `api.enabled` (the per-user API socket) or `web.enabled` (the loopback web listener). When both are configured the **API socket is preferred** — it is `0600` inside a `0700` directory, whereas the TCP listener `web.enabled` controls is reachable by every uid on the box.
- **`agent.enabled`**, with at least one usable key source. The SSH identity used to authenticate to each remote is drawn from the same [agent backend](ssh-agent.md) that serves `ssh-add -l` — there is no separate credential to configure.

!!! warning "Windows: `web.enabled` is required"
    The per-user API socket (`api.enabled`) is Unix-only today. On Windows, `dotvault ssh` and the managed-forward subsystem need `web.enabled` — there is no local named-pipe equivalent of the API socket yet.

## Managing remotes

```sh
dotvault ssh add <host> [--force] [--accept-host-key] [--socket <path>] [--port N]
dotvault ssh edit <host> [--port N] [--socket <path>] [--enable|--disable]
dotvault ssh list
dotvault ssh remove <host>
```

These are thin clients of the running daemon's own web API — they do not write `ssh.yaml` directly. The identity used to verify a new remote lives in the daemon's agent backend, so only a running, authenticated daemon can perform the live dial `ssh add` requires; routing every mutation through the one service layer the web UI also uses removes any CLI-versus-daemon write race. `ssh add`, `ssh edit`, and `ssh remove` therefore always require a reachable daemon and fail clearly when there isn't one. `ssh list` degrades gracefully: when the daemon can't be reached it falls back to reading `ssh.yaml` directly and reports `unavailable` in the status column, since reading the file is safe without a daemon but writing it is not.

### `dotvault ssh add`

`add` does not persist an entry it hasn't proven works. Before writing anything to `ssh.yaml` it performs a full dry run against the target host: resolve an identity from the agent, dial and authenticate, verify the host key, probe the remote `$HOME` if the socket path needs expanding, and request the forward. Only once that succeeds does the entry get written and the daemon reconcile immediately. This catches the failures that would otherwise show up an hour later as a mute `offline` row — no agent identity, an unauthorised principal, `AllowStreamLocalForwarding no` on the remote `sshd`, a socket path in an unwritable directory.

`add` is idempotent on the host: running it again updates the existing entry rather than creating a duplicate. `--port` and `--socket` override the SSH port (default `22`) and the remote Unix socket path (default `~/.ssh/dotvault.sock`) respectively. `--force` skips the verification dial and persists the entry as given — the documented escape for registering a host that happens to be offline right now; it does not bypass the host-key confirmation on a later re-add, only the verification dial itself.

A remote whose `sshd` has `AllowStreamLocalForwarding no` cannot be managed at all — the verification dial's forward request fails outright, and `ssh add` refuses to persist the entry (`--force` doesn't help here either, since a persisted entry could never connect).

### `dotvault ssh edit`

`edit` is the CLI counterpart of the web UI's per-remote form. Only the flags you pass change — everything else keeps its current value: `--port 0` resets the port to the default `22`, `--socket ""` resets the remote socket path to the default `~/.ssh/dotvault.sock`, and `--enable`/`--disable` flip the forward without removing it. The daemon persists `ssh.yaml` and reconciles the forward immediately, so an enable or disable takes effect without a restart. Passing no change flags is refused before any request is made; on success the resulting entry is printed with defaults applied.

### `dotvault ssh list`

```
HOST                 STATUS         REMOTE SOCKET                    RECONNECTS  LAST ERROR
foo.example.com      connected      /home/me/.ssh/dotvault.sock      2           -
bar.example.com      reconnecting   /home/me/.ssh/dotvault.sock      5           connection refused
baz.example.com      host-key-error /home/me/.ssh/dotvault.sock      0           host key is not pinned and no configured CA signed it
```

The remote socket column reports the **expanded** path once known, so you see what was actually bound rather than the literal `~/`-prefixed value in `ssh.yaml`.

### `dotvault ssh remove`

Idempotent: removing a host that isn't configured prints a message and exits `0`.

### A wart worth knowing about

If a request to `dotvault ssh remove` or `dotvault ssh edit` (or a config edit) arrives over the very forward it's about to change — for example, running `ssh remove` against a host reached only through the forward being removed — the change still commits, but the connection carrying the request is dropped mid-response as that forward's old connection is torn down. Re-run the command over a different path (directly, or through a different managed forward) to confirm the result. This is inherent to changing a connection out from under the request that's using it, not a bug.

## The `ssh.yaml` file

Managed remotes are stored in a user-level file, `ssh.yaml`, a sibling of the per-user env file already documented at `~/.config/dotvault/env`. It is **never** resolved from a system location, never read from the Windows registry, and never carried by the [remote-config overlay](../configuration/remote-config.md) — those surfaces are for admin-owned policy, and which hosts you personally connect to is not that.

| OS | Path |
|----|------|
| Linux | `${XDG_CONFIG_HOME:-~/.config}/dotvault/ssh.yaml` |
| macOS | `~/Library/Application Support/dotvault/ssh.yaml` |
| Windows | `%APPDATA%\dotvault\ssh.yaml` |

```yaml
remotes:
  - host: foo.example.com
    port: 22
    remote_socket: ~/.ssh/dotvault.sock
    host_key: "ssh-ed25519 AAAA…"
    enabled: true
```

| Field | Description | Default |
|-------|-------------|---------|
| `host` | The remote's identity — `add` is idempotent on it, `remove` keys on it | — (required) |
| `port` | SSH port | `22` |
| `remote_socket` | Unix socket path bound on the remote. Absolute, or `~/`-prefixed for the remote account's home | `~/.ssh/dotvault.sock` |
| `host_key` | Pinned host key in `authorized_keys` form, written by `ssh add`. Empty when a configured certificate authority covers the host instead | — |
| `enabled` | Whether the daemon should maintain this remote | `true` |

A leading `~/` in `remote_socket` is expanded **at connect time** against the remote account's home (probed once per connection via `echo $HOME` on an exec channel), not at `add` time — so the entry stays portable if the remote account's home ever moves. `~user/`-style paths are rejected at validation, as is any path that is neither absolute nor `~/`-prefixed.

The file is written atomically at `0600` inside a `0700` directory, and unrecognised top-level keys are preserved across a rewrite so a future dotvault version's fields aren't silently dropped by an older one editing the same file. Hand-editing `ssh.yaml` is fully supported — the daemon picks up changes on the next config-refresh tick — but the daemon (via `Registry`) is the only writer dotvault itself uses; there's no lock to coordinate a second one.

## Host-key trust

There are exactly three outcomes when the daemon connects to a remote — no fourth, and critically, **no runtime trust-on-first-use**:

1. A `certificate_authorities` entry (system config, below) signs the host's certificate → accepted, nothing pinned.
2. The entry's `host_key` in `ssh.yaml` matches what the host presents → accepted.
3. Anything else → rejected, and the remote enters the terminal `host-key-error` state.

Pinning a raw host key happens exactly once, during `dotvault ssh add`, which is an explicit human gesture: the verification dial captures the key, and if no configured CA covers it, the fingerprint is printed for confirmation rather than saved automatically. On a TTY you're prompted to accept it; from a script or a non-interactive shell, pass `--accept-host-key` after verifying the printed fingerprint out of band — there's no way for a non-interactive `ssh add` to silently trust an unpinned key. **A changed host key is always a hard error, never a re-prompt** — if a previously-pinned or CA-signed host suddenly presents something different, that's the possible-MITM case, and the remote fails closed into `host-key-error` rather than asking you to confirm again.

!!! danger "A host offering a certificate needs a configured CA — there is no fallback to pinning"
    If a remote presents an SSH certificate rather than a plain host key, and no `certificate_authorities` entry validates it, the connection is **rejected outright** — it does not fall back to "pin the certificate's key and prompt like normal." This is deliberate, not an oversight: with no CA to check the certificate against there is nothing that makes it trustworthy (an expired certificate, a wrong principal, or even a user certificate presented as a host key would otherwise sail through as "just needs confirming"), and pinning the certificate's underlying key would never actually take effect on a later connection, since a certificate-bearing host is never compared against a raw pinned key. Such a host must either be covered by a `certificate_authorities` entry or be reconfigured to present a plain host key instead.

    A host already pinned to a raw key that later starts presenting a certificate hits the same wall, for the same reason: the certificate can never be validated against a raw-key pin.

!!! note "An empty `ValidPrincipals` list trusts a CA for every hostname"
    Host certificates are checked with `golang.org/x/crypto/ssh`'s standard `CertChecker`, so a certificate with an empty principals list is accepted for *any* hostname it's presented for — the same behaviour OpenSSH itself has. Practically: listing a CA in `certificate_authorities` grants it wildcard host-certificate-minting authority across your whole remote set unless every certificate it issues is scoped with explicit principals. Size your CA trust with that in mind.

### System config: `ssh:` section

The trust material — the CA list and the insecure escape hatch — lives in the **system** config (`config.yaml` or the Windows GPO registry), not in the per-user `ssh.yaml`, because it's admin-owned policy rather than "which hosts do I personally connect to":

```yaml
ssh:
  certificate_authorities:
    - "@cert-authority *.example.com ssh-ed25519 AAAA…"
  insecure_ignore_host_key: false
```

`insecure_ignore_host_key` (default `false`) disables host-key verification entirely — a security downgrade, which is exactly why it's admin-owned rather than something a user's `ssh.yaml` could flip. On a personal machine you're the admin anyway. It applies per connection attempt, so a change takes effect on the next reconnect with no daemon restart, and every single connection made under it **logs a WARN naming the host** — it can't be set once and quietly forgotten.

## The remote socket's directory

The socket's parent directory is created on the remote before the first bind, by running `mkdir -p -m 700` over an exec channel — `sshd` cannot create it as part of binding, and the default `~/.ssh` need not exist on a freshly provisioned account. A directory dotvault creates is created `0700`, since it holds a socket carrying Vault tokens (and, by default, is `~/.ssh`); a directory that already exists is left exactly as it is, permissions included. `dotvault ssh add` does the same thing, deliberately — it verifies by really binding the socket, so refusing to create the directory would make it reject hosts that are in fact perfectly forwardable. This is the only change `ssh add` makes on a remote it has not yet been told to manage.

Creating it is **best-effort**: an absolute `remote_socket` needs no exec channel at all, so a remote that permits streamlocal forwarding but forbids command execution — an `authorized_keys` `command="…"` restriction, `ForceCommand`, a restricted shell, a Windows OpenSSH account whose shell is `cmd.exe` — keeps working exactly as it did. A `mkdir` that fails is retained, not raised: the bind is attempted regardless, and if the bind succeeds the forward is healthy and the failure is only a debug log. Only when the bind *also* fails is the `mkdir` failure reported, folded into the bind error as the likely root cause (with whatever the remote wrote to stderr), and the remote's error class is `remote-socket-dir` rather than `remote-socket-bind`.

One caveat worth knowing if you nest the socket deeper than one directory: POSIX applies `-m` to the *final* operand only, so intermediate directories `-p` creates get the remote account's umask instead of `0700`. For the default `~/.ssh/dotvault.sock` there are no intermediates and the point is moot, but a `remote_socket` of, say, `~/a/b/dotvault.sock` can leave `~/a` group- or world-traversable. If that matters to you, create and mode the intermediate directories yourself; dotvault deliberately doesn't chmod path components it may not have created.

## Stale sockets

Because `x/crypto/ssh` doesn't unlink a stale socket for you and `sshd` won't bind over an existing path, a bind failure on the remote doesn't automatically mean the path is free. dotvault proves nothing it could otherwise dial is actually listening there before reclaiming it, so a live `ssh -R` session it can freely reach is never evicted out from under it. Only once that's confirmed does dotvault attempt one `rm -f` on the remote and retry the bind, once.

That probe cannot distinguish "nothing is listening" from "something is listening that this account cannot reach": a permission-restricted socket left at the same absolute path by a *different* local account would look identical to an empty path and get reclaimed. This is not currently guarded against — it's why `remote_socket` defaults under the connecting account's own home rather than a shared location, where such a collision can't arise in the first place.

## Runtime state

Each remote's live connection is one of: `connecting`, `connected`, `reconnecting`, `offline`, `authentication-error`, `host-key-error`, or `disabled` (the state when a precondition above isn't met, or the entry has `enabled: false`). `authentication-error` and `host-key-error` still retry automatically — a Vault-CA certificate can be reissued, a host key can be re-pinned by re-running `ssh add` — but from a much longer backoff floor than a plain network blip, since those conditions typically need a human to clear them.

`dotvault ssh list` and `GET /api/v1/status`'s `ssh` block both report this live state; `dotvault status` itself does not currently render it (use `ssh list` for that).

## Web UI

A CRUD API under `/api/v1/ssh/remotes` backs an equivalent page in the web UI SPA. Unlike the peer-action endpoints (`browse`/`notify`/`clipboard`), these routes are ordinary CSRF-protected mutations — the Origin-check exemption those use exists specifically because a bare `curl` over a forwarded socket can't run the issue-then-spend CSRF handshake, and both consumers of the SSH routes (the SPA and `dotvault ssh`) can.
