# SSH Agent

dotvault can expose an SSH agent backed by your live Vault token. Because the
daemon already holds a renewing token and reads your per-user KVv2 secrets, it
can answer signing requests without ever writing a private key to disk.

Three key sources are supported:

- **KV keys** — raw key pairs discovered under a KV path prefix (the same
  `public_key` / `private_key` schema the [SSH enrolment engine](../services/ssh.md)
  writes).
- **Vault-CA certificates** — short-lived certificates minted on demand by a
  Vault SSH CA secrets engine. The private key is generated in memory and never
  persisted.
- **Upstream agent** — a second SSH agent (your own `ssh-agent`, the Windows
  OpenSSH agent, or Pageant) that dotvault delegates `List`/`Sign` to. dotvault
  never stores or reads its key material — it forwards the agent protocol — so
  you keep using legacy on-disk keys that already live in your personal agent
  (the static keys you've registered with GitHub, Bitbucket Server, etc.)
  alongside dotvault's Vault-backed keys, from one socket.

The agent is **read-only**: like dotvault's one-way sync, it never accepts keys,
locks, or removals from clients. `ssh-add -d`, `ssh-add -D`, and `ssh-add`
(adding) all return an error.

!!! tip "Cert mode is the recommended direction"
    With Vault-CA certificates the private key never lands on disk, rotation is
    automatic, and remote hosts trust only the CA public key
    (`TrustedUserCAKeys`) rather than per-user `authorized_keys`. The KV-key and
    file-sync paths remain supported for hosts where distributing the CA trust
    is impractical, but prefer cert mode where you can.

## Configuration

Add an `agent:` section. It is disabled by default.

```yaml
agent:
  enabled: true
  unix:
    path: ""          # default: $XDG_RUNTIME_DIR/dotvault/agent.sock
  windows:
    pipe: "\\\\.\\pipe\\dotvault-agent"
    putty: true       # also serve the Pageant-convention pipe (default true)
  keys:
    - source: kv
      path_prefix: "ssh/"          # kv/data/users/<you>/ssh/*
    - source: vault-ca
      mount: "ssh-client-signer"
      role: "dotvault-user"
      principals: ["{{.vault_username}}"]
      ttl: "15m"
      ephemeral_key: true
    - source: agent
      socket: ""                   # default: $XDG_RUNTIME_DIR/ssh-agent.socket
      # pipe: "\\\\.\\pipe\\openssh-ssh-agent"   # Windows upstream agent
```

| Field                | Description                                       | Default                     |
|----------------------|---------------------------------------------------|-----------------------------|
| `agent.enabled`      | Master switch for the agent listener              | `false`                     |
| `agent.unix.path`    | Unix socket path                                  | per-user runtime path       |
| `agent.windows.pipe` | Windows pipe name                                 | `\\.\pipe\dotvault-agent`   |
| `agent.windows.putty` | Also serve a Pageant-convention pipe (Windows)   | `true`                      |
| `agent.keys[]`       | Ordered list of key sources (see below)           | —                           |

On Windows, the entire `agent` section can be deployed via Group Policy / the
registry under `HKLM\SOFTWARE\Policies\goodtune\dotvault\Agent` instead of YAML
— including the ordered `keys[]` list, which is stored as numbered subkeys
(`Agent\Keys\0`, `\1`, …). Author the registry values directly, or generate them
from a YAML file with `dotvault reg-import config.yaml` (and recover YAML from a
`.reg` with `dotvault reg-export`). When the registry policy keys exist, they
take precedence and the YAML file is ignored.

### KV source

`source: kv` with an optional `path_prefix`, resolved under
`kv/data/users/<you>/`. Every secret beneath the prefix is treated as a key
pair (`public_key` in authorized-keys form, `private_key` as an OpenSSH PEM).
Keys are *discovered*, not declared — a secret appearing or disappearing in
Vault changes the agent's identities on the next `ssh-add -l` without a restart.

#### Passphrases and KV keys

A passphrase protects a private key **at rest on disk**. In agent mode the key
is never written to a filesystem — it lives encrypted at rest in Vault, gated by
your token policy, and is read and signed with in-process — so the passphrase
is redundant here, and the headless daemon has no way to prompt to decrypt one.
Enrol KV keys destined for the agent with `passphrase: unsafe`: the name is a
misnomer in this context, because Vault is the at-rest protection. The standing
assumption is that you **never exfiltrate the secret to disk** (no parallel
file-sync rule for the same key, no `vault kv get … > id_ed25519`); if you do,
you reintroduce the at-rest exposure a passphrase would have covered, so encrypt
it then — see [Choosing a mode](../services/ssh.md#choosing-a-mode-it-depends-on-how-the-key-is-consumed).

The agent therefore rejects a passphrase-encrypted KV key at signing time rather
than silently failing. Store agent keys unencrypted in Vault, or prefer cert
mode (no key material at all).

### Vault-CA source

`source: vault-ca` with the SSH CA secrets-engine `mount`, a `role`, templated
`principals` (e.g. `{{.vault_username}}`), a `ttl`, and `ephemeral_key: true`.
dotvault generates an in-memory key pair at startup and requests a certificate
from Vault at signing time. Certificates are cached until shortly before expiry
and transparently re-minted on the next request — including over a forwarded
agent connection, so long-lived forwarded session chains keep working.

### Upstream-agent source

`source: agent` points dotvault at a *second* SSH agent and delegates the
`List` and `Sign` requests to it. This is how you keep using legacy keys that
live on disk and are already held by your personal agent — for example a static
key you've registered with a service that can't take a short-lived cert — while
still serving dotvault's Vault-backed keys from the same socket. dotvault is a
pure proxy here: it never stores, reads, or persists the upstream's private
keys, and it dials a fresh connection per request so the upstream agent can come
and go without a dotvault restart.

The upstream endpoint is the other agent's socket (Unix) or named pipe
(Windows):

```yaml
- source: agent
  socket: ""    # Unix; default $XDG_RUNTIME_DIR/ssh-agent.socket
                # (required explicitly on macOS — no XDG_RUNTIME_DIR there)
  pipe: ""      # Windows; default \\.\pipe\openssh-ssh-agent
```

| Field    | Platform | Description                          | Default                                       |
|----------|----------|--------------------------------------|-----------------------------------------------|
| `socket` | Unix     | Upstream agent Unix socket path      | `$XDG_RUNTIME_DIR/ssh-agent.socket` (Linux)¹  |
| `pipe`   | Windows  | Upstream agent named pipe            | `\\.\pipe\openssh-ssh-agent`                  |

¹ The Unix default only exists when `XDG_RUNTIME_DIR` is set — the norm on
Linux, but **not on macOS**, where it is typically unset. With no
`XDG_RUNTIME_DIR` and no explicit `socket`, the upstream-agent source resolves
to an error (reported in status) rather than a bogus path, so macOS users must
set `socket` explicitly (e.g. the value of `$SSH_AUTH_SOCK`, or a fixed path).

Both accept `{{.username}}` and `{{.uid}}` template variables, so a fleet-wide
config can resolve to each user's own agent (e.g.
`socket: "/run/user/{{.uid}}/ssh-agent.socket"`). `{{.username}}` is the bare OS
account name; `{{.uid}}` is the numeric UID on Unix (and the user's SID on
Windows, where it is rarely useful in a pipe name). A mis-typed variable
(e.g. `{{.user}}`) is rejected when the source is constructed, not silently left
in the path. A leading `~` in a socket path is expanded to your home directory.
The Unix default keeps the upstream socket in the same XDG runtime directory
dotvault's own socket lives in.

Two constraints apply:

- **At most one upstream-agent source.** An agent advertises *all* of its
  identities with no path scoping, so a second one would only fan out
  redundantly and make `Sign` routing ambiguous. Configure one; it surfaces
  every key the upstream holds.
- **No self-reference.** dotvault refuses to delegate to its own endpoint — that
  would loop `List`/`Sign` back into the daemon forever. If the resolved
  upstream endpoint equals dotvault's own socket/pipe, the source is reported as
  an error in status (see below) and contributes no keys, while the other
  sources keep working.

If the upstream agent isn't running, its source simply contributes no
identities (and shows an "unreachable" error in the web dashboard); dotvault's
other sources are unaffected.

## Pointing clients at the agent

dotvault claims its **own** endpoint everywhere and never sets `SSH_AUTH_SOCK`
or any PuTTY registry value on your behalf — wiring clients to it is the
integration step, left to you (or your fleet tooling).

- **OpenSSH (all platforms):** set `SSH_AUTH_SOCK` to the socket path (Unix) or
  pipe name (Windows). Windows OpenSSH honours `SSH_AUTH_SOCK` pointing at a
  named pipe.

  ```sh
  export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/dotvault/agent.sock"
  ssh-add -l   # list the identities dotvault is serving
  ```

- **PuTTY / Pageant (Windows):** modern PuTTY-family clients (PuTTY 0.71+,
  WinSCP, FileZilla, …) locate Pageant over a named pipe whose name follows a
  fixed convention — `\\.\pipe\pageant.<user>.<hash>` — that they compute
  themselves and cannot be told to ignore. So that those clients find the agent
  with **no configuration at all**, dotvault serves a second listener on exactly
  that pipe whenever `agent.windows.putty` is true (the default). A named pipe
  carries a single name, so this is a parallel listener over the same backend,
  not an alias of `agent.windows.pipe`. Both pipes serve the identical agent
  protocol. Set `putty: false` to serve only `agent.windows.pipe` (e.g. when a
  separate Pageant is already running and you don't want dotvault to claim that
  name). The option only takes effect when `agent.enabled` is true and is a
  no-op off Windows.

  Clients that let you point at an explicit pipe (or Windows OpenSSH via
  `SSH_AUTH_SOCK`) can still target `\\.\pipe\dotvault-agent` directly.

The Windows pipe(s) are created with a security descriptor granting access only
to the owning user and LocalSystem; the Unix socket is created `0600` in a
`0700` directory. Only you can connect either way — the equivalent of
dotvault's `0600` invariant on its managed files.

## Status

When the agent is enabled, `dotvault status` connects to the running daemon's
socket / pipe and lists the identities it is actually serving — the `ssh-add -l`
equivalent, spoken over the agent protocol. Because it queries the live daemon
rather than re-deriving anything from config, the output reflects exactly what
the agent offers: the keys currently discoverable in Vault and, for cert
sources, the daemon's cached certificate with its **true remaining validity**.
`dotvault status` is a read-only client here — it never creates the endpoint.

The same identities appear on the web dashboard, parallel to the per-rule sync
state. The dashboard additionally groups them **by source** and shows per-source
resolution errors (an unknown engine, a Vault read failure, a missing CA role) —
detail the CLI can't show, because it lists identities over the agent protocol,
which carries no notion of which configured source produced each one. For
"why is this source not resolving?", consult the dashboard.

```
$ dotvault status
...
SSH Agent:
  endpoint: /run/user/1000/dotvault/agent.sock
  SHA256:… users/alice/ssh/laptop
  SHA256:… dotvault-user (cert, expires 2026-05-30T12:15:00Z)
```

Because the agent is only relevant when configured, `dotvault status` consults
the endpoint only when `agent.enabled` is set. A failure to connect in that case
is reported as unexpected — it means the daemon isn't running, or hasn't
authenticated far enough to start the listener:

```
$ dotvault status
...
SSH Agent:
  endpoint: /run/user/1000/dotvault/agent.sock
  unreachable: dial unix /run/user/1000/dotvault/agent.sock: connect: no such file or directory
  (agent is enabled but the daemon is not serving this endpoint — is `dotvault run` active?)
```

## Server-side prerequisite for cert mode

Each host you connect to trusts the Vault SSH CA by pointing `sshd` at the CA
public key:

```
TrustedUserCAKeys /etc/ssh/vault_ca.pub
```

The CA public key comes from the SSH CA secrets engine
(`<mount>/config/ca`, `public_key` field). Distributing that one file is the
entire server-side cost of cert mode and is handled by your existing fleet
config tooling (Nix/Ansible/etc.).

## Security notes

!!! warning "Agent forwarding exposes a signing oracle"
    Anyone with root on a host you forward your agent to can use the forwarded
    socket to sign *as you* for the life of the session (they cannot extract the
    key). Cert mode with short TTLs and scoped `valid_principals` bounds the
    blast radius. `ProxyJump` avoids forwarding entirely where topology allows
    and is the preferred pattern.

- **Token-refresh interaction.** If the Vault token is mid-reauthentication when
  a signing request arrives, the agent blocks briefly on the lifecycle manager
  rather than failing, then signs once a usable token is available (up to a
  bounded timeout).
- **Concurrency.** The backend is safe for concurrent use — two clients may
  request signatures simultaneously, and identity listings are cached for a few
  seconds to avoid hammering Vault on repeated `ssh-add -l`.
