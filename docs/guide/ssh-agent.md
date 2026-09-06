# SSH Agent

dotvault can expose an SSH agent backed by your live Vault token. Because the
daemon already holds a renewing token and reads your per-user KVv2 secrets, it
can answer signing requests without ever writing a private key to disk.

Two key sources are configured under `agent.keys[]`, and a third — the **SSH
agent relay** — is always present unless you turn it off:

- **KV keys** — raw key pairs discovered under a KV path prefix (the same
  `public_key` / `private_key` schema the [SSH enrolment engine](../services/ssh.md)
  writes).
- **Vault-CA certificates** — short-lived certificates minted on demand by a
  Vault SSH CA secrets engine. The private key is generated in memory and never
  persisted.
- **The SSH agent relay** (implicit, on by default) — the SSH agents you already run:
  your own `ssh-agent`, a
  keyring daemon, gpg-agent, a password manager's agent, the Windows OpenSSH
  agent, Pageant) that dotvault sits in front of and proxies to. dotvault never
  stores or reads their key material — it forwards the agent protocol — so you
  keep using legacy on-disk keys that already live in your personal agent (the
  static keys you've registered with GitHub, Bitbucket Server, etc.) alongside
  dotvault's Vault-backed keys, from one socket. It **auto-detects** them and
  is **always tried last**, after your configured key sources — you do not
  declare it, and `agent.relay.enabled: false` is the one way to switch it off.

dotvault's **own** identities are read-only, mirroring its one-way sync: they
come from Vault and are never added, removed, or locked by a client. Because
the relay is on by default, `ssh-add`, `ssh-add -d` and `ssh-add -D` are
[forwarded to the agent underneath](#adding-keys-through-dotvault) rather than
refused — they do to your own agent exactly what they would have done had you
addressed it directly. With `relay.enabled: false` there is nowhere to forward
them, so the whole agent is read-only and all three return an error.

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
  relay:
    enabled: true   # default; the only way to disable the relay
    socket: ""      # Unix; empty = auto-detect (recommended)
    pipe: ""        # Windows; empty = auto-detect (recommended)
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
```

| Field                | Description                                       | Default                     |
|----------------------|---------------------------------------------------|-----------------------------|
| `agent.enabled`      | Master switch for the agent listener              | `false`                     |
| `agent.unix.path`    | Unix socket path                                  | per-user runtime path       |
| `agent.windows.pipe` | Windows pipe name                                 | `\\.\pipe\dotvault-agent`   |
| `agent.windows.putty` | Also serve a Pageant-convention pipe (Windows)   | `true`                      |
| `agent.relay.enabled` | Proxy to the SSH agents you already run          | `true`                      |
| `agent.relay.socket` | Pin the relay to one Unix socket instead of detecting | *(empty = auto-detect)* |
| `agent.relay.pipe`   | Pin the relay to one Windows pipe instead of detecting | *(empty = auto-detect)* |
| `agent.keys[]`       | Ordered list of Vault-backed key sources (see below) | —                        |

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

The `ssh-add -l` comment for a vault-ca identity is `vault-ca:<role> - by
dotvault for <user>`, naming both the configured role and the local OS user
the daemon runs as — the same value `{{.vault_username}}` expands to. That is
handy when comparing identities across more than one user's agent (e.g. a
forwarded connection, or a shared host running multiple per-user daemons).
Note the comment can contain spaces, since a Windows local account name can,
so don't split `ssh-add -l` output on whitespace to recover it.

### The SSH agent relay

The relay puts dotvault **in front of** the SSH agents you already run and
proxies the agent protocol to them. It is not something you configure into
`agent.keys[]` — it is implicit, on whenever the agent is, and always tried
**last**, after every key source you did configure.

Last is deliberate: an ssh client works down the advertised list against the
server's `MaxAuthTries` budget, so dotvault's own identities get the first
attempts and the shadowed agents fill in behind them.

On by default is also deliberate. "Point every SSH client at dotvault once and
leave it there" only holds if the keys you already had keep working without you
having to ask; an arrangement that silently drops half your keys unless you
found the right config stanza is not one you can adopt wholesale. So the single
supported way to not have it is to say so — `agent.relay.enabled: false`.

This is what keeps legacy keys working: a static key registered with a service
that can't take a short-lived cert, a key in a password manager's agent, a
Secure Enclave key — all served from the same socket as your Vault-backed
ones.

dotvault is a pure proxy here: it never stores, reads, or persists the
upstream's private keys, and it dials a fresh connection per request so an
upstream agent can come and go without a dotvault restart.

#### Auto-detection (the default)

Leave `relay.socket`/`relay.pipe` empty — the recommended setting — and
dotvault finds your agents itself:

```yaml
agent:
  enabled: true
  # relay.enabled defaults to true; nothing to write here at all
```

On every identity refresh dotvault re-scans the well-known agent locations for
the platform and proxies to every one that is a socket owned by your own
account. Because the scan is repeated rather than resolved once at startup, an
agent you start, restart, or forward in mid-session is picked up on the next
request — no config change, no daemon restart.

What it looks at, in priority order:

| Order | Unix                                                                  | Windows                                       |
|-------|-----------------------------------------------------------------------|-----------------------------------------------|
| 1     | `$SSH_AUTH_SOCK`                                                      | `$SSH_AUTH_SOCK` (Git-for-Windows / WSL set this) |
| 2     | `$XDG_RUNTIME_DIR/ssh-agent.socket` (systemd `ssh-agent.service`)      | `\\.\pipe\openssh-ssh-agent` (OpenSSH agent service) |
| 3     | `$XDG_RUNTIME_DIR/gcr/ssh`, `.../keyring/ssh` (GNOME keyring)          | the Pageant-convention pipe                   |
| 4     | `$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh`, `~/.gnupg/S.gpg-agent.ssh`   | —                                             |
| 5     | `~/.1password/agent.sock`; on macOS 1Password's group container and Secretive | —                                     |
| 6     | `/tmp/ssh-*/agent.*` (a plain `ssh-agent` fork); on macOS the launchd socket and `$TMPDIR` equivalents | — |

On Linux the runtime-dir entries are also looked for under `/run/user/<uid>`
when `XDG_RUNTIME_DIR` is unset, which is the usual state for a daemon started
outside a login session.

Two things bound the scan:

- **Ownership.** On **Linux and macOS** every connection to a discovered agent
  is checked against the *peer's* uid (`SO_PEERCRED` / `LOCAL_PEERCRED`) — the
  kernel's answer about the process on the other end, not about the path it was
  reached through. That distinction matters because paths can be swapped: a
  candidate under the globbed `/tmp` patterns could otherwise be pointed at
  your real agent to pass a path check and re-pointed before the dial. Since
  mutations are forwarded (see below), the endpoint that won that race would
  receive the private key from your `ssh-add`. A path-level socket-and-owner
  check still runs first as a cheap filter, and it follows symlinks — the tmux
  `~/.ssh/ssh_auth_sock` convention and 1Password's documented symlink on macOS
  are both symlinks, and refusing to follow them would hide the very agent you
  most want found.

    !!! warning "Only Linux and macOS have the peer check"
        Every other platform falls back to the path-level socket-and-owner
        check alone, which is weaker: it follows symlinks, so it establishes
        who owns the target *now* and cannot rule out the path being re-pointed
        before the dial. That covers Windows and also the other Unix platforms
        dotvault can be built for (the BSDs, illumos) — supported builds are
        Linux, macOS and Windows, but if you build elsewhere, this is what you
        get until a `peerUID` implementation is added for it. On any
        multi-user host in that group, the honest advice is
        `relay.enabled: false` — pinning `relay.socket`/`relay.pipe` fixes
        *which* endpoint is dialled
        but verifies nothing about who answers, and on Unix it also switches
        off the peer check auto-detection would have performed (the daemon logs
        a WARN when you pin one, for that reason).

        Windows additionally has no peer check *available* — a named pipe
        carries no owner a caller can read without opening it and querying its
        security descriptor — so detection there is a short fixed list. Be
        clear about what that does and does not buy: pipes are
        first-creator-wins, so a local user who creates
        `\\.\pipe\openssh-ssh-agent` before the OpenSSH agent service starts
        owns that name for the boot, and the Pageant name's per-boot hash is
        derived with `CryptProtectMemory(CROSS_PROCESS)`, which any process on
        the machine can reverse. This is the same trust model Windows
        OpenSSH's own `ssh.exe` and every PuTTY client already operate under
        when they dial those names — dotvault inherits that exposure rather
        than widening it. The daemon logs a WARN at startup saying so, because
        the relay is on by default and `ssh-add` through it deposits a private
        key at whatever answers.

        **Pinning `relay.pipe` is not a mitigation for this.** Naming the pipe
        yourself decides which endpoint is dialled, never who is listening on
        it — a squatted `\\.\pipe\openssh-ssh-agent` is reached identically
        whether the name came from detection or from your config. On a
        multi-user Windows host the control is `relay.enabled: false`.
- **Never itself.** dotvault refuses to delegate to an endpoint it serves,
  which would loop `List`/`Sign` back into the daemon forever. It checks the
  paths *and* asks each candidate over the wire whether it is this daemon (a
  private agent extension). The second check is the one that matters in
  practice: once you set `SSH_AUTH_SOCK` to dotvault — the whole point — the
  top candidate *is* dotvault, often reached by a symlink, bind mount, or
  forwarded socket that no path comparison would catch.

If several agents advertise the same key it is listed once, attributed to the
first, so a client doesn't burn two of a server's `MaxAuthTries` attempts on
one key. If one agent is unreachable the others still answer. If none is
running, the source simply contributes nothing — that is not an error.

The endpoints currently being shadowed are reported per source as `upstreams`
on `GET /api/v1/status` — the machine-readable answer to "what did detection
actually find?". The field distinguishes three cases, because "found nothing"
and "reports no upstreams at all" are different answers: it is absent on a
source with no upstreams to report, `[]` on a relay that found no agent to
shadow, and a list of endpoints otherwise. Key off the field rather than the
source's `type`, which does not imply it — a relay that failed to construct is
reported with `type: agent` and no `upstreams`. The endpoints are not rendered
in the web UI today; `dotvault status` lists the identities being served but
not which agent each came from.

#### Turning it off, or pinning one endpoint

Turning it off leaves the agent with only what you configured, so
`relay.enabled: false` needs at least one `agent.keys[]` entry — an agent that
can serve nothing is refused at config load rather than started as a listener
that only ever answers "no identities":

```yaml
agent:
  enabled: true
  relay:
    enabled: false             # no relay at all
  keys:
    - source: kv
      path_prefix: "ssh/"      # required: nothing else is left to serve
```

Pinning keeps the relay but stops it detecting:

```yaml
agent:
  enabled: true
  relay:
    socket: /run/user/{{.uid}}/ssh-agent.socket   # Unix: pin one agent
    pipe: \\.\pipe\openssh-ssh-agent               # Windows: pin one agent
```

| Field                | Platform | Description                              | Default                 |
|----------------------|----------|------------------------------------------|-------------------------|
| `agent.relay.enabled` | all     | Proxy to the agents you already run      | `true`                  |
| `agent.relay.socket` | Unix     | Pin the relay to this socket             | *(empty = auto-detect)* |
| `agent.relay.pipe`   | Windows  | Pin the relay to this named pipe         | *(empty = auto-detect)* |

Naming an endpoint **disables** detection for that platform and pins the relay
to exactly that one. It is the escape hatch for an agent at a path detection
doesn't know — it is **not** a security control, and it is not the answer on a
multi-user host (see the warning above): it decides which endpoint is dialled,
not who answers, and on Unix it gives up the peer-ownership check detection
performs. The daemon logs a WARN when you pin one.

Like `windows.putty`, all three are inert rather than rejected when
`agent.enabled` is false, so you can stage a config before switching the agent
on.

Only the field matching the running platform is consulted, so a single config
can carry both for a mixed fleet. Both accept `{{.username}}` and `{{.uid}}`
template variables, so a fleet-wide config can resolve to each user's own
agent (e.g. `relay.socket: "/run/user/{{.uid}}/ssh-agent.socket"`).
`{{.username}}` is the bare OS account name; `{{.uid}}` is the numeric UID on
Unix (and the user's SID on Windows, where it is rarely useful in a pipe
name). A mis-typed variable (e.g. `{{.user}}`) is rejected when the source is
constructed, not silently left in the path. A leading `~` in a socket path is
expanded to your home directory.

An endpoint that can't be resolved — a bad template, or a path equal to
dotvault's own socket — becomes an error reported in status; the other sources
keep working.

#### Adding keys through dotvault

Because dotvault sits in front of your agent rather than beside it, the
mutating agent operations are **forwarded upstream** instead of refused:

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/dotvault/agent.sock"
ssh-add ~/.ssh/id_ed25519    # lands in your own agent, via dotvault
ssh-add -l                   # lists it alongside dotvault's Vault-backed keys
ssh-add -d ~/.ssh/id_ed25519 # removes it from your agent
ssh-add -D                   # clears your agent (not dotvault's Vault keys)
ssh-add -x / -X              # locks / unlocks your agent
```

dotvault stores nothing on this path either: the key goes straight out over the
upstream connection and no copy is retained. Details worth knowing:

- **`ssh-add` targets one agent, not all of them.** The key goes to the
  most-preferred endpoint — `$SSH_AUTH_SOCK` when it names a real upstream,
  otherwise the first discovered. Copying a private key into every agent on the
  machine is not what you asked for and not something you could easily undo.
- **`-D`, `-x`, `-X` are agent-wide** and do address every shadowed agent, which
  is what a client locking "the agent" means.
- **dotvault's own identities are untouched.** They come from Vault and would
  return regardless, so `ssh-add -d` against a Vault-backed key is refused
  rather than silently doing nothing.
- **With `relay.enabled: false` the whole agent is read-only:** there is
  nowhere to forward a mutation to, so `ssh-add`, `ssh-add -d`, `-D`, `-x` and
  `-X` all return an error. That is the only configuration in which they do.
- **No Vault token is needed.** These operations touch no Vault-backed source,
  so `ssh-add` works against a daemon that hasn't authenticated yet. The same
  is true of listing and signing *upstream* keys: a daemon that cannot reach
  Vault still serves the agents it shadows, so an outage doesn't take your
  legacy keys down with the Vault-backed ones.
- **Check where `$SSH_AUTH_SOCK` points before adding a key.** `ssh-add`
  targets the most-preferred endpoint, which is `$SSH_AUTH_SOCK` when it names
  a real upstream — and on a host you reached with `ssh -A`, that is the
  *forwarded* agent on your workstation, so the key would leave this machine.
  `dotvault status` and the `upstreams` field show what is being shadowed.
- **`ssh-add -x` sends the passphrase to every shadowed agent.** Locking is
  agent-wide by definition, so with several agents detected the one passphrase
  reaches all of them.

Agent *extensions* are deliberately not proxied. Some are connection-scoped by
design — OpenSSH's `session-bind@openssh.com` binds the client's own
connection — and answering one from a proxied connection to a different agent
would be a lie about what was bound. Clients treat the refusal as "unsupported"
and carry on.

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

    !!! tip "Surviving daemon restarts (Linux)"
        The packaged `dotvault-agent.socket` unit (optional, not enabled by default) lets systemd bind this socket and hold the fd across daemon restarts, so an `ssh` launched mid-restart queues briefly instead of failing. The queue is bounded by startup, not by authentication: the daemon serves the agent before it holds a Vault token (see [Before the daemon has authenticated](#before-the-daemon-has-authenticated)). `agent.enabled` remains required, and under activation the unit's `ListenStream=` path wins over `agent.unix.path`. See [Socket activation](../admin/deployment.md#socket-activation-optional).

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
  SHA256:… vault-ca:dotvault-user - by dotvault for alice (cert, expires 2026-05-30T12:15:00Z)
```

Because the agent is only relevant when configured, `dotvault status` consults
the endpoint only when `agent.enabled` is set. A failure to reach it is
reported as unexpected — it means the daemon isn't running, or is not yet
serving this endpoint:

```
$ dotvault status
...
SSH Agent:
  endpoint: /run/user/1000/dotvault/agent.sock
  unreachable: dial unix /run/user/1000/dotvault/agent.sock: connect: no such file or directory
  (agent is enabled but the daemon is not serving this endpoint — is `dotvault run` active?)
```

A daemon that *is* serving but cannot resolve any identity right now reports
that separately, because the two send you looking in completely different
places. The usual cause is a `vault-ca` source unable to mint for a moment,
often while the daemon replaces its own Vault token — check the per-source
errors on the web dashboard, or simply retry:

```
$ dotvault status
...
SSH Agent:
  endpoint: /run/user/1000/dotvault/agent.sock
  serving, but no identities could be resolved: agent could not list identities: ssh agent: ca: mint certificate: permission denied
  (check the per-source errors on the web dashboard, or retry — a source may be mid-recovery)
```

Note this is distinct from the empty list below: an empty list means the agent
has nothing to offer and says so cleanly, where this means it could not find
out.

### Before the daemon has authenticated

The daemon starts serving the agent early, *before* it obtains a Vault token,
so a client always gets an answer. Until a token arrives the agent has no
identities to offer, which `dotvault status` reports as:

```
$ dotvault status
Auth: not authenticated (no local token; no peer socket holds a token)
...
SSH Agent:
  endpoint: /run/user/1000/dotvault/agent.sock
  (no identities loaded — the daemon holds no Vault token yet, or no configured key source resolved one)
```

(A source that *failed* is not folded into this line — that is the "serving,
but no identities could be resolved" case above.)

`ssh` sees the same empty list and moves straight on to its next
authentication method. A signing request in that window is refused rather than
held — the agent protocol carries only an opaque failure, so the client reports
something like `agent refused operation` and the reason appears in the daemon's
own log:

```
ssh agent: dotvault holds no vault token (not authenticated); run `dotvault login`
```

Fix the `Auth:` line — run `dotvault login`, or make a peer socket reachable —
and the identities appear without restarting anything.

This matters most under [socket activation](../admin/deployment.md#socket-activation-optional),
where systemd binds the socket at boot and the kernel completes `connect()`
into its backlog whether or not the daemon is accepting yet. Serving early
keeps that queue to the length of startup itself. A host that can never obtain
a token — nothing local and no peer to borrow from — would otherwise leave
every `ssh` and every `dotvault status` blocked indefinitely on a connection
that had been made and would never be read.

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

- **Token-refresh interaction.** If the Vault token is being replaced when a
  request arrives, the agent blocks briefly on the lifecycle manager rather
  than failing, then proceeds once a usable token is available (up to a bounded
  timeout). This covers *listing* as well as signing: a client asks the agent
  what identities it has before choosing a key, so rebuilding that list from a
  half-replaced token is where a connection is actually lost. It also covers
  the replacements that succeed — a certificate-auth daemon renewing its own
  token unattended holds the gate for the few hundred milliseconds the mint and
  login take, so callers wait it out instead of racing it. A listing that needs
  no Vault call is still answered immediately: a cached list inside its window,
  or the empty list the daemon owes before it has authenticated (see "Before
  the daemon has authenticated" above), never waits.
- **A source that errors is not silently empty.** With several `agent.keys[]`
  sources configured, one that fails to list is skipped and the rest are still
  advertised. If *every* source fails, the agent reports an error rather than
  an empty list, because "the credential source hit a transient problem" and
  "no keys are configured" call for opposite responses from a client — the
  first is worth retrying in a moment, the second is not. A listing taken while
  any source was failing is also not cached, so a retry sees the source the
  moment it recovers rather than waiting out the cache window.
- **Concurrency.** The backend is safe for concurrent use — two clients may
  request signatures simultaneously, and identity listings are cached for a few
  seconds to avoid hammering Vault on repeated `ssh-add -l`.
- **Per-source isolation on signing.** With multiple `agent.keys[]` sources
  configured, a source that currently can't produce a signature (e.g. a
  `vault-ca` role that doesn't resolve under your active Vault auth method)
  never blocks signing for a key owned by a different, healthy source. If `ssh`
  fails with `agent refused operation` even though `ssh-add -L` lists a valid,
  non-expired identity, check `dotvault status` or the web dashboard for a
  per-source error against one of your *other* configured sources.
