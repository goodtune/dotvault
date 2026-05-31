# SSH Agent

dotvault can expose an SSH agent backed by your live Vault token. Because the
daemon already holds a renewing token and reads your per-user KVv2 secrets, it
can answer signing requests without ever writing a private key to disk.

Two key sources are supported:

- **KV keys** — raw key pairs discovered under a KV path prefix (the same
  `public_key` / `private_key` schema the [SSH enrolment engine](enrolment.md)
  writes).
- **Vault-CA certificates** — short-lived certificates minted on demand by a
  Vault SSH CA secrets engine. The private key is generated in memory and never
  persisted.

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
| `agent.keys[]`       | Ordered list of key sources (see below)           | —                           |

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

- **PuTTY / Pageant (Windows):** point PuTTY's agent-pipe location at the
  dotvault pipe name (`\\.\pipe\dotvault-agent`). The same pipe serves both
  OpenSSH and PuTTY clients — the agent protocol over the pipe is identical for
  both families.

The Windows pipe is created with a security descriptor granting access only to
the owning user and LocalSystem; the Unix socket is created `0600` in a `0700`
directory. Only you can connect either way — the equivalent of dotvault's
`0600` invariant on its managed files.

## Status

The agent's listed identities, per-certificate TTL, and any per-source
resolution errors appear in `dotvault status` and on the web dashboard,
parallel to the per-rule sync state.

```
$ dotvault status
...
SSH Agent:
  endpoint: /run/user/1000/dotvault/agent.sock
  kv:ssh           SHA256:… users/alice/ssh/laptop
  vault-ca:dotvault-user  SHA256:… vault-ca:dotvault-user (cert, expires 2026-05-30T12:15:00Z)
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
