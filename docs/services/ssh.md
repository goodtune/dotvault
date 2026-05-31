# SSH Key Onboarding

The `ssh` enrolment engine generates Ed25519 SSH key pairs in OpenSSH format. The private key can optionally be encrypted with a passphrase. The generated keys are stored in Vault, then synced to local files by the sync engine.

## Configuration

### Minimal

```yaml
enrolments:
  ssh:
    engine: ssh

rules:
  - name: ssh-private-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519"
      format: text
      template: "{{ .private_key }}"

  - name: ssh-public-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519.pub"
      format: text
      template: "{{ .public_key }}"
```

### With custom settings

```yaml
enrolments:
  ssh:
    engine: ssh
    settings:
      passphrase: recommended    # prompt for passphrase but allow skipping
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `passphrase` | `required` | Passphrase mode: `required`, `recommended`, or `unsafe` |

### Passphrase modes

| Mode | Behaviour |
|------|-----------|
| `required` | User must provide a passphrase; enrolment fails if empty |
| `recommended` | User is prompted but can press Enter to skip |
| `unsafe` | No passphrase prompt; private key is stored unencrypted |

### Choosing a mode: it depends on how the key is consumed

The passphrase protects the private key **at rest on disk**. So the right mode
depends entirely on whether the key ever lands on a filesystem:

- **File-sync mode** (a sync rule writes the private key to `~/.ssh/…` via
  `format: text`): the key sits on disk, where it can be read by a stolen
  laptop, a backup, or any process running as you. **Encourage a passphrase**
  (`required`) — it is the only thing protecting the key at rest, exactly as it
  would for a hand-generated `ssh-keygen` key.

- **Agent mode** (the [SSH agent](../guide/ssh-agent.md) reads the key from
  Vault on demand and signs in-process — the key is never written to a
  filesystem): the at-rest protection is **Vault**, not the passphrase. The
  daemon is headless and cannot prompt to decrypt, so a passphrase-encrypted key
  cannot be used by the agent at all. Use **`unsafe`**. Despite the name it is
  *not* unsafe here: the secret is encrypted at rest in Vault and gated by your
  token policy. The one assumption is that **you never exfiltrate the secret to
  disk** (e.g. don't also add a file-sync rule for the same key, and don't
  `vault kv get … > id_ed25519`) — doing so silently reintroduces the at-rest
  exposure that the passphrase would have covered.

In short: a passphrase on a key that also lives unencrypted in Vault and gets
used by the agent adds friction with no security gain; a passphrase on a key
written to disk is essential.

#### Minimum safe example — file-sync mode (passphrase required)

```yaml
enrolments:
  ssh:
    engine: ssh
    settings:
      passphrase: required        # key lands on disk — protect it at rest

rules:
  - name: ssh-private-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519"
      format: text
      template: "{{ .private_key }}"
  - name: ssh-public-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519.pub"
      format: text
      template: "{{ .public_key }}"
```

#### Minimum safe example — agent mode (unsafe, key never on disk)

```yaml
enrolments:
  ssh:
    engine: ssh
    settings:
      passphrase: unsafe          # Vault is the at-rest protection; agent can't prompt

agent:
  enabled: true
  keys:
    - source: kv
      path_prefix: "ssh/"         # kv/data/users/<you>/ssh/*
# Note: deliberately NO sync rule writing the private key to disk.
```

## How key generation works

1. dotvault generates an Ed25519 key pair using Go's `crypto/ed25519`
2. The user is prompted for a passphrase (unless mode is `unsafe`)
3. If a passphrase is provided, the user must confirm it by entering it a second time
4. The private key is marshalled to OpenSSH PEM format (encrypted if a passphrase was given)
5. The public key is marshalled to `authorized_keys` format with a `{username}@dotvault` comment
6. Both keys are written to Vault

### Terminal output

```
Enter passphrase:
Confirm passphrase:
✓ SSH key generated!
```

## Credentials stored in Vault

The engine writes these fields to the Vault KV secret:

| Field | Description |
|-------|-------------|
| `public_key` | SSH public key in `authorized_keys` format (`ssh-ed25519 ... user@dotvault`) |
| `private_key` | OpenSSH PEM-formatted private key (optionally passphrase-encrypted) |

## Combining enrolment with sync

A typical setup pairs the enrolment with sync rules so the workflow is:

1. User starts dotvault for the first time
2. dotvault checks Vault for `users/{username}/ssh` — it's empty
3. The enrolment wizard generates an Ed25519 key pair
4. Credentials are written to Vault
5. Sync rules write the private and public keys to `~/.ssh/`
6. The user can add the public key to services like GitHub, GitLab, or remote hosts

On subsequent starts, the enrolment check finds the keys already present and skips the flow.

The `text` format handler uses full replacement (no merge), which is the correct behaviour for key files — each key file should contain exactly one key.
