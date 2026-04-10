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
