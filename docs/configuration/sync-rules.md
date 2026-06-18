# Sync Rules

Rules define the mapping between Vault secrets and local files. Each rule specifies which secret to read, where to write it, and how to format and merge the data.

## Rule structure

```yaml
rules:
  - name: gh                              # unique identifier
    vault_key: "gh"                        # key under user's Vault path
    target:
      path: "~/.config/gh/hosts.yml"       # local file (~ is expanded)
      format: yaml                         # output format
      template: |                          # optional Go template
        github.com:
          oauth_token: "{{ .oauth_token }}"
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique rule identifier, used in status output and state tracking |
| `vault_key` | yes | Secret key under the user's Vault path |
| `target.path` | yes | Local file path (`~` is expanded to the user's home directory) |
| `target.format` | yes | Output format: `yaml`, `json`, `ini`, `toml`, `text`, `netrc`, or `ssh_config` |
| `target.template` | no | Go template to reshape secret data before writing |

## How sync works

For each rule, on every sync cycle:

1. **Read** the secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}`
2. **Skip** if the Vault secret version is unchanged AND the target file checksum is unchanged
3. **Render** the template (if present) with the Vault data map as the dot context
4. **Parse** the rendered output through the format handler
5. **Read** the existing target file (a missing file is treated as empty, not an error)
6. **Merge** the incoming data into the existing file content
7. **Write** atomically (temp file with correct permissions, then rename)
8. **Update** state (version, timestamp, SHA-256 checksum)

Rules are isolated from each other — one rule failing does not block others.

## Merge behaviour by format

Each format has a merge strategy appropriate to its structure:

| Format | Merge strategy |
|--------|---------------|
| **YAML** | Deep merge of mapping nodes; existing keys not in incoming data are preserved |
| **JSON** | Recursive map merge; arrays are replaced wholesale |
| **INI** | Section + key merge; supports flat files (default section) |
| **TOML** | Recursive merge; supports tables, inline tables, and dotted keys |
| **Text** | Full replacement (no merge) — for private keys, certificates, etc. |
| **Netrc** | Per-entry merge by machine name; the default entry is skipped |
| **ssh_config** | Surgical directive-level merge within each `Host`/`Match` section; comments, blank lines, and unmanaged directives are preserved verbatim |

The key insight is that for structured formats (YAML, JSON, INI, TOML, netrc, ssh_config), dotvault only touches the keys it manages. A user's other settings in the same file are preserved.

### ssh_config

The `ssh_config` format manages an OpenSSH client configuration file (typically `~/.ssh/config`) as documented in `ssh_config(5)`. It is **template-only** — there is no natural mapping from raw Vault key/value pairs to ssh directives, so a rule using this format must supply a `target.template` (a rule without one fails at sync time with a clear error).

The merge is surgical at the directive level. Directives are grouped into the sections introduced by `Host` and `Match` lines (directives before the first such line form an implicit *global* section that applies to every host). Sections are matched by their criteria line (`Host *`, `Match host *.internal user deploy`, …), and within a matched section dotvault updates only the directives the template names, leaving every comment, blank line, and unmanaged directive exactly where it was. A section the template introduces but the file lacks is appended whole.

Most keywords are single-valued — a second occurrence replaces the first. Keywords that legitimately repeat (`IdentityFile`, `CertificateFile`, `LocalForward`, `RemoteForward`, `DynamicForward`, `SendEnv`, `SetEnv`, `Include`, `PermitRemoteOpen`) accumulate instead: each entry is keyed by a discriminator drawn from its arguments — the listen spec for a forward, the path for an `IdentityFile`, the variable name for a `SetEnv` — so re-syncing the same logical entry updates it in place while distinct entries coexist.

The motivating use case is a predictable, agent-forwarding SSH socket. A template such as:

```
Host *
    User {{ username }}
    RemoteForward /home/{{ username }}/.ssh/windows.sock \\.\pipe\dotvault-ssh-agent
```

keeps the `User` and the `RemoteForward` listen path stable across syncs (the `username` function resolves to the OS account dotvault runs as), so the agent forward is updated in place rather than duplicated each cycle. See [Templates](templates.md#template-functions) for the `username` function.

> **Ordering note.** ssh_config takes the *first* obtained value for each parameter. Directives placed in the global section (no `Host` block) sit at the top of the file and therefore win over any host-specific value below them — keep that in mind when choosing whether a template targets the global section or a specific `Host`/`Match` block.

## File permissions

All managed files are written with `0600` permissions (owner read/write only). Parent directories are created with `0755` if they don't exist.

All writes are atomic: dotvault writes to a temporary file with the target permissions and then renames it into place, so the target file is never in a partially-written state.

## State tracking

Sync state is persisted to `{cache_dir}/state.json` and tracks per-rule:

- Vault secret version number
- Last synced timestamp
- SHA-256 checksum of the target file

This allows dotvault to efficiently skip unchanged secrets and detect external modifications to target files.
