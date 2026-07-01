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
| `vault_key` | no | Secret key under the user's Vault path. Omit it for a [keyless rule](#rules-without-a-vault-key) that manages a file with no Vault content |
| `target.path` | yes | Local file path (`~` is expanded to the user's home directory) |
| `target.format` | yes | Output format: `yaml`, `json`, `ini`, `toml`, `text`, `netrc`, or `ssh_config` |
| `target.template` | conditional | Go template to reshape secret data before writing. Required when `vault_key` is omitted (a keyless rule has no secret data to fall back on) |

## Rules without a Vault key

`vault_key` is optional. A rule that omits it is **keyless**: dotvault never contacts Vault for that rule, renders its template with an empty data context, and writes the result like any other rule. This is the natural shape for a file that has no secrets in it at all — the motivating case is an `~/.ssh/config` whose only dynamic part is the OS username:

```yaml
rules:
  - name: dotvault-forward
    target:
      path: "~/.ssh/config"
      format: ssh_config
      template: |
        Host *
            User {{ username }}
            RemoteForward /home/{{ username }}/.ssh/dotvault.sock 127.0.0.1:8200
```

Because the rule has no `vault_key`, the `{{ .field }}` dot context is empty — a template that references a secret field would render `<no value>`. The [`username` function](templates.md#template-functions) still resolves, because it is a template function rather than a context field, so per-user paths work without any Vault data. A keyless rule therefore **must** carry a `target.template`: without secret data and without a template there is nothing to write, and config load rejects it.

Everything else about a rule is identical whether or not it has a key: the same formats and surgical merges apply, the same skip logic runs (a keyless rule has no secret version, so its render fingerprint and the on-disk file checksum decide when to re-sync), and the section round-trips through YAML, `.reg`, and the Windows registry unchanged. Add a `vault_key` back the moment a template needs secret fields — the two modes are the same rule type.

## How sync works

For each rule, on every sync cycle:

1. **Read** the secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}` (skipped for a [keyless rule](#rules-without-a-vault-key), which uses an empty data context)
2. **Skip** if the rule's render-affecting definition is unchanged AND the target file checksum is unchanged AND (for a keyed rule) the Vault secret version is unchanged
3. **Render** the template (if present) with the Vault data map as the dot context (empty for a keyless rule; `{{ username }}` still resolves)
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

> **The discriminator is the directive's identity — keep it stable.** For a repeatable keyword, the discriminator (a forward's listen spec, an `IdentityFile` path, a `SetEnv` variable name) is what decides *update-in-place* versus *add-a-new-line*. This is deliberate: it lets dotvault's managed forwards coexist with ones you hand-add. The trade-off is that **changing the discriminator itself cannot be expressed as a rewrite.** If a sync renders a `RemoteForward` whose listen spec differs from one already in the section — even by a single character — dotvault treats it as a *new* forward, appends it, and leaves the old line orphaned (it has no way to know the two are "the same" forward with a changed path). The fix is the same as for any unmanaged content dotvault didn't write: remove the stale line by hand once. To avoid it, design the template so the discriminator never changes — interpolate only the *target* of a forward, not its listen spec, and where the listen path must contain the username use the stable `{{ username }}` function (a path that was previously rendered with an empty or different value will not match and will orphan). The same applies to the other repeatable keywords: re-pointing an `IdentityFile` to a new path, or renaming a `SetEnv` variable, adds rather than replaces.

The motivating use case is a predictable `RemoteForward` that exposes the local dotvault (Vault) endpoint on a remote host through a stable per-user socket — one half of a dotvault-to-dotvault information-sharing setup. A template such as:

```
Host *
    User {{ username }}
    RemoteForward /home/{{ username }}/.ssh/dotvault.sock 127.0.0.1:8200
```

keeps the `User` and the `RemoteForward` listen path stable across syncs (the `username` function resolves to the OS account dotvault runs as), so the forward is updated in place rather than duplicated each cycle. See [Templates](templates.md#template-functions) for the `username` function.

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
