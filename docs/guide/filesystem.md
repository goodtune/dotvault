# Filesystem

dotvault can mount your Vault secrets as a filesystem. Each secret becomes a `.json` file whose contents are its `data` section, and each KV folder becomes a directory:

```console
$ ls ~/.dotvault
databricks  gh.json  jfrog.json

$ jq . ~/.dotvault/gh.json
{
  "oauth_token": "gho_...",
  "user": "gary"
}

$ jq -r .oauth_token ~/.dotvault/gh.json | gh auth login --with-token
```

The extension is not decoration: the contents really are JSON, and it is what makes an editor, an IDE or `vim` highlight, fold and lint the file instead of treating it as unknown plain text. Directories carry no extension — a KV folder is not a JSON document.

It is disabled by default. Where [sync rules](../configuration/sync-rules.md) write specific fields into specific config files on a schedule, the filesystem is the opposite: a live, read-only view of everything under your own KV prefix, for the cases where writing a rule is more ceremony than the job deserves — a one-off script, an interactive shell, a tool that wants a value you have not templated anywhere.

## Enabling it

```yaml
fuse:
  enabled: true
  mountpoint: "~/.dotvault"   # default
  read_write: false           # default
  cache_ttl: "30s"            # default
```

The daemon mounts the filesystem after its first successful Vault authentication and unmounts it on shutdown. The mountpoint is created (mode `0700`) if it does not exist.

`dotvault status` reports what is configured and whether anything is actually mounted:

```console
$ dotvault status
...
Filesystem:
  mountpoint: /home/gary/.dotvault
  mode:       read-only
  cache ttl:  30s
  state:      mounted
```

## Per-user preferences

The `fuse` section can also be set in your **own** configuration file, which is merged over the system configuration:

| Platform | Path |
|----------|------|
| Linux | `${XDG_CONFIG_HOME:-~/.config}/dotvault/config.yaml` |
| macOS | `~/Library/Application Support/dotvault/config.yaml` |
| Windows | `%APPDATA%\dotvault\config.yaml` |

```yaml
# ~/.config/dotvault/config.yaml
fuse:
  enabled: true
  mountpoint: "~/vault"
  cache_ttl: "5s"
```

This is the file to use when your machine's system configuration does not mention the filesystem and you want it, without editing a config an administrator owns.

**Only `fuse` may appear here.** Any other section — `vault`, `web`, `agent`, `api`, and the rest — is a hard error naming it, because that file is yours to write and configuration like where the daemon points its Vault is not. A section this build does not recognise is ignored with a warning, so a newer dotvault's config still starts on an older binary.

Each field merges by its own rule rather than simply overwriting policy:

| Field | Rule |
|-------|------|
| `enabled` | You may turn the filesystem **on** when the system leaves it off. You may **not** turn it off when the system enables it |
| `read_write` | You may turn writes **off** when the system enables them. You may **not** turn them on |
| `mountpoint` | Yours wins |
| `cache_ttl` | Yours wins |

The two booleans ratchet in opposite directions, and that is deliberate rather than an inconsistency. Enabling a read-only mount grants nothing your Vault token could not already do, so an administrator's "off" is only a default. Read-write is a different kind of setting — it puts every process running as you one `>` away from replacing a credential — so there the administrator's "no" is binding, and you stay free to be more careful than policy requires.

An omitted key is not a preference. Writing only `mountpoint:` leaves `enabled` and `read_write` exactly as the system configuration set them; you have to write `enabled: false` to mean it, and even then it only takes effect if the system had not already enabled it. When a preference is overruled, the daemon logs a warning naming the field, so a mount you asked not to have is never silently there.

A bad value is a startup error naming your file rather than a silent fallback — an unparseable `cache_ttl` stops the daemon instead of quietly reverting to 30s.

## Requirements

| Platform | Requirement |
|----------|-------------|
| Linux | A FUSE-capable kernel (`/dev/fuse`) and the `fusermount3` helper, from the `fuse3` package on most distributions. A daemon with `CAP_SYS_ADMIN` can mount without the helper |
| macOS | [macFUSE](https://macfuse.github.io/), installed separately. macOS requires approving its kernel extension in System Settings |
| FreeBSD | The in-kernel `fusefs` module |
| Windows | **Not supported.** Setting `fuse.enabled` logs a warning and mounts nothing |

Windows has no FUSE. The nearest equivalent, WinFsp, is a DLL reached through cgo, and dotvault ships `CGO_ENABLED=0` static binaries — so rather than carry a dependency it cannot build, the daemon treats the setting as inert there. A config shared across a mixed-platform fleet is safe: the Windows hosts ignore the section and start normally.

Mounting is never fatal. If FUSE is unavailable the daemon logs the reason once and carries on syncing, serving its API socket and running its SSH agent. The failure is not retried — the causes (no `/dev/fuse`, no helper binary, macFUSE not installed, mountpoint occupied) do not clear on their own, and a retry loop would just log forever.

## What you see

The mount root is your own KV prefix, `{kv_mount}/{user_prefix}{username}/`, so a secret at `kv/users/gary/gh` is `~/.dotvault/gh.json`. It is not possible to reach another user's secrets through the mount: the prefix is bound at construction, not derived from the path you ask for.

Grouped keys nest the way you would expect. An enrolment key of `databricks/prod` lives at `~/.dotvault/databricks/prod.json`, with `databricks` as a directory.

Exactly one extension is added, so the mapping is reversible: a secret genuinely named `config.json` in Vault appears as `config.json.json`. That looks odd, and it is the honest spelling — anything cleverer would make two different secrets share one filename.

`stat` reports:

- **size** — the exact byte length of the rendered JSON, so `wc -c`, `mmap` and anything else that trusts `st_size` get the truth.
- **mtime** — the current version's `created_time` from Vault. This is KVv2's nearest equivalent of a modification time, and it means `make`-style staleness checks and `ls -lt` do something meaningful.
- **mode** — `0400` for files and `0500` for directories on a read-only mount, `0600`/`0700` when `read_write` is on, so `test -w` agrees with what a write would actually do.

The mount is owner-only. dotvault deliberately does not offer FUSE's `allow_other`: the whole premise of a per-user daemon is that the secrets it holds belong to one uid.

!!! warning "Reads reach Vault"
    A file in this mount is not a copy on disk — a read that misses the cache calls Vault. That is what keeps it live, and it is why `grep -r` across the mount is a bad idea: it will read every secret you have, and each read shows up in Vault's audit log. Reach for a specific path. The same goes for an editor or IDE that indexes your home directory in the background.

## Caching

`cache_ttl` (default 30s) is how long a directory listing or a rendered secret is reused before Vault is asked again.

This is not really an optimisation. A filesystem asks far more questions than a person does: a single `ls -l` stats every entry, and stat needs the file's size, which can only be known by rendering the document. Without a cache, one `ls -l` is one Vault read per secret, every time. Lookups that find nothing are cached too — a miss is the most common request a mounted filesystem gets, from shell completion and from every tool probing for a config file it might have.

Set `cache_ttl: "0"` to disable caching entirely and pay a Vault round trip per operation. Writes through the mount invalidate their own entries immediately, so a read straight after a write always sees what was just written; the only staleness you can observe is a secret changed by something *else* within the window.

## Read-write mode

`read_write: true` allows writes. It is off by default even though the daemon's token can usually write, because the token's write capability exists for dotvault's own sync and enrolment work — exposing it through a filesystem puts every process running as you, and every mistyped shell redirect, one `>` away from replacing a credential. Opting in is a separate decision from mounting.

With it on:

```console
# Replace a secret: the whole document is written as one new KVv2 version
$ jq '.oauth_token = "gho_new"' ~/.dotvault/gh.json > /tmp/gh.json && cat /tmp/gh.json > ~/.dotvault/gh.json

# Create one
$ echo '{"token":"abc123"}' > ~/.dotvault/scratch.json

# Create one under a new group
$ mkdir ~/.dotvault/databricks
$ echo '{"host":"https://x.cloud.databricks.com"}' > ~/.dotvault/databricks/prod.json

# Delete one — every version of it
$ rm ~/.dotvault/scratch.json
```

!!! warning "Edit through a scratch file, not in place"
    In-place editors and `sponge` write a temp file *beside* the target and `rename` it over. Rename is refused here, so the temp file is created as a real secret in Vault, written, and then unlinked — which deletes every version of it. It works, but it churns your KV store with a short-lived secret each time. Stage the edit outside the mount, as above.

The rules:

- **A file's contents must be a JSON object with at least one field.** The write is applied on `close()`, so invalid JSON surfaces as a failing `close` (`EINVAL`) rather than as a silently discarded edit. Numbers survive the round trip exactly — reading and rewriting a secret unchanged does not turn `1000000` into `1e+06`.
- **A write replaces the whole document.** There is no field-level merge; the file *is* the secret's data section, and writing it creates one new KVv2 version.
- **`rm` deletes every version**, not just the latest. There is no filesystem gesture that means "soft delete", so unlink is the destructive one.
- **`mkdir` creates a directory that exists only in memory** until a secret is written inside it. KVv2 has no directories of its own — a folder exists because secrets exist beneath it — so there is nothing for `mkdir` to write. An empty one disappears at unmount. `rmdir` removes it while it is still empty; on a directory backed by real secrets it reports `ENOTEMPTY`, because emptying it is what removes it.
- **`rename` is not supported** — `mv` reports "Operation not supported" (`ENOTSUP`). Renaming a secret means read, write elsewhere, delete: three Vault operations that cannot be made atomic, where a partial failure leaves you with two copies or none.
- **A new file must be named `.json`, and a new directory must not be.** `echo ... > ~/.dotvault/thing` is refused (`EINVAL`): the file would appear as `thing.json` on the next listing, renaming itself the moment you looked away. `mkdir ~/.dotvault/thing.json` is refused for the mirror reason — it would shadow the secret `thing`, which is the one filename collision the extension does not otherwise remove.
- **Appending is refused** (`EINVAL` at open). Appending to a JSON document does not produce a JSON document, and failing at `open` is more useful than failing at `close`.
- **`touch` on a new name fails.** A secret with no fields is not something KVv2 stores, so creating a file commits you to writing something valid to it. Use `echo '{...}' > file`.
- Files are capped at 1 MiB. A KV secret holding a megabyte of JSON is a misuse of the mount; the cap mostly exists so a runaway redirect cannot grow the daemon's memory without bound.

## Layout

A secret and a folder may share a name. `users/you/databricks` and `users/you/databricks/prod` both exist happily: the first is `~/.dotvault/databricks.json`, the second is `~/.dotvault/databricks/prod.json`. Two different filenames, both reachable — which is the second thing the extension buys, after the syntax highlighting.

One collision survives, and it is narrow: **a KV folder whose name already ends in `.json`** competes with the secret of the same stem. A folder `report.json/` and a secret `report` both want the filename `report.json`. The behaviour is deterministic — the directory wins, so the secrets underneath stay reachable — and the daemon logs a warning naming the path, but the shadowed secret has no path in the mount. Read it through the web UI or `vault kv get`. The mount refuses to *create* such a directory, so it can only arise from a KV tree laid out that way already.

## Permissions

The mount only shows what your Vault token can read, so a token scoped more tightly than your KV prefix simply sees less.

A policy that grants `read` on specific paths without granting `list` on their parent is handled: `ls` reports the permission error, but opening a path you know the name of still works, because the lookup falls back to reading the path directly.

## Troubleshooting

**`Transport endpoint is not connected`** — a daemon died without unmounting. The next daemon start detects this and clears it automatically. To clear it by hand: `fusermount3 -u ~/.dotvault` (Linux, or `fusermount -u` on older `fuse2` systems) or `umount ~/.dotvault` (macOS).

**The daemon will not exit** — something is holding the mount busy, most often a shell whose working directory is inside it. dotvault retries the unmount for about three seconds, then leaves the mount in place and logs which mountpoint it could not release, rather than refusing to shut down. `cd` out and unmount by hand.

**`ls` hangs, then everything reports `ETIMEDOUT`** — Vault is unreachable. Each operation is bounded at 30 seconds; a filesystem call that never returns would leave the calling process in uninterruptible sleep.

**Reads fail with `Permission denied`** — Vault rejected the request (an expired token, or a policy that does not cover the path). Check `dotvault status`.

## See also

- [Config File Reference](../configuration/config-reference.md#filesystem-section) — the full field table and the Windows GPO equivalents
- [Sync Rules](../configuration/sync-rules.md) — writing specific fields into specific files, which is what you want for a tool that reads a fixed config path
- [SSH Agent](ssh-agent.md) — the other live surface over the daemon's Vault token
