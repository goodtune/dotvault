# Docker volume driver

Status: design, 2026-09-08. Branch `claude/docker-vault-volume-driver-vm9dma`.

## Problem

The [filesystem](../../guide/filesystem.md) answers "give me a live view of my secrets" for processes running as the user on the host. A container is the case it does not reach. Rootless Docker and Podman run a container's processes as the user's own uid (container root) and as subordinate uids (everyone else), inside a mount namespace the engine created before the daemon mounted anything. A FUSE mount is accessible only to the mounting uid, so a container process running as anything but root gets `EACCES`; whether the mount is visible in the engine's namespace at all depends on mount propagation the engine may or may not have asked for; and a FUSE file held open by a container keeps the daemon's mount busy at shutdown.

What a container wants is what Docker's own secrets already look like: a directory of plain files at a path like `/run/secrets/dotvault`, owned by root inside the container, readable by whoever the operator says, and kept current by something outside the container. dotvault already has the authentication, the KV layout, the renderer, and — on Enterprise — the event subscription that says when a secret changed. It should serve that directory.

## Scope

dotvault serves the Docker volume plugin protocol on a per-user Unix socket. A volume is a directory of the user's secrets, selected at `docker volume create`, materialised on the first mount, kept current by a refresh policy chosen from the Vault edition, and deleted on the last unmount. The same protocol is what Podman consumes, so `podman run --mount type=volume,volume-driver=dotvault,…` works unchanged.

Explicitly **not** in scope: the managed-plugin (v2) packaging format, which runs the plugin as a root-managed container and defeats the per-user point; any Windows or macOS surface, since the engine there runs in a VM where a host socket is unreachable; and writing into Vault from a container.

## Design

### Files, not a filesystem

Each volume is a subdirectory of `docker.volume_dir` (default `$XDG_RUNTIME_DIR/dotvault/volumes`, a tmpfs cleared at logout). The driver renders every selected secret into it through the same `vaultfs.RenderDocument` the mount uses, so `gh.json` has identical bytes whichever way it is read, and updates each file atomically (temp file, mode, mtime, rename) so a container reading mid-refresh sees the old document or the new one, never a partial. A refresh converges the directory on Vault: a deleted secret's file is pruned, a changed one lands in a new inode, an unchanged one keeps its inode. A refresh that fails leaves the previous rendering untouched rather than pruning half of it.

The engine bind-mounts the directory, so the directory's inode is the container's view. That has two consequences the driver honours: a refresh must update files *inside* the directory, never swap the directory itself; and the daemon must not delete the directory while the engine still counts a container on it.

Every operation inside a volume goes through an `os.Root`. Under a rootless engine container root *is* the uid that owns the files, so unless the volume was mounted read-only a container can rearrange the directory between refreshes — replace a subdirectory with a symlink to `~/.ssh`, say. Plain `os` calls would follow it (chmod the target, rename a rendered secret into it); a root refuses any path resolving outside the volume, so the worst such a container can do is disturb its own volume, which the next refresh repairs. The volume directory itself carries a marker file, and a non-empty directory without one is refused at startup rather than pruned, so a mistyped `docker.volume_dir` cannot become a startup that deletes the user's files.

### Selection and layout

`-o secrets=gh,databricks/,ci/deploy` selects single secrets (bare names) and whole folders (trailing slash) as canonical relative KV paths; no option selects the user's entire subtree, matching the mount. `-o layout=fields` renders each secret as a directory holding one file per field (`gh/oauth_token`), the shape a `*_FILE` environment convention expects, with string values written byte-for-byte and other values as JSON. `-o mode=0444` widens the files beyond owner-read (the default, `0400`, is readable by container root alone under a rootless engine); write and execute bits are refused, and directories derive traverse bits from the file mode. `-o ttl=30s` sets the volume's own refresh window. An unknown option is an error, because `secret=` silently selecting everything would hand a container the opposite of what was typed.

### Refresh policy

The driver asks Vault's edition once (retrying until it answers) and then:

| Edition | While connected | While disconnected |
|---------|-----------------|--------------------|
| Enterprise | Subscribed to `kv-v2/*`; a volume re-renders when an event names a secret it selects, debounced 250ms, and is otherwise never re-read | Every volume re-renders on its ttl until the subscription reconnects, which re-renders everything |
| Community | Every volume re-renders on its ttl | — |

The wildcard subscription matters: writes alone would let a deleted secret survive in a volume for exactly as long as the subscription stayed up. Reconnection uses the sync engine's backoff (1s doubling to 5m). The watcher waits for a token before subscribing, and until the edition is known every volume polls — nothing is lost by waiting.

`ttl` defaults to `docker.cache_ttl` (default `1m`) and is capped at ten minutes for the reason the filesystem caps its cache: the window is also how long a rotated secret keeps being served.

### Lifecycle and persistence

`Create` validates and records the definition. `Mount` populates the directory on the first reference (refusing with a named cause while the daemon holds no token), starts the refresh loop, and records the engine's mount ID. `Unmount` drops the ID; the last one stops the loop and deletes the directory. `Remove` forgets the definition and deletes the directory, trusting the engine's reference count over the driver's own when they disagree.

Definitions and mount IDs persist in `{cache_dir}/docker-volumes.json` (no secret data). A daemon restarted under a running container therefore resumes refreshing the directory that container still has bind-mounted, rather than wiping it or answering "no such volume" at the next `Mount`; a directory for a volume with no references, or for a name no longer known, is removed at startup. Shutdown leaves every mounted directory in place for the same reason.

### Discovery

The socket is `docker.socket`, default `$XDG_RUNTIME_DIR/dotvault/docker.sock`, bound through `internal/uds` (0600 in a 0700 directory) — or, optionally, claimed from systemd through the same seam the API socket and SSH agent use (`dotvault-docker.socket`, `FileDescriptorName=docker`), which only smooths the engine's own calls across a daemon restart since a held volume's directory survives one anyway. It is deliberately not under an engine's plugin directory: rootless dockerd scans `/run/docker/plugins` inside its own mount namespace (a private copy-up of `/run` nothing outside RootlessKit can populate), and a rootful dockerd's is root-owned. Both engines accept a `.spec` file naming an arbitrary socket. dotvault does not write that file — the same posture as never setting `SSH_AUTH_SOCK` — but `dotvault status` prints the one-line command. Released rootless dockerds (v27, v28) scan `~/.local/lib/docker/plugins` for it; their `~/.config/docker/plugins` branch is inverted in the source and resolves to `/etc/docker/plugins`, so the guide names the former.

### Surfaces

`config.DockerConfig` (`enabled`, `socket`, `volume_dir`, `cache_ttl`) is a static section: refused in a remote document, named in the restart-required warning, round-tripped through the registry (`Docker` subkey) and `.reg`. `dotvault status` dials the socket and lists volumes with mount counts and refresh mode; `GET /api/v1/status` carries a `docker` block. The plugin starts before authentication, alongside the agent and HTTP listeners, so the engine's bookkeeping calls are answered and a premature `Mount` gets a reason rather than "plugin not found".

## Security posture

A volume can only ever contain secrets under the user's own prefix, bound in the store at construction. The volume directory sits inside an owner-only parent, so on the host only the user can reach it; inside the container, file mode is the control, and the default admits container root alone. Container root can overwrite the files (it maps to the owning uid); the next refresh restores them, and the guide recommends `readonly`. Secrets are materialised on disk, on a tmpfs by default, for exactly as long as a container holds the volume — the same exposure as Docker's own secrets, and the trade the container case forces.
