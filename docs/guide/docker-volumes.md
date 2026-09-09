# Docker volumes

dotvault can serve your Vault secrets to containers as a **Docker volume**. Rootless Docker and Podman both speak the volume plugin protocol, so once the plugin is registered a container mounts its secrets like any other volume:

```console
$ docker volume create -d dotvault -o secrets=gh,databricks/ app-secrets
$ docker run --rm -v app-secrets:/run/secrets/dotvault:ro alpine ls -R /run/secrets/dotvault
/run/secrets/dotvault:
databricks
gh.json

/run/secrets/dotvault/databricks:
prod.json

$ docker run --rm -v app-secrets:/run/secrets/dotvault:ro alpine cat /run/secrets/dotvault/gh.json
{
  "oauth_token": "gho_...",
  "user": "gary"
}
```

Each secret is a `.json` file holding its `data` section, rendered exactly as the [filesystem](filesystem.md) renders it, and each KV folder is a directory. The volume is a directory of plain files the daemon writes and keeps current — not a FUSE mount — which is what makes it work inside a container: no special uid, no mount propagation, and a `mode` option that lets a non-root container user read it. Authentication and the KV prefix come from dotvault's own configuration; a volume can only ever contain secrets under your own prefix.

It is disabled by default and Linux only.

## Enabling it

In the system configuration (see the [config reference](../configuration/config-reference.md#docker-volumes-section)):

```yaml
docker:
  enabled: true
```

The daemon then listens on `$XDG_RUNTIME_DIR/dotvault/docker.sock` and materialises volumes under `$XDG_RUNTIME_DIR/dotvault/volumes`. Both live on the per-user runtime tmpfs — owner-only, memory-backed, cleared at logout — so a rendered secret never outlives the login that produced it.

### Registering the plugin

Container engines do not look in dotvault's runtime directory on their own, so register the socket once with a one-line **spec file**. `dotvault status` prints the exact command for your socket path.

=== "Rootless Docker"

    ```console
    $ mkdir -p ~/.local/lib/docker/plugins
    $ echo "unix://$XDG_RUNTIME_DIR/dotvault/docker.sock" > ~/.local/lib/docker/plugins/dotvault.spec
    ```

    Rootless `dockerd` discovers plugins from `~/.local/lib/docker/plugins`. (Docker's documentation also names `~/.config/docker/plugins`, but released daemons through v28 resolve that path to `/etc/docker/plugins` — the error check in `rootlessConfigPluginsPath`, `pkg/plugins/discovery_unix.go` in moby/moby, is inverted — so use `~/.local/lib`.)

=== "Rootless Podman"

    In `~/.config/containers/containers.conf`:

    ```toml
    [engine.volume_plugins]
    dotvault = "/run/user/1000/dotvault/docker.sock"
    ```

    Podman needs the literal path (it does not expand `$XDG_RUNTIME_DIR`); `echo $XDG_RUNTIME_DIR` tells you yours.

=== "Rootful Docker"

    As root, `echo "unix:///run/user/1000/dotvault/docker.sock" > /etc/docker/plugins/dotvault.spec`. A root daemon can reach a user's socket, but think before doing this: every container that daemon runs can then mount that user's secrets, and the container's root is real root.

dotvault deliberately does not write the spec file itself — it never edits another tool's configuration, the same way it never sets `SSH_AUTH_SOCK`.

## Creating volumes

`docker volume create -d dotvault [-o option=value ...] NAME`, or inline at run time with `--mount type=volume,volume-driver=dotvault,volume-opt=secrets=gh,dst=/run/secrets/dotvault,readonly`.

| Option | Default | Meaning |
|--------|---------|---------|
| `secrets` | everything | Comma-separated paths relative to your prefix. A bare name is one secret (`gh`, `databricks/prod`); a trailing slash is a whole folder (`databricks/`). Selecting a secret that does not exist yet is fine — it appears once enrolled |
| `layout` | `json` | `json` writes `<name>.json` per secret. `fields` writes a directory per secret with one file per field, the raw value as the contents — for programs that read `DB_PASSWORD_FILE=/run/secrets/dotvault/db/password` |
| `mode` | `0400` | File mode. Only read bits are accepted (`0400`, `0440`, `0444`); directories get matching traverse bits |
| `ttl` | `docker.cache_ttl` (`1m`) | This volume's refresh window when polling (see [Staying current](#staying-current)). Capped at ten minutes |

An unknown option is an error: a mistyped `secret=` that silently selected every secret you have would be the opposite of what you asked for.

With no `secrets` option the volume carries your whole subtree, like the filesystem does. Prefer naming what the container needs — a container is usually the one place you *do* want less than everything.

### Who can read the files

Under a rootless engine the files are owned by your uid, which the container sees as root. With the default `mode=0400` only container root can read them. A container that runs its process as another user needs `-o mode=0444`:

```console
$ docker volume create -d dotvault -o secrets=db -o layout=fields -o mode=0444 db-secrets
$ docker run --rm --user 1000 -v db-secrets:/run/secrets/dotvault:ro app
```

Mount the volume `readonly` (`:ro`, or `readonly` in `--mount`). Container root maps to the uid that owns the files and can overwrite them otherwise; the next refresh puts them back, but an application that wrote there would be surprised.

## Staying current

The daemon keeps every mounted volume fresh, and how it does so follows the Vault edition:

- **Vault Enterprise** — the daemon subscribes to the KVv2 event stream. A volume is rendered when it is first mounted and then re-rendered the moment Vault reports a change to a secret it selects; while the subscription is connected it is otherwise never re-read. If the subscription drops, volumes fall back to their `ttl` until it reconnects, and reconnecting re-renders everything, since anything may have changed in the gap.
- **Vault Community** — there is no event stream, so every volume is re-rendered on its `ttl` (the volume's option, else `docker.cache_ttl`, default one minute).

Either way a rotated secret reaches the running container without a restart: files are replaced atomically, so a program re-reading `/run/secrets/dotvault/gh.json` sees the old document or the new one, never a partial write. A deleted secret's file is removed. A program that reads the secret once at startup needs restarting like any other, of course.

`docker volume inspect` shows the policy in force, when the volume last refreshed, and any error:

```console
$ docker volume inspect app-secrets --format '{{json .Status}}' | jq
{
  "layout": "json",
  "mode": "0400",
  "mounts": 1,
  "refresh": "events",
  "secrets": 2,
  "selection": ["databricks/", "gh"],
  "last_refresh": "2026-09-08T10:12:31Z",
  "ttl": "1m0s"
}
```

`refresh` is `events` (Enterprise, subscription connected), `poll` (Community, or a subscription that is down — an `events_error` key here, in `dotvault status` and in `/api/v1/status` names the reason), or `probing` (the daemon has not yet learned the edition, typically because it has no token yet; volumes poll meanwhile).

## Lifecycle

A volume's files exist only while a container holds it. The first `Mount` renders the directory; the last `Unmount` deletes it. `docker volume rm` deletes it too. No secret is written to disk for a volume nobody has mounted — only its definition, in `{cache_dir}/docker-volumes.json`.

The daemon remembers its volumes and which containers hold them across restarts, so restarting dotvault under a running container keeps that container's directory and resumes refreshing it — the container never sees an empty mount. Stopping the daemon leaves mounted directories in place for the same reason; the next daemon picks them up, and removes any directory that belongs to a volume no container holds.

!!! tip "Socket activation (systemd)"
    The packaged `dotvault-docker.socket` unit (optional, not enabled by default) lets systemd bind the plugin socket and hold it across daemon restarts, so a `docker run` that lands mid-restart queues briefly instead of the engine reporting the plugin unreachable. `systemctl --user enable --now dotvault-docker.socket`; `docker.enabled` is still required, and the `.spec` file must name the unit's `ListenStream=` path (the default is the same `$XDG_RUNTIME_DIR/dotvault/docker.sock`). See [Socket activation](../admin/deployment.md#socket-activation-optional).

A `Mount` while the daemon holds no Vault token yet is refused with a message saying so (`docker run` reports it), rather than producing an empty volume. `docker volume create`, `ls` and `inspect` work without a token.

`dotvault status` reports the plugin as the engine sees it:

```console
$ dotvault status
...
Docker Volumes:
  socket:     /run/user/1000/dotvault/docker.sock
  volume dir: /run/user/1000/dotvault/volumes
  register:   echo unix:///run/user/1000/dotvault/docker.sock > ~/.local/lib/docker/plugins/dotvault.spec
  app-secrets          mounts=1 secrets=2 refresh=events
```

## Requirements and limits

| Platform | Support |
|----------|---------|
| Linux | Rootless or rootful Docker, and Podman. Nothing beyond the engine is needed — no FUSE, no privileges |
| macOS, Windows | **Not supported.** Docker Desktop and Podman machine run the engine in a virtual machine where a host socket is unreachable. Setting `docker.enabled` logs a warning and serves nothing, so a config shared across a mixed fleet is safe |

Volumes are `local` scope and belong to this daemon's user; the plugin is the "legacy" socket-discovered kind, not a managed (`docker plugin install`) plugin, because managed plugins run as root-controlled containers and would defeat the per-user point.

!!! warning "Secrets are on disk while a volume is mounted"
    Unlike the filesystem, a volume's contents really are files, for as long as a container holds it. They live on the runtime tmpfs by default, inside a directory only your uid can traverse, and are deleted at the last unmount — the same exposure Docker's own `/run/secrets` has. If `docker.volume_dir` is pointed at a persistent disk that changes; leave it on the runtime directory unless you have a reason.

## Troubleshooting

**`docker: Error response from daemon: error looking up volume plugin dotvault: plugin not found`** — the engine has not found the spec file, or it names the wrong socket. Check `~/.local/lib/docker/plugins/dotvault.spec` (rootless) against the socket path `dotvault status` prints. Under `dotvault-docker.socket` the unit's `ListenStream=` path is the authoritative one, and `dotvault status` reports `docker.socket` from the config, so keep the two the same.

**`… dotvault has not authenticated with vault yet`** — the daemon is running but holds no token. `dotvault login`, or wait for the peer borrow, then retry.

**`refresh` stuck at `poll` on Enterprise** — the token's policy must allow the subscription: `read` on `sys/events/subscribe/kv-v2/*` and `subscribe` on the secrets with `subscribe_event_types = ["*"]` (the dev stack's `dotvault` policy in `docker-compose.yaml` is a reference). The reason is the `events_error` in `dotvault status`, `docker volume inspect` and the daemon log; volumes keep refreshing on their `ttl` meanwhile.

**Container user cannot read the files** — create the volume with `-o mode=0444` (see above); `0400` admits container root only.
