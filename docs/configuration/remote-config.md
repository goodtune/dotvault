# Remote Configuration

The locally provisioned configuration (the YAML file, or the Windows registry under Group Policy) can act as a **base** that is overlaid with a partial configuration document fetched over HTTPS from a `dotvault-config` service. This lets a fleet operator deliver dynamic, personalised configuration — per-user, per-OS, and per-group rules and enrolments — without touching the locally managed base.

The server side — layer storage, composition, group resolution, and seeding — is documented in [dotvault-config Service](../services/dotvault-config.md). The full design lives in the repository spec at `docs/superpowers/specs/2026-06-10-remote-config-design.md`.

## Enabling the overlay

```yaml
remote_config:
  url: https://dotvault-config.example.com/v1/config
  refresh_interval: 15m        # optional; default: sync.interval
  ca_cert: /etc/ssl/corp.pem   # optional CA pin for the fetch
  headers:                     # optional extra dimension headers
    X-Dotvault-Env: production
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | — (overlay disabled when empty) | The remote configuration endpoint. `https` is required unless the host is loopback/`localhost` (local development). |
| `refresh_interval` | string | `sync.interval` | How often a running daemon re-fetches the document. Go duration syntax plus `Nd` for whole days; floor `1m`. |
| `ca_cert` | string | system roots | CA bundle used to verify the service's TLS certificate. There is deliberately **no** skip-verify option — TLS integrity is the only guarantee that you are talking to the real service. |
| `headers` | map | — | Extra dimension headers sent with every fetch. They cannot override the built-in identity headers. |

## What the service can (and cannot) deliver

The remote document is a **partial config** restricted to the dynamic sections: `rules`, `enrolments`, and `sync`. The static sections — `vault`, `web`, `agent`, `observability`, `bypass_system_config`, and `remote_config` itself — are exclusively local; their presence in a remote document is a hard error. A remote service can therefore never redirect your Vault, open listeners, alter telemetry, or re-point where configuration comes from. Unknown sections are ignored with a warning, so an older daemon keeps working against a newer server.

Merge semantics:

- **Rules** merge by name — a remote rule with the same name as a base rule replaces it wholesale (keeping its position); new names are appended.
- **Enrolments** merge by map key — an entry replaces the base entry wholesale.
- **`sync.interval`** overrides the base value when set.

Merging is additive-only: there are no deletion markers. The merged view is recomputed from the base plus a freshly fetched document on every refresh, so an entry removed from the remote document simply disappears at the next refresh. Removing an entry the *local base* defines requires editing the local config.

A base config that sets `remote_config.url` may carry **zero rules** — the usual "at least one rule" requirement is waived because the remote document supplies them. If the merged result still has no rules, the daemon starts, idles, and converges once the service serves some.

## Identity headers

Every fetch sends client-asserted dimension headers. Configuration is **not secret**: the service is unauthenticated and these headers are spoofable by design — anyone may fetch anyone's document, so configuration layers must never contain secret values.

| Header | Value |
|--------|-------|
| `X-Dotvault-OS` | `windows`, `linux`, or `darwin` |
| `X-Dotvault-User` | the OS account name (`DOMAIN\` prefix stripped) — the same identity dotvault syncs under |
| `X-Dotvault-Arch` | e.g. `amd64`, `arm64` |
| `X-Dotvault-Hostname` | the machine hostname |
| `X-Dotvault-Version` | the dotvault build version |
| *(configured extras)* | from `remote_config.headers` |

## Failure behaviour

Fetching **fails open** down a ladder:

1. a fresh document from the service (a `200`, or a `304` revalidating the cache via `If-None-Match`);
2. the cached last-known-good document at `{cache_dir}/remote-config.json` (written `0600`, bound to the request identity so a cache fetched as one user/OS is never replayed for another);
3. the local base config alone, with a warning.

A service outage therefore degrades to "configuration frozen at last-known-good", never "daemon down". Long-lived daemons retry on every refresh tick.

## Refresh and convergence

A running daemon (in every mode — web, headless, CLI) re-fetches on each `refresh_interval` tick; an unchanged document costs a single cheap `304`. Changes converge without a restart:

- rules added/changed/removed → applied on the next tick (state for removed rules is pruned, and a sync runs immediately);
- enrolments added/changed/removed → the enrolment managers and the web UI's enrolment page update (deferred one tick if an enrolment is mid-run);
- `sync.interval` → the sync engine's ticker resets.

Static sections still require a daemon restart, exactly as for a locally edited config.

## Which commands fetch

| Command | Remote fetch? |
|---------|---------------|
| `run`, `sync`, `status`, `enrol` | yes — they operate on the merged configuration |
| `login`, `login-check` | no — they use only the local `vault` section, and `login-check` runs in shell-startup paths where network latency is unacceptable |
| `reg-import`, `reg-export` | no — pure format converters |

## Observing the overlay

- `dotvault status` prints a `Remote Config:` block — URL, source (`remote` / `cache` / `none`), ETag, last success, last error.
- The web UI's `/api/v1/status` carries the same as a `remote_config` object, and the Effective Configuration screen (and its YAML/.reg download) reflects the **merged** configuration, including the `remote_config` section itself.
- The `dotvault.remoteconfig.fetches` metric counts fetch outcomes (`fresh`, `not_modified`, `cache_fallback`, `base_only`).

## Trust model

The remote service operator is trusted equivalently to the local config admin: rules and templates direct where credentials are written on disk, which was already true of the local config. The integrity boundary is TLS — use `https` (mandatory off-loopback) and pin `ca_cert` where appropriate. Because the endpoint is unauthenticated, never put secret values in configuration layers; enrolment settings are non-secret by contract, and OTLP tokens stay local (the `observability` section cannot be delivered remotely at all).

## Windows / Group Policy

The section round-trips through the registry like every other: scalar values under the `RemoteConfig` subkey and headers under `RemoteConfig\Headers`. See [Windows Group Policy](../admin/windows-gpo.md#remote-configuration-remoteconfig-subkey).
