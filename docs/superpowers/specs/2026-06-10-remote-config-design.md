# Remote Configuration Design

## Overview

dotvault configuration today comes entirely from a locally provisioned source — the YAML file at the platform system path, or the Windows registry under GPO. This design adds a second, *remote* source: the local config becomes the **base**, and the client fetches a partial configuration document over HTTPS from a new **`dotvault-config` service** and merges it on top before running. The service composes the document server-side from layered partials (global → OS → LDAP/static groups → user), so a global organisation can deliver per-region enrolments and rules — a user in the Sydney office sees Sydney's third of the products, a user in two offices sees two thirds — without touching the locally managed base config.

Configuration is explicitly **not secret**. The service is unauthenticated, and the dimension headers that select the document (`X-Dotvault-OS`, `X-Dotvault-User`) are client-asserted and spoofable by design. HTTPS provides integrity (the client must know it is talking to the real service), not confidentiality.

The service lives in this repository (`cmd/dotvault-config`) so it reuses `internal/config` types and validation verbatim — a layer is validated with exactly the code the daemon runs.

## Client: the `remote_config` section

A new top-level config section, **settable only from the local base** (file or registry — it is rejected in remote documents):

```yaml
remote_config:
  url: https://dotvault-config.example.com/v1/config
  refresh_interval: 15m        # optional; default: sync.interval
  ca_cert: /etc/ssl/corp.pem   # optional CA pin for the fetch
  headers:                     # optional extra dimension headers
    X-Dotvault-Env: production
```

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `url` | string | — (section inactive when empty) | must parse; scheme `https` unless host is loopback/`localhost` (dev) |
| `refresh_interval` | duration string (`Nd` supported) | `sync.interval` | positive, floor 1m |
| `ca_cert` | path | system roots | file must exist at use |
| `headers` | map[string]string | — | names/values free of CR/LF/NUL; cannot override built-in `X-Dotvault-*` headers |

There is deliberately **no `tls_skip_verify`** — TLS integrity is the only protection the channel has.

The section round-trips through all three config surfaces like every other section: the live registry loader (`RemoteConfig` subkey with `URL`, `RefreshInterval`, `CACert` values and a `Headers` subkey, names preserved verbatim), the `.reg` renderer/parser, and YAML.

## Partial documents

The wire format between service and client is a **partial config**: a YAML document restricted to the dynamic sections.

```go
type Partial struct {
    Sync       *SyncConfig          `yaml:"sync,omitempty"`
    Rules      []Rule               `yaml:"rules,omitempty"`
    Enrolments map[string]Enrolment `yaml:"enrolments,omitempty"`
}
```

`config.ParsePartial(data []byte)` enforces the wire contract:

- **Static keys are a hard error**: `vault`, `web`, `agent`, `observability`, `bypass_system_config`, `remote_config`. These stay exclusively local — the remote service can never redirect the Vault address, open the web UI, reconfigure the SSH agent or telemetry, or grant itself a config bypass. This also sidesteps the runtime problems those sections carry (one-shot OTel init, Vault client identity, listener sockets).
- **Unknown keys are warn-and-ignore**: an older daemon receiving a newer server's document keeps working. This is the forward-compatibility contract between mixed client/server versions.

`(*Partial).Validate()` applies the same per-entry checks the full config uses (rule name/vault_key/target.path present, known target format, unique rule names, enrolment key shape and non-empty engine), sharing the extracted `validateRule` helper so the two paths cannot drift.

## Merge semantics

One merge implementation (`internal/config/merge.go`) serves both sides: the client merging the fetched document onto its base, and the service composing layers into the served document.

| Section | Strategy |
|---------|----------|
| `rules` | merged **by rule name** — a same-named rule replaces the base rule wholesale (a rule is an atomic unit; field-level splicing would be unreadable), keeping the base's position; new names append in document order |
| `enrolments` | merged **by map key** — an entry replaces the base entry wholesale |
| `sync` | `interval` overrides when non-empty |

Merging is **additive-only in v1** — there are no deletion tombstones, and none are needed for convergence: the client recomputes *base ⊕ fresh remote* on every refresh, so an entry removed from the remote document simply vanishes from the next merged view. The one thing a remote document cannot do is remove an entry the **local base** defines; that requires editing the local config (or restructuring so the entry lives in a remote layer). Tombstones are future work if that becomes a real operational need.

## Client load pipeline

The base is parsed **without final validation** (from either the YAML file or the registry — `LoadRaw` / `LoadSystemRaw`), the remote document is fetched and merged, and only the **merged** config is validated. This matters because a fleet-managed base may legitimately carry zero rules when the remote supplies them all; the existing "at least one rule" check now applies only when `remote_config.url` is empty. With a URL configured, zero merged rules is a warning, not an error — the daemon starts, idles, and converges when the service comes back.

Fetch failures **fail open** down a ladder:

1. fresh document from the service (`200`, or `304` validating the cache);
2. cached last-known-good from `{cache_dir}/remote-config.json`;
3. base config alone, with a warning.

The daemon retries on every refresh tick, so an outage degrades to "config frozen at last-known-good" rather than "daemon down". One-shot commands get the same ladder with a single attempt.

| Command | Remote fetch? |
|---------|---------------|
| `run`, `sync`, `status`, `enrol` | yes (merged loader) |
| `login`, `login-check` | no — they consume only local-only `vault.*`, and `login-check` runs in shell-startup paths where network latency is unacceptable |
| `reg-import`, `reg-export` | no — pure format converters |

### Cache

JSON envelope at `{cache_dir}/remote-config.json`, written 0600 via temp-file + rename (same pattern as `state.json`): `{schema, url, identity, etag, fetched_at, body}`. `identity` is a hash of the request identity (URL + OS + user + extra headers) so a cache written under one identity is never replayed for another. The file carries non-secret config and sits in the user's own cache directory — the same trust as `state.json`.

## Dimension headers

Every request sends:

| Header | Value |
|--------|-------|
| `X-Dotvault-OS` | `runtime.GOOS` (`windows`, `linux`, `darwin`) |
| `X-Dotvault-User` | `paths.Username()` (OS account, `DOMAIN\` stripped — the same identity the sync engine writes under) |
| `X-Dotvault-Arch` | `runtime.GOARCH` |
| `X-Dotvault-Hostname` | `os.Hostname()` |
| `X-Dotvault-Version` | build version |
| *(configured extras)* | from `remote_config.headers` |

Header names are case-insensitive on the wire (Go canonicalises to `X-Dotvault-Os` etc.; the service reads via `r.Header.Get`). The service lowercases the OS value before layer lookup. Extras are forwarded but not consumed by v1 layer kinds — "environment" is modelled as group membership; a future layer kind can key off an extra header without a client change.

## Daemon refresh and convergence

The existing per-tick config reload (previously CLI-interactive-only, enrolments-only) becomes a mode-agnostic refresh loop running in **all** daemon modes (CLI, web, headless). Each tick re-runs the loader — a conditional GET with `If-None-Match`, so an unchanged document costs one cheap 304 — and diffs the dynamic sections:

- **enrolments** changed → existing `Manager`/`RefreshManager`/`WatchManager.UpdateConfig` fan-out, plus the web server's enrolment runner is rebuilt (deferred to the next tick if an enrolment is mid-run);
- **rules / sync.interval** changed → new `sync.Engine.UpdateConfig` (swap under the engine mutex, prune state-store entries for removed rules, reset the loop ticker, trigger an immediate sync) and the web server's rule/sync snapshots are swapped under a new lock.

Live-propagation matrix (v1):

| Change | Propagates without restart? |
|--------|------------------------------|
| rules added/changed/removed | yes (next refresh tick) |
| enrolments added/changed/removed | yes (next refresh tick) |
| `sync.interval` → sync engine + refresh loop | yes |
| `sync.interval` → WatchManager poll cadence | no — fixed at construction (documented limitation) |
| anything in static sections | n/a — local-only; local changes still require a restart, as today |

`dotvault status` and `GET /api/v1/status` gain a `remote_config` block: url, source (`remote`/`cache`/`none`), etag, last attempt/success, last error. The web UI's Effective Configuration screen and `GET /api/v1/config/download` export the **effective merged** config — that is the screen's documented purpose. The export carries the `remote_config` section, and re-importing it as a base converges because the merge is idempotent.

## Trust model and security notes

- **The service operator is trusted equivalently to the local config admin.** Remote rules direct where secrets are written on disk and templates can read environment variables — this was already true of the local config; the remote channel does not widen what config *can* do, only who can author it. The integrity boundary is TLS: HTTPS mandatory (loopback exempt for dev), optional `ca_cert` pinning, no skip-verify.
- The static-key rejection bounds the blast radius of a compromised service: it cannot move the Vault, open listeners, or alter telemetry.
- Spoofed dimension headers are accepted by design — anyone may fetch anyone's document, so **layers must never contain secrets**. Enrolment settings are non-secret by contract; OTLP tokens already have the `EnvironmentFile` path and observability is local-only anyway.
- The service itself authenticates only to its storage backend (Vault via Kubernetes auth in production); it never holds user credentials.

## The `dotvault-config` service

A small Go HTTP service in this repo: `cmd/dotvault-config` (Cobra: `serve`, `seed`, `compose` for debugging a composition offline, `version`), packages under `internal/configsvc/`.

### Layers and composition

> **Superseded note (2026-06-12):** the fixed composition order described here became the *default* of a configurable model — layers are now addressable by any dimension combination under an operator-declared `composition.order`; see `2026-06-12-multi-dimension-composition.md`.

Layer documents are Partials stored under canonical keys, composed in fixed order with `MergePartial`:

```
global  →  os/<os>  →  group/<g> (each, sorted)  →  user/<user>
```

Group order is `sort.Strings` for determinism — the composed bytes must be stable so the ETag (`sha256` of the document) is stable. A present-but-corrupt layer is a 500 naming the layer key, never a silently dropped layer. Missing layers skip silently; an unknown user composes to global+os, which is valid. The Sydney/New York/London story: each office is a group layer carrying its region's enrolments and rules; membership in two groups yields the additive union.

### HTTP API

| Route | Behaviour |
|-------|-----------|
| `GET /v1/config` | requires `X-Dotvault-OS` + `X-Dotvault-User` (400 otherwise); composes; `If-None-Match` match → 304; else 200, `Content-Type: application/yaml`, `ETag`, `Cache-Control: no-cache` |
| `GET /healthz` | liveness |
| `GET /readyz` | readiness — gated on storage `Ping` |

No client auth. No loopback-binding invariant — unlike the daemon's web UI, this is a deployable network service; TLS is expected to be terminated by the operator's ingress or the service's own listener config.

### Storage abstraction

Following the ghp pattern (`Store` interface, driver factory, separate Vault constructor):

```go
type Store interface {
    GetLayer(ctx, key) ([]byte, bool, error)
    PutLayer(ctx, key, doc) error
    DeleteLayer(ctx, key) error
    ListLayers(ctx, prefix) ([]string, error)
    GetGroups(ctx, user) ([]string, bool, error)   // static resolver backing
    PutGroups(ctx, user, groups) error
    Ping(ctx) error
    Close() error
}
func Open(ctx, driver, dsn string) (Store, error)   // "sqlite" (modernc.org/sqlite — pure Go, CGO stays off)
func OpenVault(ctx, VaultStoreConfig) (Store, error)
```

- **SQLite** (dev/test): tables `layers(key TEXT PRIMARY KEY, doc BLOB, updated_at TEXT)` and `groups(username TEXT PRIMARY KEY, groups TEXT)`.
- **Vault KVv2** (production): document as a single `doc` field at `<mount>/data/<path>/layers/<key>`, group membership at `<path>/groups/<user>`. Auth methods `token` (dev) and `kubernetes`: POST `auth/<k8s_mount>/login` with the service-account JWT **re-read from disk on every login** so projected-token rotation needs no restart; re-login on 403/lease expiry. Built directly on `github.com/hashicorp/vault/api` — the daemon's `internal/vault` is deliberately not reused (it carries events/MFA machinery a storage driver doesn't want).

### Group resolution

`groups.Resolver` interface with a TTL cache wrapper and two implementations: **static** (membership maps in the store — dev/test and small fleets) and **LDAP** (`github.com/go-ldap/ldap/v3`, pure Go) for the directory-driven case that motivates this design.

### Seeding / config-as-code

`dotvault-config seed --dir <layers>` walks `global.yaml`, `os/*.yaml`, `group/*.yaml`, `user/*.yaml` and an optional `groups.yaml` (static membership), validates everything via `ParsePartial` + `Validate` **before any write**, then writes. The same command works against both backends, giving CI a publish step: layers live in a git repo, CI seeds Vault on merge.

## Build and dev environment

New Makefile target and GoReleaser build id for `dotvault-config` (linux + darwin; no Windows service binary in v1). Dev workflow: `configsvc.dev.yaml` (sqlite, `127.0.0.1:9100`, static groups), fixtures under `dev/remote-layers/`, a `serve --seed <dir>` convenience flag, a third `.claude/launch.json` Preview configuration, and `config.dev.yaml` gains `remote_config: {url: http://127.0.0.1:9100/v1/config}` (loopback, so plain HTTP is allowed).

## Testing

- Merge/Partial: table-driven (by-name replace, append order, enrolment override, static-key rejection, unknown-key tolerance, zero-rules-with-url validation).
- Fetcher: `httptest` tables — ETag round-trip then 304, 5xx/refused → cache fallback, no-cache → base-only, header assertions, 0600 cache mode, identity-mismatch ignores cache, 1 MiB body cap, static-key document rejected.
- Regfile: `remoteconfig` round-trip tests mirroring the observability ones; registry loader tests stay `//go:build windows`.
- Engine/web: rule swap + state prune + ticker reset; `-race` over concurrent update-vs-read; enrolment-runner update refusal while running.
- Service: store conformance suite (sqlite `:memory:`, reusable for future drivers), Vault store under `test/integration/`, compose golden tables (precedence, determinism, multi-group union), `httptest` endpoint tests, seed fixture with a deliberately invalid layer.

## Future work

Deletion tombstones; service-side composed-response caching keyed by (os, user, groups); layer kinds keyed on extra dimension headers; WatchManager cadence propagation; a `postgres` store driver (the factory and conformance suite leave the slot open).

## Files Changed

| File | Change |
|------|--------|
| `internal/config/remote.go` | New — `RemoteConfig` section + validation |
| `internal/config/partial.go` | New — `Partial`, `ParsePartial`, `Validate` |
| `internal/config/merge.go` | New — `ApplyPartial`, `MergePartial` |
| `internal/config/config.go` | `RemoteConfig` field; `LoadRaw`/`LoadSystemRaw`/`Validate` seam; ≥1-rule gate conditional on remote URL; `validateRule` extraction |
| `internal/config/registry_windows.go` | `RemoteConfig` subkey + `Headers` in the live loader |
| `internal/regfile/regfile.go`, `parse.go` | Render/parse the `RemoteConfig` section |
| `internal/remoteconfig/` | New — fetcher, cache, status |
| `internal/observability/observability.go` | `RecordRemoteConfigFetch` counter |
| `cmd/dotvault/main.go` | Raw loaders + `withRemote`/`withLocalOnly` wrapping; mode-agnostic refresh loop; status output |
| `internal/sync/engine.go`, `state.go` | `UpdateConfig`, ticker reset, `StateStore.Prune` |
| `internal/web/server.go`, `api.go`, `oauth.go` | Rule/sync locking, `UpdateDynamicConfig`, `UpdateEnrolments`, status + effective-config surfacing |
| `cmd/dotvault-config/`, `internal/configsvc/` | New — the service (server, compose, store, groups, seed) |
| `Makefile`, `.goreleaser.yml`, `config.dev.yaml`, `configsvc.dev.yaml`, `.claude/launch.json`, `dev/remote-layers/` | Build + dev wiring |
| `docs/configuration/remote-config.md`, `docs/services/dotvault-config.md`, `docs/admin/windows-gpo.md`, `CLAUDE.md` | Documentation |
