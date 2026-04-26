# JFrog Token Refresh Ownership

**Status:** Design
**Date:** 2026-04-17

## Goal

Make dotvault the owner of JFrog access token lifecycle. Every JFrog enrolment produces a dotvault-minted, refreshable access token with a **configurable, shorter-than-default TTL**. A new background manager detects tokens past half-life and refreshes them in place, writing the rotated pair back to Vault. The sync engine renders only the current access token into the on-disk CLI config, so `jf` never attempts its own refresh.

## Why

1. **Shorter TTL is better security hygiene.** The JFrog server default is 1 year. Admin users — the class most likely to pick dotvault for credential management — deserve *shorter* token lifetimes, not longer. Sixty days is a sensible production default; the dev stack runs at 6 hours to exercise the refresh path in practice.
2. **Refresh token rotation is a correctness hazard under the current design.** JFrog rotates the `refresh_token` on every successful refresh, so any copy outside Vault becomes stale immediately. If `jf` owned refresh (today's template emits `refreshToken` + `webLogin: true`), its in-place rewrites of `jfrog-cli.conf.v6` would race dotvault's sync rule, which clobbers the file on the next tick. Moving refresh ownership into dotvault resolves the race: Vault is authoritative, the sync rule renders only `accessToken`, and `jf` stays a passive consumer.

## Non-Goals

- A `CanRefresh()` bool or other addition to the base `Engine` interface — a new optional `Refresher` sub-interface is enough.
- Refresh for GitHub OAuth tokens, SSH keys, or hypothetical future engines. Only JFrog expires and rotates today.
- A user-facing "refresh now" button in the web UI. Periodic check + refresh-on-daemon-start is sufficient; manual refresh can be added later if needed.
- Persisting per-enrolment refresh state to disk. Vault is authoritative; the manager is stateless between ticks.
- A fallback that retains old refresh tokens in case mid-rotation fails. Either the next tick gets `ErrRevoked` (→ re-enrol) or the transient error clears naturally.
- Migration of existing fat-secret enrolments — there is effectively one (the dev-stack enrolment from the E2E run) and it gets re-enrolled manually during this work.

## Architecture

### New: `Refresher` sub-interface (`internal/enrol/engine.go`)

```go
// Refresher is implemented by engines whose credentials expire and can be
// rotated without user interaction. Today only JFrog implements it.
type Refresher interface {
    Engine

    // Refresh takes the current Vault secret body and returns a replacement.
    // The returned map overwrites the whole Vault secret (it must contain
    // every field the engine still cares about, including a new expires_at).
    //
    // Returns ErrRevoked to signal the upstream credential is permanently
    // gone (401/403) — caller wipes the Vault secret and flags for re-enrol.
    // Any other error is transient; caller keeps the existing secret and
    // retries with backoff.
    Refresh(ctx context.Context, settings map[string]any, existing map[string]string) (map[string]string, error)
}

// ErrRevoked indicates the upstream credential is no longer valid and
// cannot be recovered by refresh.
var ErrRevoked = errors.New("credential revoked upstream")
```

Engines that don't implement `Refresher` are silently skipped by the manager — no impact on GitHub or SSH.

### New: `RefreshManager` (`internal/enrol/refresh.go`)

Modeled on `internal/auth/lifecycle.go`. Constructor:

```go
func NewRefreshManager(
    client *vault.Client,
    kvMount, userPrefix string, // userPrefix already includes username + trailing slash
    enrolments map[string]config.Enrolment,
    checkInterval time.Duration,
    opts ...RefreshManagerOption, // WithClock, WithMaxBackoff — test hooks
) *RefreshManager
```

Design note: decoupling from `*config.Config` means the manager only depends on the slice of configuration it actually uses. `userPrefix` is pre-built by the caller (`cfg.Vault.UserPrefix + username + "/"`), matching the convention used by the enrolment manager.

`checkInterval` is caller-supplied (5 minutes in the daemon, shorter values in tests). Non-positive values are coerced to a safe fallback with a WARN log so `time.NewTicker` cannot panic.

`Start(ctx)` spawns a goroutine that ticks every `checkInterval`. Per tick:

1. Iterate `cfg.Enrolments`. For each key where the engine implements `Refresher`:
2. Read the Vault secret at `{kv_mount}/data/{user_prefix}{username}/{key}`.
3. If the secret has no `expires_at` field, skip (legacy pass-through — see Q2.A in Brainstorming).
4. Parse `issued_at` and `expires_at` as RFC3339. Compute `halfLife := issuedAt.Add(expiresAt.Sub(issuedAt) / 2)`. If `now.Before(halfLife)`, skip.
5. Call `engine.Refresh(ctx, settings, existing)`.
6. **Success**: `vault.WriteKVv2` the returned map (full replace); reset this enrolment's backoff to `checkInterval`.
7. **`ErrRevoked`**: `vault.Delete` the secret, log WARN. No retry — the existing web UI status-polling loop picks up the missing secret and surfaces a fresh `pending` card.
8. **Other error**: log WARN, keep the existing secret, double this enrolment's backoff (capped at 5 min). Backoff is **per-enrolment** so one flaky JFrog instance doesn't stall other refreshes.

### Daemon wiring (`cmd/dotvault/main.go`)

After `auth.LifecycleManager.Start(ctx)`, also start the refresh manager:

```go
rm := enrol.NewRefreshManager(
    vaultClient,
    cfg.Vault.KVMount,
    cfg.Vault.UserPrefix+username+"/",
    cfg.Enrolments,
    5*time.Minute,
)
rm.Start(ctx)
```

The daemon's existing config-reload loop calls `rm.UpdateConfig(reloaded.Enrolments)` alongside `enrolMgr.UpdateConfig` so the refresh manager notices when enrolments are added or removed.

Failures from the refresh goroutine are logged, not bubbled up. Refresh is best-effort — the sync engine continues rendering whatever's in Vault, which degrades gracefully even if refresh is broken.

## Vault Schema

Current JFrog KV secret (8 fields):
`access_token, refresh_token, token_type, expires_in, scope, url, server_id, user`

After this change (7 fields):
`access_token, refresh_token, url, server_id, user, issued_at, expires_at`

Changes:

- **Add `issued_at`** — RFC3339. Stamped when the token is minted (or refreshed).
- **Add `expires_at`** — RFC3339. Stamped as `issued_at + token_ttl`.
- **Drop `expires_in`** — redundant once `expires_at` is absolute; storing both invites drift.
- **Drop `token_type`** — constant `"Bearer"` for JFrog.
- **Drop `scope`** — informational only; neither refresh nor render consumes it.
- **Keep `refresh_token`** — the refresh cycle needs it. Never rendered to disk.

## Config

New optional setting on the JFrog enrolment:

```yaml
enrolments:
  jfrog:
    engine: jfrog
    settings:
      url: "https://mycompany.jfrog.io"
      token_ttl: "60d"    # default if omitted; must be >= 10m
```

- **Engine default**: `60d` (applied in the engine, not by the config loader — keeps loader agnostic).
- **Dev stack** (`config.dev.yaml`): `6h`.
- **Floor**: 10 minutes. Anything smaller is rejected at config load with a clear error.
- **Ceiling**: none — users can set it arbitrarily large, accepting that JFrog might reject values beyond its server-configured maximum (in which case enrolment fails with the server's error, which is fine).

### Duration parsing

Go's `time.ParseDuration` doesn't accept `d`. New helper `config.ParseDuration(s string) (time.Duration, error)`:

- Accepts everything `time.ParseDuration` does.
- Additionally accepts `Nd` where N is a positive integer, converting to hours before parsing. `60d` → `1440h`.
- Returns the standard `time.ParseDuration` error for anything else.

Used for `token_ttl` today; may replace `sync.interval`'s parsing later if we want to be consistent (out of scope for this spec).

## Data Flow

### Enrolment (new — runs once per user, on first enrolment)

1. Web-login flow runs as today through the `jfrog_client_login/token/<uuid>` poll.
2. The token returned is a **short-lived bootstrap token** (JFrog server default TTL, typically 1 year).
3. The engine immediately calls `POST /access/api/v1/tokens` with `Authorization: Bearer <bootstrap>` and body:
   ```json
   {"expires_in": <token_ttl_seconds>, "refreshable": true, "scope": "applied-permissions/user"}
   ```
4. The response yields a **dotvault-owned token pair** (access + refresh) with the configured TTL.
5. Engine stamps `issued_at: now`, `expires_at: now + token_ttl`, returns the 7 fields.
6. Bootstrap token is discarded — it is never used or stored again.

v1 rather than v2: the v2 endpoint is admin-only across every JFrog deployment we've tested, so non-admin callers (and older Artifactory versions) see it as a 404. v1 has been the self-token creation endpoint since Artifactory 7.21.1 — well below our floor of 7.64.0 for the web-login flow itself — and is what `jfrog-client-go` uses for the same operation. Non-admin users can still mint refreshable tokens for themselves via v1 with any non-zero TTL.

### Refresh (periodic — every 5 min)

1. `RefreshManager` tick. For each enrolment whose engine implements `Refresher`:
2. Read Vault secret. Skip if no `expires_at` (legacy). Skip if `now < halfLife`.
3. Call `engine.Refresh(ctx, settings, existing)`.
4. For JFrog, `Refresh` calls `POST /access/api/v1/tokens` with form body `grant_type=refresh_token&access_token=<current>&refresh_token=<current>`.
5. On 200: parse the response, stamp new `issued_at: now`, new `expires_at: now + token_ttl` (dotvault's TTL, **not** whatever JFrog returns), return the full field map.
6. `RefreshManager` writes the returned map to Vault.
7. Sync engine's next tick (already independent, runs on its own schedule) picks up the new Vault version and re-renders `jfrog-cli.conf.v6`.

### Template change (`config.dev.yaml`)

Drop `refreshToken` and `webLogin: true` from the rendered `jfrog-cli.conf.v6`:

```yaml
template: |
  {
    "servers": [
      {
        "serverId": "{{ .server_id }}",
        "url": "{{ .url }}/",
        "artifactoryUrl": "{{ .url }}/artifactory/",
        "distributionUrl": "{{ .url }}/distribution/",
        "xrayUrl": "{{ .url }}/xray/",
        "missionControlUrl": "{{ .url }}/mc/",
        "pipelinesUrl": "{{ .url }}/pipelines/",
        "accessUrl": "{{ .url }}/access/",
        "user": "{{ .user | default "" }}",
        "accessToken": "{{ .access_token }}",
        "isDefault": true
      }
    ],
    "version": "6"
  }
```

Without `refreshToken` in the config, `jf` will not attempt its own refresh. Because dotvault refreshes at half-life and writes the new token to Vault — which triggers the sync engine to re-render the file (via the Events API stream in Enterprise Vault, or the next poll cycle otherwise) — `jf` in steady state always sees a valid, non-expiring-soon access token and never hits a 401 from expiry.

## Error Handling

| Failure | Engine returns | RefreshManager does |
|---------|---------------|---------------------|
| JFrog 401/403 on refresh | `enrol.ErrRevoked` | `vault.Delete(path)`, log WARN, no retry |
| JFrog 5xx | wrapped error | log WARN, per-enrolment backoff, keep secret |
| Network / timeout | wrapped error | log WARN, per-enrolment backoff, keep secret |
| Vault unreachable on write-back | — (manager-side) | log WARN, per-enrolment backoff, retry next tick |
| Secret shape unparseable | — (manager-side) | log ERROR, skip, continue with other enrolments |
| `token_ttl` below 10-min floor | — (config-load time) | daemon refuses to start with clear error |

Per-enrolment backoff means one flaky JFrog doesn't stall refresh of a (future) second JFrog enrolment. Starting delay equals `checkInterval` (5 min), cap 5 min. Since `checkInterval` already equals the cap, backoff in practice just means "don't retry sooner than the next tick". The data structure is in place so longer checkpoint intervals stay safe.

## Testing

1. **`JFrogEngine.Refresh` unit tests.** `httptest.Server` serving `POST /access/api/v1/tokens`. Cases: happy path (new pair returned); 401 → `ErrRevoked`; 403 → `ErrRevoked`; 500 → wrapped error; malformed JSON → wrapped error.
2. **`RefreshManager` unit tests.** Fake clock (new internal `Clock` interface, default `realClock`), fake `vault.Client` (reuse existing test double if present), `Refresher` test double recording calls. Cases: no `expires_at` → skipped; before half-life → skipped; past half-life → `Refresh` called; returned map written back; `ErrRevoked` → `vault.Delete`; transient error → secret intact, backoff doubled.
3. **Config parsing.** `ParseDuration("60d") == 1440h`; `ParseDuration("6h") == 6h`; `ParseDuration("5m")` rejected by `token_ttl` validator (floor check); `ParseDuration("bogus")` returns error.
4. **Engine mint-on-enrol.** Extend `TestJFrogEngine_Run_FullFlow` to also serve `POST /access/api/v1/tokens`, assert the bootstrap token is discarded, the stored TTL matches `settings["token_ttl"]`, and `issued_at`/`expires_at` are present.
5. **Manual verification** against the local Artifactory with `token_ttl: "6h"`: daemon logs should show a refresh at ~3 h, and the Vault version number increments. For a tighter loop, cranking `token_ttl: "10m"` + a test-only `check_interval_seconds: 30` demonstrates full rotation within minutes. Not committed as an automated test.

## Files Touched

| File | Change |
|------|--------|
| `internal/enrol/engine.go` | Add `Refresher` interface and `ErrRevoked` sentinel |
| `internal/enrol/refresh.go` | New file: `RefreshManager` + `Clock` interface |
| `internal/enrol/refresh_test.go` | New file: manager unit tests |
| `internal/enrol/jfrog.go` | Add post-web-login `POST /access/api/v1/tokens`; add `Refresh` method; new schema (issued_at/expires_at; drop token_type/expires_in/scope) |
| `internal/enrol/jfrog_test.go` | Extend for mint-on-enrol; add `Refresh` tests |
| `internal/config/config.go` | Add `ParseDuration` helper; validate `token_ttl` at load |
| `internal/config/config_test.go` | Duration parsing + validation tests |
| `cmd/dotvault/main.go` | Construct and start `RefreshManager` after `LifecycleManager` |
| `config.dev.yaml` | Add `token_ttl: "6h"`; drop `refreshToken` and `webLogin` from template |
| `CLAUDE.md` | Document `token_ttl`, default 60d, refresh semantics, minimal template fields |

## Out of Scope / Follow-Ups

- `CanRefresh()` bool on base `Engine`.
- Web UI "Refresh now" button.
- Refresh support for other engines.
- Config-level `check_interval` for the refresh manager (today it's wired at 5 min; if this becomes load-bearing we can surface it).
- `w` and `y` duration suffixes.
- Converting `sync.interval` to `config.ParseDuration` for consistency.
