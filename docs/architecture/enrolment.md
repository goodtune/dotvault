# Enrolment engines

> Carved from CLAUDE.md. The engine interface and per-engine flows. User-facing equivalents live under `docs/services/`.

## Enrolment

Automated credential acquisition from external services (`internal/enrol/`). Enrolments are declared in config under a top-level `enrolments` map keyed by Vault KV path segment.

Enrolment keys support one level of grouping (`group/name`, e.g. `databricks/prod`) so related enrolments cluster under a shared prefix. The key is treated as an opaque segment everywhere it flows: the Vault path nests naturally (`users/<you>/databricks/prod`); the web UI groups by the prefix-before-slash and renders an expandable folder (the Enrolments nav in `internal/web/ui.go`); the enrolment page URL carries the key percent-encoded (`uiEnrolPageURL`); and the Windows registry / `reg-import`/`reg-export` round-trip stores the key as one subkey literally named `databricks/prod` (a forward slash is legal in a registry key *name* — only backslash is the separator — so no nesting is introduced and the GPO-parity contract holds). `validateEnrolmentKey` (`internal/config/config.go`) enforces the one-level limit.

### Engine Interface

Engines implement `Name()`, `Run(ctx, settings, io)`, and `Fields()`. Registered in a package-level map. Currently implemented: GitHub (OAuth device flow), JFrog (browser-based web login), Databricks (OAuth U2M authorization-code + PKCE), ghp (CLI device-authorization flow against a self-hosted ghp server), SSH (Ed25519 key generation), Copy (mirror an existing KVv2 secret).

Optional interfaces extend the contract for engines that need them:

- `SettingsFielder.FieldsFromSettings(settings)` — engines whose written-field set depends on per-enrolment settings (currently the Copy engine, where the JSON template determines the keys). The manager and web runner use `EngineFields(engine, settings)` which falls back to `Fields()` when not implemented.
- `Refresher.Refresh(ctx, settings, existing)` — engines whose credentials expire and can be rotated without user interaction (currently JFrog and Databricks). Driven by `RefreshManager`.
- `Unattended.Unattended() bool` — engines that acquire their credential with no user involvement at all (currently only Copy). The first-run web wizard excludes these entirely — from the decision to show it, in both directions, and from the page itself (`wizardStates`), since a card the user cannot act on is noise on a page about the work they must do; they stay available under `/ui/enrolments/`. On the decision: an unattended enrolment gives the user nothing to do so it cannot trigger the wizard, and — the bug this closes — because it completes on its own it must not count as "something is already enrolled", which previously suppressed the wizard for the interactive enrolments that genuinely needed one. A capability rather than a name check, so a future unattended engine inherits the rule by declaring it. Engines that don't implement it are treated as interactive, the safe default.
- `Watcher.WatchSources(settings, username) []WatchSource` — engines whose output is derived from upstream Vault data and must track source changes (currently Copy). Driven by `WatchManager`, which polls every sync interval and (on Enterprise Vault) reacts to source-write events within seconds.

### GitHub Engine Defaults

- Client ID: `178c6fc778ccc68e1d6a` (GitHub CLI's OAuth app)
- Scopes: `repo`, `read:org`, `gist`
- Host: `github.com`

Overridable via settings: `client_id`, `scopes`, `host`. Returns `{"oauth_token": "<token>", "user": "<username>"}`.

Outbound HTTPS (device-code request, polling, and the post-flow `/user` lookup) is routed through `internal/httpproxy`. By default the resolver consults the host's native proxy machinery — on Windows that's `ieproxy.GetProxyFunc()`, which evaluates the IE/WinHTTP configuration (PAC scripts included) once per request, so a policy returning DIRECT for one host and a proxy for another is honoured. On Linux and macOS the resolver falls back to `http.ProxyFromEnvironment` (HTTP_PROXY / HTTPS_PROXY / NO_PROXY); native CFNetwork detection on macOS would require CGO and is deliberately avoided. A per-enrolment override is available via the `https_proxy` (or `http_proxy`, accepted as an alias) setting — when set, every request is pinned to that URL and host-conditional PAC routing is bypassed, by design. The override accepts the `http`, `https`, `socks5`, and `socks5h` schemes; anything else fails at config-load. The settings adapter lives in `internal/httpproxy.ClientFromSettings` so the JFrog engine and any future HTTP-talking package can opt in to the same YAML key contract without duplication (#76). Example:

```yaml
enrolments:
  gh:
    engine: github
    settings:
      https_proxy: http://squid.example.com:3128
```

### JFrog Engine

Mirrors the `jf login` web login flow from `jfrog-cli`, then mints a dotvault-owned refreshable token with a configurable TTL. No public OAuth app exists — JFrog Platform hosts its own browser login endpoint, so the engine just requires the platform URL.

Required settings:
- `url` — JFrog Platform URL (e.g. `https://mycompany.jfrog.io`)

Optional settings:
- `token_ttl` — lifetime of the dotvault-minted access token. Accepts `time.ParseDuration` syntax plus `Nd` for whole days (e.g. `60d`, `6h`, `10m`). Default `60d`. Floor `10m` — validated at config-load time. Non-admin users can mint refreshable tokens at any non-zero TTL; only the never-expire case (`expires_in=0`) requires admin.
- `client_name`: `JFrog-CLI` (sent as `jfClientName` query parameter)
- `client_code`: `1` (sent as `jfClientCode` query parameter)

Flow (enrolment — runs once per user):
1. POST `{url}/access/api/v2/authentication/jfrog_client_login/request` with a random UUID
2. Open `{url}/ui/login?jfClientSession=<uuid>&jfClientName=JFrog-CLI&jfClientCode=1` — user confirms the last 4 chars of the UUID after sign-in
3. Poll GET `{url}/access/api/v2/authentication/jfrog_client_login/token/<uuid>` until 200 — returns a bootstrap token with the JFrog server default TTL (typically 1 year)
4. POST `{url}/access/api/v1/tokens` with `Authorization: Bearer <bootstrap>` and `{"expires_in":<token_ttl_seconds>,"refreshable":true,"scope":"applied-permissions/user","include_reference_token":true}` — mints the dotvault-owned pair; the bootstrap token is discarded. v1 rather than v2 because v2 is admin-only on most JFrog deployments (non-admins and older Artifactory versions see it as a 404); v1 has been the self-token endpoint since Artifactory 7.21.1 and is what `jfrog-client-go` uses. `include_reference_token` is always sent so the response also carries an opaque `reference_token` alongside the JWT `access_token`; on servers older than Access 7.38.4 the field is simply absent and `reference_token` is stored empty.

Flow (refresh — periodic, driven by `RefreshManager`):
1. Every `check_interval` (daemon-wired at 5 min), iterate all enrolments whose engine implements `Refresher`
2. For each, read the secret and skip unless `now >= issued_at + (expires_at - issued_at) / 2`
3. POST `{url}/access/api/v1/tokens` with `grant_type=refresh_token&access_token=<current>&refresh_token=<current>&include_reference_token=true` — **JFrog rotates both tokens (and the reference token) on every successful refresh**, so the old refresh_token is invalid immediately
4. Stamp new `issued_at: now`, `expires_at: now + token_ttl` (dotvault's configured TTL, not whatever JFrog returns), write the replacement map atomically
5. `401`/`403` from the refresh endpoint is treated as permanent revocation — the secret is deleted from Vault and the user is prompted to re-enrol. Other errors are transient; the existing secret is kept and retried with exponential backoff

Vault schema (8 fields): `access_token`, `refresh_token`, `reference_token`, `url`, `server_id`, `user`, `issued_at` (RFC3339), `expires_at` (RFC3339). The rendered `jfrog-cli.conf.v6` only contains `accessToken` — `refreshToken` and `webLogin: true` are deliberately omitted so `jf` never attempts its own refresh (which would race the sync-engine clobber). `reference_token` is the opaque equivalent of the JWT access token — useful where a compact credential is preferred (Docker/registry logins, clients that choke on long JWTs). It is captured unconditionally but not written to any target by default; a sync rule opts in by referencing `{{ .reference_token }}` in its template.

`server_id` is deduced from the platform hostname (e.g. `mycompany.jfrog.io` → `mycompany`, IP addresses → `default-server`); `user` is extracted from the access-token JWT subject. Requires JFrog Artifactory 7.64.0 or newer on the remote side. `reference_token` additionally requires Access 7.38.4 or newer; older servers leave it empty.

`reference_token` and `user` are written when available but are deliberately excluded from the engine's `Fields()` set, so `enrol.Manager.HasAllFields` does not reject enrolments on deployments that don't return them.

### Databricks Engine

Replicates the `databricks auth login` OAuth user-to-machine (U2M) flow: an authorization-code grant with PKCE against the workspace (or account) OAuth endpoints, caught by a localhost redirect listener. Databricks access tokens are short-lived (~1 hour), so the engine implements `Refresher` and dotvault owns the rotation — the rendered credential carries only the access token (the native CLI token cache is intentionally not written, so nothing races the sync-engine clobber). This is the same ownership model as JFrog.

Required settings:
- `host` — the Databricks workspace URL (https, scheme + host only, no path; e.g. `https://dbc-xxxx.cloud.databricks.com`). For account-level login, the accounts console URL. (This is the Databricks analogue of the JFrog engine's `url` setting.)

Optional settings:
- `account_id` — when set, the engine performs account-level login (`{host}/oidc/accounts/{account_id}/…`) instead of workspace login.
- `client_id` — default `databricks-cli` (the CLI's public OAuth app). Override only for a custom registered OAuth app that also registers the `http://localhost:8020`–`8040` redirect range.
- `scopes` — default `offline_access all-apis`. A custom list is honoured verbatim except `offline_access` is always ensured (it yields the refresh token dotvault rotates with).
- `https_proxy` / `http_proxy` — same `internal/httpproxy.ClientFromSettings` contract as GitHub/JFrog; routes the OAuth + SCIM traffic.

Flow (enrolment — runs once per user):
1. GET `{host}/oidc/.well-known/oauth-authorization-server` (account-level inserts `/oidc/accounts/{account_id}`) to discover `authorization_endpoint` and `token_endpoint`.
2. Bind a loopback redirect listener (prefer port 8020, walk up to 8040, matching the CLI). Generate a PKCE verifier + `S256` challenge and an anti-CSRF `state`.
3. Open the browser to the authorization endpoint (`client_id=databricks-cli`, redirect URI, `response_type=code`, scopes, PKCE challenge). The user signs in; Databricks redirects back to the loopback with a `code`. The handler validates `state`.
4. POST `token_endpoint` with `grant_type=authorization_code` + `code_verifier` (public client, params in the body) → access + refresh token + `expires_in`.
5. Best-effort `GET /api/2.0/preview/scim/v2/Me` resolves the username (the access token is opaque to dotvault).

Flow (refresh — periodic, driven by `RefreshManager`): every check interval, refresh past half-life via `grant_type=refresh_token`. Databricks may rotate the refresh token (adopted when returned, otherwise the existing one is kept). `401`/`403` is permanent revocation (`ErrRevoked` → wipe + re-enrol); other errors are transient.

Vault schema: `access_token`, `refresh_token`, `host`, `issued_at` (RFC3339), `expires_at` (RFC3339), plus `user` (from SCIM `/Me`, written when available). `user` is deliberately excluded from `Fields()` so a transient SCIM failure doesn't mark an enrolment incomplete. The typical sync rule renders `~/.databrickscfg` (INI) with `host` + `token = {{ .access_token }}` — an OAuth access token is accepted wherever a PAT is, and dotvault keeps it fresh.

### SSH Engine

Generates Ed25519 key pairs in OpenSSH format. Returns `{"public_key": "<ssh-ed25519 ...>", "private_key": "<PEM>"}`. The public key comment is `{username}@dotvault`.

Passphrase mode controlled via settings `passphrase` field:
- `"required"` (default) — user must provide a passphrase; fails if empty
- `"recommended"` — user prompted but can skip
- `"unsafe"` — no passphrase (unencrypted private key)

No external dependencies beyond `golang.org/x/crypto/ssh`.

### Copy Engine

Mirrors an existing KVv2 secret into the user's enrolment path, optionally
transforming its shape via a JSON template. Useful when other tooling (or a
separate operator workflow) populates a per-user secret under a shared prefix
(e.g. `apps/<app>/keys/<user>`) and dotvault needs to expose that value to
the user under their own path with potentially different field names.

Required settings (nested map):

- `from.mount` — source KV mount (e.g. `kv`)
- `from.path` — source path; supports a `{{.user}}` substitution that resolves to the authenticated Vault username (`token_meta_username`)
- `format` — must be `json` (only supported format)
- `template` — Go template producing JSON; receives `{ "data": <source secret data>, "user": <username> }` as dot context. Top-level keys of the rendered JSON become the fields written to the target.

Behaviour:

- Only `json` format is supported; the rendered output must parse as a JSON object whose values are strings (or are coerced to strings).
- The target secret is **merged**, not replaced — keys produced by the template are written, but pre-existing keys at the target that the template does not name are preserved. This makes it safe for multiple operators / processes to maintain different fields under the same user path.
- The set of fields the engine writes is derived dynamically from the template's top-level JSON keys (via the `SettingsFielder` interface). The manager treats the enrolment as complete when those fields are present in the target, just as for static-field engines.
- Preserved values are **stringified**, not type-preserved: the engine flattens the returned data to `map[string]string`, so any pre-existing object/number/bool field at the target is JSON-marshalled to its textual form before being written back. This is intentional (the engine contract is `map[string]string` and dropping non-strings would lose data) but means the copy engine should not be co-tenanted with workflows that depend on KVv2 fields keeping their original JSON type.

The Copy engine also declares `Unattended`: it needs no user involvement, so the web UI's first-run wizard neither counts it in deciding whether to appear nor renders a card for it (see Web UI → First-run enrolment wizard); it is managed from `/ui/enrolments/` like any other. Everywhere else it is ordinary pending work.

Periodic refresh:

- The Copy engine implements `Watcher`, so the daemon's `WatchManager` re-evaluates each copy enrolment on every poll cycle (defaults to the sync interval) and writes back only when the merged result differs from the current target — avoiding spurious KVv2 versions.
- On Vault Enterprise, the WatchManager also subscribes to the `kv-v2/data-write` event type and filters incoming events client-side against the configured source paths, triggering an immediate refresh when a matching source secret is updated. Failures degrade gracefully to poll-only, mirroring the sync engine's reconnection behaviour.

### Manager & Wizard

The Manager checks Vault for missing/incomplete secrets, then runs the Wizard for any pending enrolments. The Wizard runs engines sequentially with terminal progress display and best-effort clipboard support (via `internal/clipboard`, shared with the remote-clipboard peer action). On success, credentials are written to Vault KVv2, and the sync engine is triggered.

Config changes to the enrolments section are detected on each polling tick without requiring a daemon restart.

### Browser-based enrolment in the web UI

Several engines drive an interactive browser login (GitHub device flow, JFrog web login, Databricks OAuth U2M). These present an **actionable URL** to the user and then block on a result — a poll (GitHub/JFrog) or a loopback redirect listener (Databricks). The contract that makes these render correctly in the web UI, and the bug class to avoid:

- The web enrol runner (`internal/web/enrol_runner.go`) deliberately builds `enrol.IO` **without** a `Browser` opener (unlike the CLI paths in `cmd/dotvault/`, which set `Browser: browser.OpenURL`). The daemon must not pop a browser on a possibly-headless host, and the loopback web UI is the user's actual surface — so each engine's `io.Browser == nil` branch fires and it writes the login URL to `io.Out` rather than opening anything server-side.
- The enrolment card (`internal/web/ui_enrol.go` + `uitmpl/enrol_card.tmpl`) parses the engine's line-oriented output and renders one of: a **device-code card** when a `! First, copy your one-time code: X` line **and** an `https://` URL are present (GitHub/JFrog); a **redirect card** when only an `https://` URL is present with no code (Databricks); a **passphrase prompt** (ssh); or a raw-output fallback. Both the device-code and redirect cards expose a real **clickable "Open <service> →" anchor** — a genuine user gesture, so it isn't swallowed by pop-up blockers the way a programmatic `window.open` would be. The user clicks it, authenticates, and the card flips to the progress/complete state as the engine's output advances.
- **The failure mode this guards against:** a browser-login engine whose output the card doesn't recognise falls through to the raw-output branch and the user just sees the bare URL dumped into a code block with nothing to click — a "terminal flow in the browser". This was fixed for GitHub/JFrog (the device-code card) and then again for Databricks (the redirect card, which exists precisely because a pure authorization-code+PKCE flow has no user code to key the device-code card on).
- **When adding a new browser-driven engine,** emit the actionable URL to `io.Out` in a form the card already recognises (a line containing an `https://` URL, plus the `! First, copy your one-time code: X` line if and only if there is a user code), and attempt `io.Browser` only inside the non-nil branch. If the new flow has a genuinely new shape, add a matching branch to `uitmpl/enrol_card.tmpl` (and the state it needs to `buildUIEnrolCard`) rather than letting it land in the raw-output fallback. Verify the web experience, not just the CLI — the CLI path opens a real browser via `io.Browser` and can mask a missing web card. Note a card that is waiting on `io.PromptSecret` deliberately stops polling (a patch would clobber the half-typed value), so a new prompting state must render its own form rather than relying on the refresh.

