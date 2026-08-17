# Web UI

dotvault includes an optional web-based dashboard built as a Preact single-page application. It provides browser-based authentication, status monitoring, and secret inspection. Alongside the SPA, the same daemon serves a **server-rendered UI at `/ui/`** with bookmarkable URLs — see [Server-rendered UI](#server-rendered-ui-ui) below.

## Enabling the web UI

```yaml
web:
  enabled: true
  listen: "127.0.0.1:9000"
```

!!! danger "Loopback only"
    The `listen` address **must** be a loopback address (`127.0.0.1`, `[::1]`, or `localhost`). dotvault will refuse to start if a non-loopback address is configured. This is a hard security constraint that cannot be overridden.

## Features

### Authentication

The web UI supports every auth method:

- **OIDC** — "Login with OIDC" button redirects to the identity provider
- **LDAP** — username/password form with inline MFA handling (Duo push and TOTP)
- **Token** — paste a Vault token to authenticate
- **mTLS** (`mtls`, `mtls+tpm`, `mtls+os`) — certificate auth needs no credential in normal operation, so there is no recurring login. The one and only interactive moment is the **one-time certificate bootstrap** on a new host, which presents whichever of the LDAP or OIDC forms above `vault.mtls.bootstrap_method` names, framed as an enrolment. Because the daemon still has to sign and install the certificate after that login returns, the page then polls `/api/v1/status` until the daemon holds a token. This is what lets a host with no terminal bootstrap — notably `dotvaultw.exe`, the GUI-subsystem Windows binary with no console. *Before this was wired the SPA had no branch for certificate auth at all and rendered an "Unknown auth method: mtls" error card instead of a login page.*

Note that `POST /auth/token/login` is refused with **403** under certificate auth: there the operational token comes from the certificate login alone, so pasting one would install a credential the certificate flow never sanctioned.

### Status dashboard

Shows at a glance:

- Authentication state and Vault token TTL
- Vault server address and KV mount configuration
- Per-rule sync status (last synced, secret version)
- Username and user prefix

### Secret inspection

Browse and inspect secrets synced by dotvault. Secrets are hidden by default and require explicit reveal (`?reveal=true`). Nested Vault paths — such as a grouped enrolment written under `databricks/prod` — render in the sidebar as expandable folders that lazy-load their contents on first open, mirroring the grouped layout on the enrolment screen.

### Manual sync

Trigger an immediate sync cycle from the dashboard without waiting for the next poll interval.

### Copy Vault token

A clipboard icon in the header bar allows you to copy the current active Vault token to the clipboard. This lets you authenticate directly to the Vault web UI using your existing token, avoiding a repeated multi-factor authentication flow.

## Customisable content

You can display markdown text on the login page and secret view page:

```yaml
web:
  enabled: true
  listen: "127.0.0.1:9000"
  login_text: |
    Welcome to **dotvault**. Click Login to authenticate via your
    organisation's single sign-on.
  secret_view_text: |
    These secrets are synchronised from Vault. Contact IT support
    if you need additional credentials provisioned.
```

## Server-rendered UI (`/ui/`)

Browsing to `http://127.0.0.1:9000/ui/` (whatever your `web.listen` is) serves a parallel, server-rendered surface with real, bookmarkable URLs. It reuses the SPA's stylesheet so the look and feel matches, but navigation moves into a left-hand accordion — **Enrolments**, **Remotes**, **Secrets** — where each section expands when its route is active:

- `/ui/` — the index page: the SPA-style header (version, connection state, Vault link on the left; live "Updated" time, Config, copy-token, and Sync Now on the right) plus the configured `secret_view_text` markdown in the content column. The "Updated" time is a live value streamed over Server-Sent Events.
- `/ui/secrets/` — Secrets panel expanded; `/ui/secrets/<key>` shows a secret (heading linked to the secret in the Vault UI, revision subheading, and a field/value/actions table). Values are masked until the eye icon reveals them — the reveal auto-hides after 30 seconds — and the clipboard icon copies the value **server-side**: the secret never travels to the browser at all.
- `/ui/enrolments/` — Enrolments panel expanded, grouped by engine (an engine nests into a folder only when it has more than one enrolment) with a status dot per entry: green = enrolled, orange = in progress, red = error, grey = not started. `/ui/enrolments/<engine>/<key>/` is where the enrolment itself runs.
- `/ui/remotes/` — managed SSH forwards with the same status-dot vocabulary (green = connected, orange = connecting, red = enabled but disconnected, grey = disabled) and an add form revealed by the Add button; `/ui/remotes/<host>/` edits one remote (port, remote socket, enabled switch, delete) and shows its pinned host key — the SHA256 fingerprint with the full key revealable on demand, or a note when trust comes from a configured certificate authority instead. Adding an unpinned host presents the same fingerprint-confirmation gesture as the SPA and CLI. Both pages subscribe to a live state stream (`/ui/sse/ssh`), so state and configuration changes — a forward connecting or dropping, a remote edited, added, or removed, including asynchronously by `dotvault ssh` or the daemon's own reconnect loop — appear without refreshing the page.
- `/ui/config/` — the Effective Configuration view, with the left navigation kept in place.

Interactivity comes from [datastar](https://data-star.dev) patching server-rendered fragments over SSE; there is no client-side application state. An unauthenticated visit to any `/ui/` page redirects to the SPA at `/`, which owns all login flows.

## Security

- **CSRF protection** — all mutating SPA API endpoints require a CSRF token (obtained from `GET /api/v1/csrf`), with three deliberate exceptions: the peer-action endpoints `POST /api/v1/remote/browse`, `POST /api/v1/remote/notify`, and `POST /api/v1/remote/clipboard` (see below). The server-rendered `/ui/` surface uses a different but equivalent control for its POSTs: a **required same-origin `Origin` header** — browsers attach one to every POST, so a cross-site request (or one with no Origin at all) is rejected, which suits server-rendered forms and multi-tab use better than a one-shot token
- **Content Security Policy** — `default-src 'self'; frame-ancestors 'none'` prevents XSS via injected scripts and clickjacking via framing. `/ui/` responses additionally allow `'unsafe-eval'` for scripts (datastar compiles its `data-*` attribute expressions with the Function constructor) and inline styles; inline scripts remain forbidden on both surfaces
- **X-Content-Type-Options** — `nosniff` header on all responses
- **Loopback binding** — enforced at startup; non-loopback addresses are rejected

## API endpoints

The web UI communicates with the dotvault daemon via a REST API:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/status` | Server status, auth state, token TTL, sync state, certificate-bootstrap state |
| `GET` | `/api/v1/rules` | Configured sync rules |
| `GET` | `/api/v1/token` | Current Vault token (authenticated sessions only) |
| `GET` | `/api/v1/secrets/{path}` | List or reveal a secret |
| `POST` | `/api/v1/sync` | Trigger immediate sync (CSRF-protected) |
| `POST` | `/api/v1/remote/browse` | Open a form-posted `url` in this host's default browser (not CSRF-protected) |
| `POST` | `/api/v1/remote/notify` | Raise a form-posted desktop notification on this host (not CSRF-protected) |
| `POST` | `/api/v1/remote/clipboard` | Put form-posted `text` on this host's clipboard (not CSRF-protected) |
| `GET` | `/api/v1/csrf` | Obtain a one-time CSRF token |

`POST /api/v1/remote/browse` is the outbound counterpart of `GET /api/v1/token`: over the same SSH-forwarded Unix socket that lets a headless peer borrow the workstation's token, it lets the peer hand a URL back so browser-driven flows open where a browser actually exists — see [`dotvault browse`](cli.md#dotvault-browse). It accepts a form POST (`url=https://...`, body only — the query string is ignored) and only `http`/`https` URLs with a host and no embedded `user:pass@` credentials; `file://` and custom protocol schemes are rejected before anything reaches the OS URL opener, and only one browser open runs at a time (concurrent requests get a 503). It is deliberately exempt from the CSRF handshake: its consumer is a bare `curl`/`dotvault browse` POST with no practical way to run the issue-then-spend token dance, and it reads no state and returns nothing sensitive. Cross-site browser traffic is rejected by an `Origin` check instead — browsers always attach an `Origin` header to cross-origin POSTs, and only the daemon's own origin (a loopback hostname on the daemon's own listener port — a page served by any *other* loopback server does not qualify) is accepted; curl and the CLI send no `Origin` and pass.

`POST /api/v1/remote/notify` is the same idea for desktop notifications — see [`dotvault notify`](cli.md#dotvault-notify). It accepts a form POST with `level` (one of `info`, `warning`, `error`, `attention`), `title`, an optional `body`, and an optional `action_url`, and raises a native notification (Windows toast / macOS Notification Center / Linux D-Bus). `action_url` (http/https, the same allowlist as browse) makes the notification open that URL when clicked on Windows, and is appended to the body on macOS/Linux where a one-shot notification cannot be made clickable. It shares the browse endpoint's security posture exactly: no CSRF, the same `Origin` check, body-only fields, and a single-flight bounded delivery. Its input-validation control restricts `level` to the known set, validates `action_url` against the http/https allowlist, and sanitizes `title`/`body` — stripping control characters and neutralizing the metacharacters that would otherwise break out of the Windows toast backends (an XML CDATA section and a PowerShell here-string), so a crafted notification cannot inject toast XML or execute a PowerShell subexpression on the delivering host. Log lines record the level and field lengths only, never the title/body text or the `action_url` (arbitrary, potentially capability-bearing content that may name secret systems).

`POST /api/v1/remote/clipboard` is the third peer action — see [`dotvault clipboard`](cli.md#dotvault-clipboard). It accepts a form POST with a single `text` field (body only — a URL is the last place a secret should travel) and places the value on this host's clipboard, so a headless peer can stage a one-time token or device code right where the user's paste is after `remote/browse` opened the page that asks for it. It shares the browse/notify security posture exactly: no CSRF, the same `Origin` check, and a single-flight bounded write. Validation rejects input no clipboard can carry faithfully (interior NULs, invalid UTF-8) or that signals a caller bug (empty, over 64 KiB); the text is otherwise written **verbatim** — clipboard content is data, never interpolated into an evaluated context, and the typical payload is a credential that must arrive byte-for-byte intact. This endpoint carries the most secret-bearing payload of the three, so log lines record the text's length only — never the content — and writer errors are additionally scrubbed of the exact text before logging or being returned (best-effort defense in depth; the writers never embed their input in errors).

Auth endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oidc/start` | Redirect to Vault OIDC auth URL |
| `GET` | `/auth/oidc/callback` | Handle OIDC callback |
| `POST` | `/auth/ldap/login` | Start async LDAP login (CSRF-protected) |
| `GET` | `/auth/ldap/status` | Poll login status |
| `POST` | `/auth/ldap/totp` | Submit TOTP passcode (CSRF-protected) |
| `POST` | `/auth/token/login` | Validate and set token (CSRF-protected; 403 under certificate auth) |
