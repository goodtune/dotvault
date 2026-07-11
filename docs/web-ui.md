# Web UI

dotvault includes an optional web-based dashboard built as a Preact single-page application. It provides browser-based authentication, status monitoring, and secret inspection.

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

The web UI supports all three auth methods:

- **OIDC** — "Login with OIDC" button redirects to the identity provider
- **LDAP** — username/password form with inline MFA handling (Duo push and TOTP)
- **Token** — paste a Vault token to authenticate

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

## Security

- **CSRF protection** — all mutating API endpoints require a CSRF token (obtained from `GET /api/v1/csrf`), with one deliberate exception: `POST /api/v1/remote/browse` (see below)
- **Content Security Policy** — `default-src 'self'` prevents XSS via injected scripts
- **X-Content-Type-Options** — `nosniff` header on all responses
- **Loopback binding** — enforced at startup; non-loopback addresses are rejected

## API endpoints

The web UI communicates with the dotvault daemon via a REST API:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/status` | Server status, auth state, token TTL, sync state |
| `GET` | `/api/v1/rules` | Configured sync rules |
| `GET` | `/api/v1/token` | Current Vault token (authenticated sessions only) |
| `GET` | `/api/v1/secrets/{path}` | List or reveal a secret |
| `POST` | `/api/v1/sync` | Trigger immediate sync (CSRF-protected) |
| `POST` | `/api/v1/remote/browse` | Open a form-posted `url` in this host's default browser (not CSRF-protected) |
| `POST` | `/api/v1/remote/notify` | Raise a form-posted desktop notification on this host (not CSRF-protected) |
| `GET` | `/api/v1/csrf` | Obtain a one-time CSRF token |

`POST /api/v1/remote/browse` is the outbound counterpart of `GET /api/v1/token`: over the same SSH-forwarded Unix socket that lets a headless peer borrow the workstation's token, it lets the peer hand a URL back so browser-driven flows open where a browser actually exists — see [`dotvault browse`](cli.md#dotvault-browse). It accepts a form POST (`url=https://...`, body only — the query string is ignored) and only `http`/`https` URLs with a host and no embedded `user:pass@` credentials; `file://` and custom protocol schemes are rejected before anything reaches the OS URL opener, and only one browser open runs at a time (concurrent requests get a 503). It is deliberately exempt from the CSRF handshake: its consumer is a bare `curl`/`dotvault browse` POST with no practical way to run the issue-then-spend token dance, and it reads no state and returns nothing sensitive. Cross-site browser traffic is rejected by an `Origin` check instead — browsers always attach an `Origin` header to cross-origin POSTs, and only the daemon's own origin (a loopback hostname on the daemon's own listener port — a page served by any *other* loopback server does not qualify) is accepted; curl and the CLI send no `Origin` and pass.

`POST /api/v1/remote/notify` is the same idea for desktop notifications — see [`dotvault notify`](cli.md#dotvault-notify). It accepts a form POST with `level` (one of `info`, `warning`, `error`, `attention`), `title`, and optional `body`, and raises a native notification (Windows toast / macOS Notification Center / Linux D-Bus). It shares the browse endpoint's security posture exactly: no CSRF, the same `Origin` check, body-only fields, and a single-flight bounded delivery. Its input-validation control restricts `level` to the known set and strips control characters from `title`/`body` so nothing injects into the platform delivery backends. Log lines record the level and field lengths only, never the title/body text (arbitrary user content that may name secret systems).

Auth endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oidc/start` | Redirect to Vault OIDC auth URL |
| `GET` | `/auth/oidc/callback` | Handle OIDC callback |
| `POST` | `/auth/ldap/login` | Start async LDAP login (CSRF-protected) |
| `GET` | `/auth/ldap/status` | Poll login status |
| `POST` | `/auth/ldap/totp` | Submit TOTP passcode (CSRF-protected) |
| `POST` | `/auth/token/login` | Validate and set token (CSRF-protected) |
