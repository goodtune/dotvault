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

Browse and inspect secrets synced by dotvault. Secrets are hidden by default and require explicit reveal (`?reveal=true`).

### Manual sync

Trigger an immediate sync cycle from the dashboard without waiting for the next poll interval.

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

- **CSRF protection** — all mutating API endpoints require a CSRF token (obtained from `GET /api/v1/csrf`)
- **Content Security Policy** — `default-src 'self'` prevents XSS via injected scripts
- **X-Content-Type-Options** — `nosniff` header on all responses
- **Loopback binding** — enforced at startup; non-loopback addresses are rejected

## API endpoints

The web UI communicates with the dotvault daemon via a REST API:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/status` | Server status, auth state, token TTL, sync state |
| `GET` | `/api/v1/rules` | Configured sync rules |
| `GET` | `/api/v1/secrets/{path}` | List or reveal a secret |
| `POST` | `/api/v1/sync` | Trigger immediate sync (CSRF-protected) |
| `GET` | `/api/v1/csrf` | Obtain a one-time CSRF token |

Auth endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/oidc/start` | Redirect to Vault OIDC auth URL |
| `GET` | `/auth/oidc/callback` | Handle OIDC callback |
| `POST` | `/auth/ldap/login` | Start async LDAP login (CSRF-protected) |
| `GET` | `/auth/ldap/status` | Poll login status |
| `POST` | `/auth/ldap/totp` | Submit TOTP passcode (CSRF-protected) |
| `POST` | `/auth/token/login` | Validate and set token (CSRF-protected) |
