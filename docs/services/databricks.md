# Databricks Onboarding

The `databricks` enrolment engine automates Databricks credential acquisition using the OAuth user-to-machine (U2M) login that `databricks auth login` performs: an authorization-code flow with PKCE against the workspace OAuth endpoints, with a localhost redirect listener catching the authorization code. Databricks access tokens live for about an hour, so dotvault stores the access/refresh pair in Vault and a background refresh manager rotates it at its half-life — the synced credential never expires in place.

dotvault owns the rotation. The rendered credential file therefore carries only the access token (the same model the `jfrog` engine uses): the Databricks CLI's native OAuth token cache is intentionally not written, so nothing races dotvault's refresh.

## Configuration

### Minimal

```yaml
enrolments:
  databricks:
    engine: databricks
    settings:
      host: "https://dbc-xxxx.cloud.databricks.com"

rules:
  - name: databricks-cfg
    vault_key: "databricks"
    target:
      path: "~/.databrickscfg"
      format: ini
      template: |
        [DEFAULT]
        host  = {{ .host }}
        token = {{ .access_token }}
```

The rendered `~/.databrickscfg` is a standard token (PAT-style) profile. The Databricks CLI and SDKs send the value as `Authorization: Bearer <token>`, which accepts an OAuth access token just as it does a personal access token — and dotvault keeps that token fresh.

### Account-level login

Set `account_id` to log in at the account console instead of a workspace. The `host` then becomes the accounts URL:

```yaml
enrolments:
  databricks:
    engine: databricks
    settings:
      host: "https://accounts.cloud.databricks.com"
      account_id: "00000000-0000-0000-0000-000000000000"
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `host` | _(required)_ | Databricks workspace URL — **https**, host only, no path, e.g. `https://dbc-xxxx.cloud.databricks.com`. A bare host is assumed https; an explicit `http://` is rejected (the bearer token would travel in cleartext). For account-level login, the accounts console URL. |
| `account_id` | _(unset)_ | Databricks account ID. When set, the engine performs account-level login against `{host}/oidc/accounts/{account_id}/…`. |
| `client_id` | `databricks-cli` | OAuth client ID. Override only if your organisation registered a custom public OAuth app (the custom app must register `http://localhost:8020`–`8040` as a redirect URI). |
| `scopes` | `offline_access all-apis` | OAuth scopes. A custom list is honoured verbatim, except `offline_access` is always ensured — dotvault depends on the refresh token to rotate the short-lived access token. |
| `https_proxy` / `http_proxy` | _(native proxy machinery)_ | Pin OAuth/SCIM HTTPS traffic to a specific proxy (`http`, `https`, `socks5`, `socks5h`). See the [GitHub engine notes](github.md) — the same `internal/httpproxy` contract applies. |

## How the login flow works

1. dotvault fetches the OAuth metadata document from `{host}/oidc/.well-known/oauth-authorization-server` (account-level inserts `/oidc/accounts/{account_id}`) to discover the `authorization_endpoint` and `token_endpoint`.
2. It binds a loopback redirect listener, preferring port `8020` and walking up to `8040` (matching the Databricks CLI), and generates a PKCE verifier/challenge (`S256`) plus an anti-CSRF `state`.
3. The user's browser is opened to the authorization endpoint with `client_id=databricks-cli`, the redirect URI, `response_type=code`, the scopes, and the PKCE challenge.
4. After the user signs in (SSO/MFA as configured for the workspace), Databricks redirects back to the loopback listener with an authorization code. dotvault validates `state`.
5. dotvault exchanges the code at the token endpoint (public client, PKCE `code_verifier`) for an access token + refresh token.
6. A best-effort SCIM `GET /api/2.0/preview/scim/v2/Me` resolves the signed-in username.
7. The token pair and metadata are written to Vault.

### Terminal output

```
✓ Opened https://dbc-xxxx.cloud.databricks.com/oidc/v1/authorize?... in browser
⠼ Waiting for authentication...
⠼ Exchanging authorization code...
✓ databricks (Databricks) — credentials acquired
```

## How the refresh cycle works

After enrolment, the daemon's `RefreshManager` checks every 5 minutes whether the Databricks secret has crossed its half-life (`now >= issued_at + (expires_at - issued_at) / 2`; the half-life of a one-hour token is ~30 minutes). When it has:

1. dotvault POSTs `grant_type=refresh_token&refresh_token=<current>&client_id=databricks-cli` to the token endpoint.
2. The response carries a fresh access token (and a rotated refresh token if the server issues one — dotvault adopts it, otherwise it keeps the existing refresh token).
3. dotvault stamps a fresh `issued_at=now`, `expires_at=now + expires_in`, and writes the new pair to Vault atomically.
4. The sync engine picks up the updated secret and rewrites `~/.databrickscfg`.

A `401` or `403` from the token endpoint is treated as permanent revocation: the secret is deleted from Vault and the user is prompted to re-enrol on the next wizard pass. Other errors are transient; the existing secret is kept and the refresh is retried with exponential backoff.

## Credentials stored in Vault

| Field | Description |
|-------|-------------|
| `access_token` | The OAuth access token (rotated at half-life) |
| `refresh_token` | The companion refresh token |
| `host` | The Databricks workspace (or accounts) URL |
| `issued_at` | RFC 3339 timestamp when dotvault issued the current token pair |
| `expires_at` | RFC 3339 timestamp when the access token expires (`issued_at + expires_in`) |
| `user` | Username from SCIM `/Me` (written when available; not required for completeness) |

## Requirements

- OAuth U2M must be available on the workspace (it is enabled by default on current Databricks).
- The signed-in user must be able to mint a U2M token for themselves; no admin privileges are required for the default workspace flow.
- The browser used for login must be able to reach the loopback redirect on the same machine as the daemon (`http://localhost:8020`–`8040`).
