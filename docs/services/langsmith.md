# LangSmith Onboarding

The `langsmith` enrolment engine automates LangSmith credential acquisition using the OAuth 2.0 device-authorization flow that `langsmith auth login` performs: dotvault requests a device/user code, you approve it in a browser, and dotvault polls the LangSmith token endpoint until it issues an access/refresh pair. LangSmith access tokens are short-lived, so dotvault stores the access/refresh pair in Vault and a background refresh manager rotates it at its half-life — the synced credential never expires in place.

dotvault owns the rotation. The rendered credential file therefore carries only the access token (the same model the `jfrog` and `databricks` engines use): the LangSmith CLI's native token cache is intentionally not written, so nothing races dotvault's refresh.

## Configuration

### Minimal

```yaml
enrolments:
  langsmith:
    engine: langsmith

rules:
  - name: langsmith-env
    vault_key: "langsmith"
    target:
      path: "~/.config/langsmith/env"
      format: text
      template: |
        LANGSMITH_API_KEY={{ .access_token }}
        LANGSMITH_ENDPOINT={{ .api_url }}
```

With no settings the engine logs you in against the LangSmith SaaS endpoint (`https://api.smith.langchain.com`). A LangSmith OAuth access token is accepted wherever an API key is — the SDK and CLI send both as the credential — and dotvault keeps it fresh.

### Self-hosted or EU deployment

Point `api_url` at your deployment. A `/api/v1` suffix (the conventional `LANGSMITH_ENDPOINT` value) is accepted and stripped to root the OAuth endpoints correctly:

```yaml
enrolments:
  langsmith:
    engine: langsmith
    settings:
      api_url: "https://eu.api.smith.langchain.com"
      workspace_id: "00000000-0000-0000-0000-000000000000"
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `api_url` | `https://api.smith.langchain.com` | LangSmith API endpoint — **https**, host (optionally with a `/api/v1` suffix, which is stripped). A bare host is assumed https; an explicit `http://` is rejected (the bearer token would travel in cleartext). The OAuth device/token endpoints are rooted at this host. |
| `client_id` | `langsmith-cli` | OAuth client ID. Override only if your organisation registered a custom public OAuth app. |
| `workspace_id` | _(unset)_ | Optional passthrough written to the Vault secret verbatim (for a rendered `LANGSMITH_WORKSPACE_ID`). Not acquired during login and not required for completeness. |
| `https_proxy` / `http_proxy` | _(native proxy machinery)_ | Pin the OAuth HTTPS traffic to a specific proxy (`http`, `https`, `socks5`, `socks5h`). See the [GitHub engine notes](github.md) — the same `internal/httpproxy` contract applies. |

## How the login flow works

1. dotvault POSTs to `{api_url}/oauth/device/code` (with the `client_id` and the API base as the `resource`) to request a device code, user code, and verification URL.
2. It shows you the one-time user code and opens the verification URL in your browser (in web mode it shows a clickable link instead — the daemon never opens a browser on your behalf).
3. You sign in to LangSmith (SSO/MFA as configured) and enter the user code to approve the device.
4. Meanwhile dotvault polls `{api_url}/oauth/token` on the device-flow cadence (honouring `authorization_pending` and `slow_down`) until LangSmith returns an access token + refresh token.
5. The token pair and metadata are written to Vault.

### Terminal output

```
! First, copy your one-time code: WXYZ-1234
- Press Enter to open https://smith.langchain.com/device in your browser...
✓ Opened https://smith.langchain.com/device in browser
⠼ Waiting for authentication...
✓ langsmith (LangSmith) — credentials acquired
```

In the web UI the same flow renders as a device-code card: the one-time code is shown with a **Copy Code** button and a clickable **Open LangSmith →** link. You enter the code on LangSmith and the card advances to "Waiting for approval…" and then "Enrolled successfully" on its own.

## How the refresh cycle works

After enrolment, the daemon's `RefreshManager` checks every 5 minutes whether the LangSmith secret has crossed its half-life (`now >= issued_at + (expires_at - issued_at) / 2`). When it has:

1. dotvault POSTs `grant_type=refresh_token&refresh_token=<current>&client_id=langsmith-cli` to `{api_url}/oauth/token`.
2. The response carries a fresh access token (and a rotated refresh token if the server issues one — dotvault adopts it, otherwise it keeps the existing refresh token).
3. dotvault stamps a fresh `issued_at=now`, `expires_at=now + expires_in`, and writes the new pair to Vault atomically.
4. The sync engine picks up the updated secret and rewrites the credential file.

A `401` or `403` from the token endpoint is treated as permanent revocation: the secret is deleted from Vault and you are prompted to re-enrol on the next wizard pass. Other errors are transient; the existing secret is kept and the refresh is retried with exponential backoff.

## Credentials stored in Vault

| Field | Description |
|-------|-------------|
| `access_token` | The OAuth access token (rotated at half-life) |
| `refresh_token` | The companion refresh token |
| `api_url` | The LangSmith API base (used for refresh and as a render value) |
| `issued_at` | RFC 3339 timestamp when dotvault issued the current token pair |
| `expires_at` | RFC 3339 timestamp when the access token expires (`issued_at + expires_in`) |
| `workspace_id` | Optional passthrough from settings (written when configured; not required for completeness) |

## Multiple workspaces

To manage several LangSmith deployments for the same user, give each its own enrolment under a shared `langsmith/` group. A one-level grouped key like `langsmith/eu` nests under `users/<you>/langsmith/eu` in Vault and renders as an expandable **langsmith** folder in the web UI, with each entry independently refreshed:

```yaml
enrolments:
  langsmith/us:
    engine: langsmith
    settings:
      api_url: "https://api.smith.langchain.com"
  langsmith/eu:
    engine: langsmith
    settings:
      api_url: "https://eu.api.smith.langchain.com"
```

The grouping is generic (see [Service Onboarding](overview.md#grouping-enrolments)) — the same `group/name` convention applies to any engine. Exactly one level of grouping is supported.

## Requirements

- OAuth device-flow login must be available on the LangSmith deployment (it is the mechanism `langsmith auth login` uses).
- The signed-in user must be able to approve a device login for themselves; no admin privileges are required.
- The browser used to approve the device code can be on any machine — unlike a loopback-redirect flow, the device flow needs no inbound connection back to the daemon host.
