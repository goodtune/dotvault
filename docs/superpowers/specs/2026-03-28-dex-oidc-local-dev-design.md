# Dex OIDC Provider for Local Dev Testing

## Purpose

Add Dex as a local OIDC identity provider to docker-compose so the web-based OIDC auth flow can be tested end-to-end. Dex is a dev-only dependency -- it is not used in production.

## Architecture

```
Browser
  |
  v
dotvault web UI (127.0.0.1:8250)
  |  POST auth/oidc/oidc/auth_url (redirect_uri=.../auth/callback)
  v
Vault (127.0.0.1:8200)
  |  generates auth URL pointing to Dex
  v
Dex (dex:5556, mapped to 127.0.0.1:5556)
  |  mockCallback connector auto-approves login
  |  redirects to 127.0.0.1:8250/auth/callback?code=...&state=...
  v
dotvault web UI
  |  POST auth/oidc/oidc/callback (code + state)
  v
Vault exchanges code with Dex, returns Vault token
```

## Changes

### 1. New file: `dex.yaml`

Dex configuration with:
- Issuer: `http://dex:5556/dex` (requires `127.0.0.1 dex` in host `/etc/hosts`)
- Static OIDC client:
  - ID: `dotvault`
  - Secret: `dotvault-dev-secret`
  - Redirect URI: `http://127.0.0.1:8250/auth/callback`
- Connector: `mockCallback` (auto-approves login, no credentials needed)
- Storage: SQLite3 file-backed (`/var/dex/dex.db`, persisted via Docker volume)

### 2. Updated: `docker-compose.yaml`

Add `dex` service:
- Image: `dexidp/dex:v2.41.1`
- Port: `5556:5556`
- Mounts `dex.yaml` as config
- Command: `dex serve /etc/dex/config.yaml`

Update `vault-init` service:
- `depends_on` includes `dex`
- After existing KV and policy setup, additionally:
  - Enable OIDC auth method: `vault auth enable oidc`
  - Configure OIDC auth: `vault write auth/oidc/config` with:
    - `oidc_discovery_url=http://dex:5556/dex`
    - `oidc_client_id=dotvault`
    - `oidc_client_secret=dotvault-dev-secret`
    - `default_role=default`
  - Create OIDC role: `vault write auth/oidc/role/default` with:
    - `bound_audiences=dotvault`
    - `allowed_redirect_uris=http://127.0.0.1:8250/auth/callback`
    - `user_claim=email`
    - `token_policies=dotvault`

### 3. Updated: `/Library/Application Support/dotvault/config.yaml`

Add web UI config for local dev:
```yaml
web:
  enabled: true
  listen: "127.0.0.1:8250"
```

The code default for `web.listen` remains `127.0.0.1:8200`. The explicit override to 8250 is only needed locally because the dev Vault occupies 8200.

### 4. No application code changes

The existing web-based OIDC flow in `internal/web/auth.go` and `internal/auth/oidc.go` requires no modifications.

## Prerequisites

Add to host `/etc/hosts` (one-time):
```
127.0.0.1 dex
```

## Testing

1. `docker compose up -d` (starts Vault, vault-init, Dex)
2. Run `dotvault` (or `go run ./cmd/dotvault`)
3. Browser opens to `http://127.0.0.1:8250/auth/start`
4. Redirected to Dex at `http://dex:5556/dex/auth/...`
5. mockCallback connector auto-approves (click "Grant Access")
6. Redirected back to dotvault callback
7. Vault token acquired, daemon starts syncing
