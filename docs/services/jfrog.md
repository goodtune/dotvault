# JFrog Platform Onboarding

The `jfrog` enrolment engine automates JFrog Platform access-token acquisition using the browser-based web login exchange that `jf login` uses. After the web login completes, dotvault mints a second, dotvault-owned refreshable token with a configurable TTL and stores the pair in Vault. A background refresh manager rotates the pair at its half-life so the synced credentials never expire in place.

JFrog does not publish a public OAuth app — the web login flow is hosted by each JFrog Platform deployment, so the only required setting is the platform URL.

## Configuration

### Minimal

```yaml
enrolments:
  jfrog:
    engine: jfrog
    settings:
      url: "https://mycompany.jfrog.io"

rules:
  - name: jfrog-cli
    vault_key: "jfrog"
    target:
      path: "~/.jfrog/jfrog-cli.conf.v6"
      format: json
      template: |
        {
          "servers": [
            {
              "serverId": "{{ .server_id }}",
              "url": "{{ .url }}/",
              "artifactoryUrl": "{{ .url }}/artifactory/",
              "accessToken": "{{ .access_token }}",
              "user": "{{ .user }}"
            }
          ],
          "version": "6"
        }
```

### With custom settings

```yaml
enrolments:
  jfrog:
    engine: jfrog
    settings:
      url: "https://mycompany.jfrog.io"
      token_ttl: "30d"           # default: 60d, floor: 10m
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `url` | _(required)_ | JFrog Platform base URL (scheme + host only, no path) |
| `token_ttl` | `60d` | Lifetime of the dotvault-minted access token. Accepts `time.ParseDuration` syntax plus `Nd` for whole days (e.g. `60d`, `6h`, `10m`). Floor: `10m` |

Non-admin users can mint refreshable tokens at any non-zero TTL; only the never-expire case (`expires_in=0`) requires admin privileges, and dotvault intentionally does not use it.

## How the web login flow works

1. dotvault generates a random UUID session identifier and tells the JFrog Access service a web login is about to begin
2. The user's browser is opened to `{url}/ui/login?jfClientSession=<uuid>&jfClientName=JFrog-CLI&jfClientCode=1`
3. The user signs in through the platform's normal SSO / username+password flow, then confirms the last four characters of the UUID (displayed in the terminal and copied to the clipboard)
4. dotvault polls the Access service until it returns a bootstrap access token
5. dotvault exchanges the bootstrap token for a dotvault-owned refreshable token pair with the configured `token_ttl` — the bootstrap token is then discarded
6. The minted access token, refresh token, and metadata are written to Vault

### Terminal output

```
! First, copy your one-time code: a1b2
  (you will be prompted for this after signing in)
✓ Opened https://mycompany.jfrog.io/ui/login?jfClientSession=... in browser
⠼ Waiting for authentication...
⠼ Minting dotvault-owned access token (ttl=60d)...
✓ Authentication complete!
```

## How the refresh cycle works

After enrolment, the daemon's `RefreshManager` checks every 5 minutes whether any JFrog secret has crossed its half-life (`now >= issued_at + (expires_at - issued_at) / 2`). When it has:

1. dotvault POSTs `grant_type=refresh_token&access_token=<current>&refresh_token=<current>` to the JFrog access service
2. JFrog rotates **both** tokens on every successful refresh — the old refresh token is invalidated immediately
3. dotvault stamps a fresh `issued_at=now`, `expires_at=now+token_ttl`, and writes the new pair to Vault atomically
4. The sync engine picks up the updated secret and rewrites the local `jfrog-cli.conf.v6`

A `401` or `403` from the refresh endpoint is treated as permanent revocation: the secret is deleted from Vault and the user is prompted to re-enrol on the next wizard pass. Other errors are transient; the existing secret is kept and the refresh is retried with exponential backoff.

Because dotvault owns refresh, the rendered `jfrog-cli.conf.v6` deliberately omits `refreshToken` and `webLogin: true`, so the `jf` CLI never attempts its own rotation (which would race the sync-engine clobber).

## Credentials stored in Vault

The engine writes these fields to the Vault KV secret:

| Field | Description |
|-------|-------------|
| `access_token` | The dotvault-minted JFrog access token |
| `refresh_token` | The companion refresh token (rotated on every refresh) |
| `url` | The JFrog Platform base URL |
| `server_id` | Short server identifier deduced from the hostname (e.g. `mycompany.jfrog.io` → `mycompany`; IP addresses → `default-server`) |
| `user` | Username extracted from the access-token JWT subject (blank for reference-token deployments) |
| `issued_at` | RFC 3339 timestamp when dotvault issued the current token pair |
| `expires_at` | RFC 3339 timestamp when dotvault considers the pair expired (`issued_at + token_ttl`) |

## Requirements

- JFrog Artifactory **7.64.0 or newer** on the remote side — earlier versions do not expose the `jfrog_client_login` web login endpoints.
- The signed-in user must have permission to mint an access token for themselves; no admin privileges are required for the default refreshable-token flow.

## Combining enrolment with sync

A typical setup pairs the enrolment with a sync rule so the workflow is:

1. User starts dotvault for the first time
2. dotvault checks Vault for `users/{username}/jfrog` — it's empty
3. The enrolment wizard runs the JFrog web login flow and mints a dotvault-owned token
4. Credentials are written to Vault
5. The sync rule picks up the new secret and writes `~/.jfrog/jfrog-cli.conf.v6`
6. `jf` CLI now works without manual `jf login`

On subsequent starts, the enrolment check finds the credentials already present and skips the flow. The refresh manager keeps the token pair valid for as long as the daemon is running.
