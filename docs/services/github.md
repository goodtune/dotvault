# GitHub CLI Onboarding

The `github` enrolment engine automates GitHub OAuth token acquisition using the [device authorisation flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow). This is the same flow used by the `gh auth login` command.

## Configuration

### Minimal

```yaml
enrolments:
  gh:
    engine: github

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{ .oauth_token }}"
          user: "{{ .user }}"
          git_protocol: https
```

### With custom settings

```yaml
enrolments:
  gh:
    engine: github
    settings:
      client_id: "your-oauth-app-client-id"    # default: GitHub CLI's OAuth app
      host: "github.example.com"                # default: github.com
      scopes:                                    # default: repo, read:org, gist
        - repo
        - read:org
        - gist
        - workflow
      https_proxy: http://squid.example.com:3128   # default: system proxy machinery
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `client_id` | `178c6fc778ccc68e1d6a` (GitHub CLI's app) | OAuth application client ID |
| `host` | `github.com` | GitHub host (for GitHub Enterprise Server) |
| `scopes` | `repo`, `read:org`, `gist` | OAuth scopes to request |
| `https_proxy` | host's system proxy machinery | Override HTTPS proxy for all outbound calls from this enrolment. `http_proxy` is accepted as an alias. |

## Behind a corporate proxy

By default the engine consults the host's native proxy machinery on a per-request basis. On Windows that is the IE / WinHTTP configuration — PAC scripts included, so a policy that returns DIRECT for one host and a proxy for another is honoured. On Linux and macOS the resolver reads the standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables from the daemon's environment. Native CFNetwork-based detection on macOS would require CGO, which dotvault avoids; export the variables in your `launchd` plist (or `systemd` `EnvironmentFile`) instead.

When you cannot rely on host-level configuration — for example because the daemon's environment is curated and a per-enrolment override is the cleanest place to land the URL — set `https_proxy` (or `http_proxy`, accepted as an alias) on the enrolment:

```yaml
enrolments:
  gh:
    engine: github
    settings:
      https_proxy: http://squid.example.com:3128
```

The override pins every outbound request from this enrolment to that proxy, bypassing the per-URL PAC routing that the system resolver would otherwise apply. That is deliberate — when the operator says "use this proxy", we use it. Accepted schemes are `http`, `https`, `socks5`, and `socks5h`. Credentials embedded in the URL (`http://user:pass@proxy:3128`) are forwarded to the proxy as a `Proxy-Authorization` header.

## How the device flow works

1. dotvault requests a device code from GitHub
2. A one-time user code is displayed (and copied to clipboard if possible)
3. The user opens `https://github.com/login/device` in their browser
4. The user enters the code and authorises the application
5. dotvault polls GitHub until the authorisation completes
6. The resulting OAuth token and username are written to Vault

### Terminal output

```
! First, copy your one-time code: ABCD-1234
- Press Enter to open https://github.com/login/device in your browser...
✓ Opened https://github.com/login/device in browser
⠼ Waiting for authentication...
✓ Authentication complete!
```

## Credentials stored in Vault

The engine writes these fields to the Vault KV secret:

| Field | Description |
|-------|-------------|
| `oauth_token` | The GitHub OAuth access token |
| `user` | The authenticated GitHub username |
| `refresh_token` | Only for an expiring token (see below): the token dotvault rotates with |
| `issued_at` / `expires_at` | Only for an expiring token: RFC3339 timestamps of the current access token's lifetime |
| `refresh_token_expires_at` | Only for an expiring token, when GitHub reports it: when the refresh token itself lapses |

## Expiring tokens and automatic refresh

Whether a GitHub token expires is decided by the OAuth client, not by dotvault. A classic OAuth app — including the GitHub CLI's, which is the default `client_id` — issues a token that never expires, and the secret holds just `oauth_token` and `user`, exactly as before. A **GitHub App** with user-to-server token expiration enabled (or an OAuth app opted in to expiring tokens) instead returns an access token valid for eight hours together with a refresh token valid for six months.

When the device flow returns a refresh token and an expiry, dotvault stores `refresh_token`, `issued_at` and `expires_at` alongside the token, and the daemon's refresh manager rotates it the same way it rotates JFrog and Databricks credentials:

1. Every check interval (five minutes), the secret is read and skipped unless the access token is past half its lifetime.
2. dotvault posts `grant_type=refresh_token` to `{host}/login/oauth/access_token` with the configured `client_id`. No client secret is sent or needed — device-flow tokens are refreshable by client ID alone.
3. GitHub returns a new access token **and a new refresh token**; the old refresh token stops working immediately. The whole secret is replaced, and the sync engine re-renders `hosts.yml` (or whatever the rule writes) with the new `oauth_token`.
4. If GitHub rejects the refresh token (`bad_refresh_token` — it expired, was revoked, or the `client_id` setting changed since enrolment), the secret is deleted from Vault so the enrolment flow prompts for a fresh login. Any other failure is treated as transient: the existing secret is kept and the refresh retried with backoff.

To use it, register a GitHub App with **Expire user authorization tokens** and **Enable Device Flow** turned on, and point the enrolment at it:

```yaml
enrolments:
  gh:
    engine: github
    settings:
      client_id: "Iv23li..."   # the GitHub App's client ID
```

A GitHub App's user token carries the permissions granted to the App rather than OAuth scopes, so the `scopes` setting has no effect for one. Because dotvault owns the rotation, a sync rule should render only `oauth_token` — never the refresh token — so that `gh` or `git` never tries to refresh on its own and race the daemon. A secret enrolled before this feature, or by a client that issues non-expiring tokens, carries no `expires_at` and is never touched by the refresh manager.

## GitHub Enterprise Server

For GitHub Enterprise Server, set the `host` in settings:

```yaml
enrolments:
  gh-enterprise:
    engine: github
    settings:
      host: "github.example.com"
      client_id: "your-ghe-oauth-app-id"

rules:
  - name: gh-enterprise
    vault_key: "gh-enterprise"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.example.com:
          oauth_token: "{{ .oauth_token }}"
          user: "{{ .user }}"
          git_protocol: https
```

You can have both `github.com` and GitHub Enterprise entries — the YAML merge strategy preserves both host entries in the `hosts.yml` file.

## Combining enrolment with sync

A typical setup pairs the enrolment with a sync rule so the workflow is:

1. User starts dotvault for the first time
2. dotvault checks Vault for `users/{username}/gh` — it's empty
3. The enrolment wizard runs the GitHub device flow
4. Credentials are written to Vault
5. The sync rule picks up the new secret and writes `~/.config/gh/hosts.yml`
6. `gh` CLI now works without manual `gh auth login`

On subsequent starts, the enrolment check finds the credentials already present and skips the flow.
