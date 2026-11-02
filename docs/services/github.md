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
      token_lifetime: expiring                  # default: non-expiring
      https_proxy: http://squid.example.com:3128   # default: system proxy machinery
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `client_id` | `178c6fc778ccc68e1d6a` (GitHub CLI's app) | OAuth application client ID |
| `host` | `github.com` | GitHub host (for GitHub Enterprise Server) |
| `scopes` | `repo`, `read:org`, `gist` | OAuth scopes to request |
| `token_lifetime` | `non-expiring` | `expiring` asks GitHub for a short-lived token that dotvault rotates automatically (see [Expiring tokens](#expiring-tokens-and-automatic-refresh)). A string, not a boolean, so that it round-trips through the Windows registry; any other value is a config error. |
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

By default dotvault asks for an ordinary token that never expires, and the secret holds just `oauth_token` and `user`. To get a short-lived token instead, set `token_lifetime`:

```yaml
enrolments:
  gh:
    engine: github
    settings:
      token_lifetime: expiring
```

This works with the default `client_id`; no app registration is needed. dotvault adds the `offline_access` scope to the device flow, which is what `gh auth login --expiring` does, and GitHub returns an access token valid for eight hours together with a refresh token valid for about six months. Your OAuth scopes are unchanged, so the token reaches the same repositories as before.

`token_lifetime: expiring` is a request, not a guarantee. GitHub decides what to issue, and hosts without support — GitHub Enterprise Server, today — return an ordinary token, which dotvault stores and uses as usual. Only github.com and GHE.com (`*.ghe.com`) hosts are known to support it. An `expiring` enrolment against a plain `http://` host (loopback excepted) is refused before the device flow starts, because the refresh token would cross in the clear and could never be used. The same applies to any expiring token GitHub issues over such a host whatever `token_lifetime` says, such as one from a GitHub App with token expiration turned on; that refusal comes after you finish the device flow, since only the response shows the token expires, and nothing is stored. Point `host` at an `https://` URL to enrol. dotvault requests expiry through the `offline_access` scope, so listing that scope in `scopes` has the same effect whatever `token_lifetime` says.

Changing the setting does not replace an existing enrolment, because a secret already holding an `oauth_token` counts as complete. Run the enrolment again to obtain the expiring token:

```sh
dotvault enrol gh
```

Keep the daemon running once you switch. The access token lasts eight hours and only the daemon rotates it, so a host with no daemon running for longer than that is left with an expired token until a daemon next refreshes it.

When the device flow returns a refresh token and an expiry, dotvault stores `refresh_token`, `issued_at` and `expires_at` alongside the token, and the daemon's refresh manager rotates it the same way it rotates JFrog and Databricks credentials:

1. Every check interval (five minutes), the secret is read and skipped unless the access token is past half its lifetime — about four hours for an eight-hour token.
2. dotvault posts `grant_type=refresh_token` to `{host}/login/oauth/access_token` with the configured `client_id`. No client secret is sent: the [`cli/oauth`](https://github.com/cli/oauth) library this uses documents device-flow tokens as refreshable without one, so dotvault never needs a GitHub App's secret in its config.
3. GitHub returns a new access token **and a new refresh token**; the old refresh token stops working immediately. The whole secret is replaced, and the sync engine re-renders `hosts.yml` (or whatever the rule writes) with the new `oauth_token`. A refresh that is interrupted — the daemon shutting down mid-request — is cancelled rather than left to complete in the background, so it cannot silently consume the stored refresh token.
4. If GitHub rejects the refresh token as invalid or expired (`bad_refresh_token`), dotvault waits for the next check and then, if the secret has not changed, deletes it from Vault so the enrolment flow prompts for a fresh login. The wait matters when more than one daemon enrols the same secret, as on hosts sharing one Vault identity: a refresh token works once, so the daemon that loses the race is told its token is bad, and it must not delete what the winner is writing. Any other failure is treated as transient: the existing secret is kept, a warning is logged, and the refresh is retried with backoff.

Refresh requires an `https://` host (loopback excepted): the refresh token is long-lived, and the response decides whether the secret is wiped, so neither is sent or trusted over cleartext.

### Using a GitHub App

You do not need a GitHub App for expiring tokens, but if you already use one, register it with **Expire user authorization tokens** and **Enable Device Flow** turned on and point the enrolment at it. Such an App issues expiring tokens without `token_lifetime`, so its `host` must be an `https://` URL (loopback excepted), or the enrolment is refused once the device flow completes:

```yaml
enrolments:
  gh:
    engine: github
    settings:
      client_id: "Iv23li..."   # the GitHub App's client ID
```

Such an app returns an expiring token whether or not `token_lifetime` is set. As with `token_lifetime`, changing `client_id` does not replace an existing enrolment: run `dotvault enrol gh` again, or delete the secret and let the daemon's enrolment check prompt for it. A GitHub App's user token carries the permissions granted to the App rather than OAuth scopes, so the `scopes` setting has no effect for one, and it reaches only the repositories the App is installed on.

### Keep the refresh token out of files

A sync rule should render only `oauth_token`: dotvault owns the rotation, so keep the refresh token out of files. The same applies to the other ways of reading the secret. The [filesystem mount](../guide/filesystem.md) shows every field of `gh.json`, and a [Docker volume](../guide/docker-volumes.md) that selects `gh` (or the whole key space, its default) publishes them to containers. No client secret is needed to use a refresh token, so anything that can read it can mint access tokens, and spending it takes the credential away from dotvault. Leave `gh` out of a volume's `secrets=` list once it holds a refresh token.

## GitHub Enterprise Server

For GitHub Enterprise Server, set the `host` in settings. Enterprise Server does not issue expiring tokens today, so `token_lifetime: expiring` has no effect there and you get an ordinary token.

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
