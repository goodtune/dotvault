# Slack

The `slack` engine enrols a Slack browser session for [slk](https://github.com/goodtune/slk), the terminal Slack client, so slk reads its credentials from Vault instead of keeping them on disk.

## Configuration

```yaml
enrolments:
  slack/slk:
    engine: slack
    settings:
      workspaces: [acme, acme-eng]   # the part before .slack.com
      # refresh_interval: 24h        # optional; minimum 1h
```

| Setting | Required | Description |
|---------|----------|-------------|
| `workspaces` | yes | Slack subdomains to enrol: `acme` for `acme.slack.com`. Each becomes a field of the secret. `issued_at` and `expires_at` are reserved |
| `refresh_interval` | no | How long minted tokens are treated as valid; re-minted past half of it. Default `24h`, minimum `1h` |
| `https_proxy` / `http_proxy` | no | Route the requests through a proxy, as for the other engines |

Point slk at the secret with its `[vault]` section: `secret = "slack/slk"`.

## Enrolment

1. Sign in to every listed workspace in one browser.
2. Open DevTools → Network, pick any request to `/api/`, and **Copy as cURL** (bash or cmd) or **Copy as PowerShell**. The `d` cookie alone (`xoxd-…`, from DevTools → Application → Cookies → `https://app.slack.com`) works too.
3. Run `dotvault enrol slack/slk`, or open the enrolment in the web UI, and paste it when asked.

dotvault keeps only the `d` cookie from what you paste. It signs in to each workspace with it, mints an `xoxc-` token from the workspace page (as the Slack web client does), and checks it with `auth.test`. If any workspace refuses the session, nothing is written: sign in to that workspace in the same browser and copy the request again.

Adding a workspace to `workspaces` brings the enrolment back as pending; enrolling again re-mints every listed workspace with the new session. Fields already in the secret that are not listed are kept, and left alone by refresh; remove one with `dotvault kv patch`. Fields written by another tool survive enrolment, but only string fields survive a refresh.

## Vault schema

`kv/users/<you>/slack/slk` holds one field per workspace, whose value is a JSON object:

```json
{"domain": "acme", "team_id": "T01ACME", "team_name": "Acme",
 "user_id": "U02ME", "access_token": "xoxc-…", "cookie": "xoxd-…"}
```

plus `issued_at` and `expires_at` (RFC3339).

## Refresh

The `d` cookie is long-lived; the `xoxc` token's lifetime is not published. Past half of `refresh_interval` the RefreshManager re-mints each listed workspace's token from its own cookie. A workspace field whose stored `domain` is not its own name is refused rather than minted, so the cookie is only ever sent to that workspace.

A cookie Slack no longer accepts is treated as revoked: the sign-in page instead of a token, or `invalid_auth`, `not_authed`, `account_inactive` or `token_revoked` from `auth.test`. The secret is then removed and the enrolment comes back as pending, for every workspace in it, since they share the session.

Within one attempt the engine retries only a rate limit (HTTP 429: three attempts, honouring `Retry-After` up to 10 seconds). Any other failure (network, 5xx) fails that attempt: during enrolment you see it at once, and on refresh the RefreshManager keeps the secret and retries later with backoff.
