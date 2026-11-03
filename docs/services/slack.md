# Slack

The `slack` engine stores a Slack browser session for [slk](https://github.com/goodtune/slk), the terminal Slack client, so slk reads it from Vault instead of keeping it on disk. dotvault carries only the session's `d` cookie and never contacts Slack: slk mints its own access token from the cookie every time it starts.

## Configuration

```yaml
enrolments:
  slack/slk:
    engine: slack
    settings:
      workspaces: [acme, acme-eng]   # the part before .slack.com
```

| Setting | Required | Description |
|---------|----------|-------------|
| `workspaces` | yes | Slack subdomains to enrol: `acme` for `acme.slack.com`. Each becomes a field of the secret |

Point slk at the secret with its `[vault]` section: `secret = "slack/slk"`.

## Enrolment

1. Sign in to every listed workspace in one browser.
2. Open DevTools → Network, pick any request to `/api/`, and **Copy as cURL** (bash or cmd) or **Copy as PowerShell**. The `d` cookie alone (`xoxd-…`, from DevTools → Application → Cookies → `https://app.slack.com`) works too.
3. Run `dotvault enrol slack/slk`, or open the enrolment in the web UI, and paste it when asked.

dotvault keeps only the `d` cookie from what you paste and stores it for every listed workspace, since one cookie covers every workspace that browser is signed in to. It does not check the cookie with Slack; a wrong or signed-out cookie shows up when slk starts, as a warning naming the workspace. To replace the session, run `dotvault enrol slack/slk` again.

Adding a workspace to `workspaces` brings the enrolment back as pending. Fields already in the secret that are not listed are kept; remove one with `dotvault kv patch`.

## Vault schema

`kv/users/<you>/slack/slk` holds one field per workspace, whose value is a JSON object:

```json
{"domain": "acme", "cookie": "xoxd-…"}
```

There is nothing to refresh: the cookie is long-lived and slk mints a fresh access token from it at every start. When Slack stops accepting the cookie (you signed out of that browser, or it expired), enrol again.
