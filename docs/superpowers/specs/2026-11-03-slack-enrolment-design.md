# Slack enrolment engine — design

## Problem

[slk](https://github.com/goodtune/slk), a terminal Slack client, talks to Slack with a browser session: an `xoxc-` token plus the `d` cookie. Today it keeps one plaintext JSON file per workspace under `~/.local/share/slk/tokens/`. We want those credentials enrolled into Vault by dotvault and read back by slk through the `client/` facade, with nothing on the user's disk.

That needs two things here: an enrolment engine that acquires and keeps the session fresh, and a facade method that reads every field of a secret, because slk does not know the workspace names in advance.

## The secret

One enrolment, one secret, one field per workspace. The enrolment key is whatever the operator chooses (`slack/slk` in the examples); the secret lands at `kv/users/<you>/slack/slk` as usual.

```yaml
enrolments:
  slack/slk:
    engine: slack
    settings:
      workspaces: [acme, acme-eng]   # Slack subdomains: acme.slack.com
```

Each workspace is a field named by its subdomain whose value is a JSON object (an engine writes string fields, so the object is a string):

```json
{"domain": "acme", "team_id": "T01ACME", "team_name": "Acme",
 "user_id": "U02ME", "access_token": "xoxc-…", "cookie": "xoxd-…"}
```

plus two bookkeeping fields the RefreshManager needs, `issued_at` and `expires_at` (RFC3339). Those two names are therefore reserved and refused as workspace names at config load, along with anything that is not a valid Slack subdomain (`[a-z0-9-]`, 1–63 bytes, no leading or trailing `-`).

The field names, the JSON shape and the reserved names are the whole contract with slk. Neither module imports the other's code: slk imports `client/`, so this engine importing slk would make the two modules depend on each other. The two pieces of Slack logic the engine needs (reading a pasted session, minting a token) are small and are implemented here.

## Acquisition (`Run`)

1. Prompt once, through `io.PromptSecret`, for the browser session. The prompt accepts what slk's `--add-workspace --browser` accepts: a request copied from the browser's dev tools "as cURL" (bash, cmd or PowerShell form), a `d=xoxd-…` cookie, or the bare `xoxd-…` value. Only the `d` cookie is kept: it is the long-lived credential, and one cookie covers every workspace the browser is signed in to.
2. For every configured workspace (a run re-mints them all with the session just pasted, which also makes a re-run via `dotvault enrol` the way to replace the session): GET `https://<domain>.slack.com/` with the cookie and scrape the page's `api_token` (the same mint slk does), then call `auth.test` with that token and cookie to learn `team_id`, `team_name` and `user_id`, and to prove the session works.
3. Merge into the existing secret (read `io.TargetPath` through `io.Vault`, like the Copy engine): fields this run does not produce are kept (workspace fields no longer listed, anything another tool wrote); removing one is a `dotvault kv patch`, not a side effect of editing config.
4. Stamp `issued_at` = now, `expires_at` = now + `refresh_interval` (default `24h`).

A workspace that fails to mint (not signed in to it in that browser, a 429 that outlives its retries) fails the whole run, naming the workspace, and nothing is written. A partial secret would be marked complete for the workspaces it has and silently lack the one that failed.

Fields: `FieldsFromSettings` returns the configured workspace names, so the manager treats the enrolment as incomplete until every listed workspace is present, and a newly listed workspace prompts for the session again.

Output for the web enrolment card: the prompt is a passphrase-style secret input, which the card already renders; the engine opens no browser. Its instructions (`help_text` default) say where to find the cookie: dev tools → Network → any request to `/api/` → Copy as cURL.

## Refresh (`Refresher`)

The `xoxc` token's lifetime is not documented and not observable before it fails; the `d` cookie is long-lived. So the engine re-mints every workspace's token from its stored cookie past half-life (default every 12 hours), rewriting the whole secret with fresh `access_token`s and new timestamps.

- A mint that lands on Slack's sign-in page instead of a page carrying `api_token`, or an `auth.test` answering `invalid_auth` / `not_authed`, means the cookie is dead: `ErrRevoked`, so the RefreshManager wipes the secret and the enrolment comes back as pending. That is per secret, not per workspace: the cookie is shared, so a dead cookie is dead for all of them.
- Anything else (network, 5xx, 429) is transient: the secret is kept and retried with backoff.
- A workspace whose cookie is not the same as the others (enrolled separately by hand) is refreshed with its own cookie; a revocation of any one cookie still reports revoked, because the alternative is a secret the manager counts as complete with a dead workspace in it.

`refresh_interval` (duration, default `24h`, floor `1h`) is validated at config load, as `token_ttl` is for JFrog.

## Facade: `ReadUserSecretFields`

```go
func (c *Client) ReadUserSecretFields(ctx context.Context, service string) (map[string]string, bool, error)
```

Every field of `kv/users/<identity>/<service>`, stringified exactly as `ReadKVField` stringifies one, with the same `(value, found, err)` semantics: a missing secret is `(nil, false, nil)`. A `ReadKVFields(ctx, mount, path)` sibling mirrors `ReadKVField`.

They are added to `*Client` and to a new one-method interface, `FieldsReader`, not to `Reader`: `Reader` is implemented by consumers' test fakes, and adding a method to it would break every one of them. `Client` satisfies both.

Python bindings are not extended in this change.

## Not in scope

- Reading the Slack desktop app's storage (LevelDB plus per-OS cookie decryption). The paste flow works everywhere the web UI or a terminal does; a desktop reader can be added later as another acquisition path for the same secret shape.
- Enrolling several Slack accounts for one workspace: one secret holds one session per subdomain.
