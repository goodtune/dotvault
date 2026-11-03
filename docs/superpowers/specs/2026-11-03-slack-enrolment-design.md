# Slack enrolment engine — design

## Problem

[slk](https://github.com/goodtune/slk), a terminal Slack client, talks to Slack with a browser session: an `xoxc-` token plus the `d` cookie. Today it keeps both in one plaintext JSON file per workspace under `~/.local/share/slk/tokens/`. We want the session enrolled into Vault by dotvault and read back by slk through the `client/` facade, with nothing on the user's disk.

That needs two things here: an enrolment engine that stores the session, and a facade method that reads every field of a secret, because slk does not know the workspace names in advance.

## What is stored: the cookie only

The `d` cookie is the long-lived credential; the `xoxc` token is derived from it by loading the workspace page, and slk already does that at every start. So dotvault carries the cookie and nothing else, and never contacts Slack. Minting here as well would put a short-lived token in Vault that nothing needs, plus a refresh loop to keep it current.

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
{"domain": "acme", "cookie": "xoxd-…"}
```

A workspace name must be a valid Slack domain, checked at config load: one label (`[a-z0-9-]`, 1–63 bytes, no leading or trailing `-`), optionally followed by `.enterprise` for an Enterprise Grid organisation (`acme.enterprise` for `acme.enterprise.slack.com`).

The field names and the JSON shape are the whole contract with slk. Neither module imports the other's code: slk imports `client/`, so this engine importing slk would make the two modules depend on each other. The one piece of Slack logic the engine needs (reading a pasted session) is small and implemented here.

## Acquisition (`Run`)

1. Prompt once, through `io.PromptSecret`, for the browser session. The prompt accepts what slk's `--add-workspace --browser` accepts: a request copied from the browser's dev tools as cURL (bash or cmd) or PowerShell, a `d=xoxd-…` cookie, or the bare `xoxd-…` value. Only the `d` cookie is kept; one cookie covers every workspace the browser is signed in to.
2. Write it for every configured workspace (a re-run via `dotvault enrol` is how the session is replaced).
3. Merge into the existing secret (read `io.TargetPath` through `io.Vault`, like the Copy engine): fields this run does not write are kept (workspace fields no longer listed, anything another tool wrote); removing one is a `dotvault kv patch`, not a side effect of editing config.

The cookie is not checked against Slack: that would mean minting a token, which is slk's job. A wrong or signed-out cookie surfaces when slk starts, as a warning naming the workspace.

Fields: `FieldsFromSettings` returns the configured workspace names, so the manager treats the enrolment as incomplete until every listed workspace is present, and a newly listed workspace prompts for the session again.

Output for the web enrolment card: the prompt is a passphrase-style secret input, which the card already renders; the engine opens no browser. The prompt's own label says where to find the session; an admin can add `help_text` as for any enrolment.

## No refresh

The engine is not a `Refresher`. The cookie is long-lived and cannot be rotated without the user; when Slack stops accepting it, re-enrolling replaces it.

## Facade: `ReadUserSecretFields`

```go
func (c *Client) ReadUserSecretFields(ctx context.Context, service string) (map[string]string, bool, error)
```

Every field of `kv/users/<identity>/<service>`, stringified exactly as `ReadKVField` stringifies one, with the same `(value, found, err)` semantics: a missing secret is `(nil, false, nil)`. A `ReadKVFields(ctx, mount, path)` sibling mirrors `ReadKVField`.

They are added to `*Client` and to a new one-method interface, `FieldsReader`, not to `Reader`: `Reader` is implemented by consumers' test fakes, and adding a method to it would break every one of them. `Client` satisfies both.

Python bindings are not extended in this change.

## Not in scope

- Reading the Slack desktop app's storage (LevelDB plus per-OS cookie decryption). The paste flow works everywhere the web UI or a terminal does; a desktop reader can be added later as another way to fill the same secret shape.
- Enrolling several Slack accounts for one workspace: one secret holds one session per subdomain.
