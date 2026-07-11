# ghp Onboarding

The `ghp` enrolment engine automates credential acquisition for a self-hosted [ghp server](https://github.com/goodtune/ghp) — the "GitHub Proxy for Autonomous Coding Agents". It runs ghp's CLI device-authorization flow: an [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)-style device grant served entirely by your ghp server. dotvault asks the server for a device code, you approve it in a browser (signing in to ghp via GitHub there), and dotvault polls until the server hands back a CLI session token. This is the same flow as `ghp auth login`.

The captured credential is ghp's **CLI session token** (prefix `ghpr_`) — not a GitHub token and not an agent-facing `ghx_` proxy token. dotvault stores it alongside the server URL, which are exactly the two fields ghp's own dotvault integration reads back out of Vault.

## Configuration

### Minimal

```yaml
enrolments:
  ghp:
    engine: ghp
    settings:
      url: "https://ghp.example.com"   # your ghp server's base URL

rules:
  - name: ghp
    vault_key: "ghp"
    target:
      path: "~/.config/ghp/config.yaml"
      format: yaml
      template: |
        server_url: "{{ .server_url }}"
        user_token: "{{ .user_token }}"
```

### With a proxy

```yaml
enrolments:
  ghp:
    engine: ghp
    settings:
      url: "https://ghp.example.com"
      https_proxy: http://squid.example.com:3128   # default: system proxy machinery
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `url` | _(required)_ | The ghp server base URL (e.g. `https://ghp.example.com`). Scheme + host only — no path, query, or fragment. A bare host gains an `https://` scheme. |
| `https_proxy` | host's system proxy machinery | Override HTTPS proxy for all outbound calls from this enrolment. `http_proxy` is accepted as an alias. See the [GitHub engine notes](github.md#behind-a-corporate-proxy) for proxy behaviour. |

## How the device flow works

1. dotvault `POST`s to `{url}/cli/auth/device` to start a device authorization
2. The server returns a one-time **user code** and a verification URL (copied to the clipboard if possible)
3. The user opens the verification URL in a browser, signs in to ghp via GitHub, confirms the code matches, and approves
4. dotvault polls `{url}/cli/auth/device/token` until the user approves (`authorization_pending` while waiting; `slow_down` and HTTP 429 are honoured)
5. On approval the server returns the `ghpr_` session token and username, which are written to Vault

### Terminal output

```
! First, copy your one-time code: ABCD-EFGH
  (confirm it matches the code shown after you sign in)
✓ Opened https://ghp.example.com/cli/auth?user_code=ABCD-EFGH in browser
⠼ Waiting for authentication...
✓ ghp (GitHub Proxy) — credentials acquired for @octocat
```

## Credentials stored in Vault

The engine writes these fields to the Vault KV secret:

| Field | Description |
|-------|-------------|
| `user_token` | The ghp CLI session token (prefix `ghpr_`) |
| `server_url` | The ghp server the token is valid against |
| `user` | The ghp username (written when the server returns it; not required for the enrolment to be considered complete) |

## Consuming the credential

There are two ways to use the stored credential.

**Render a config file (shown above).** A sync rule writes `~/.config/ghp/config.yaml` with `server_url` and `user_token`. The `ghp` CLI then reads its session token from that file.

**Use ghp's native dotvault integration.** The ghp CLI can read its `user_token` and `server_url` directly from Vault via dotvault's `client` library — point its `dotvault:` config stanza at the same KV path (`kv/users/<you>/ghp`). dotvault writes exactly the `user_token` and `server_url` field names ghp expects by default, so no field remapping is needed. With this approach you do **not** need the sync rule above — ghp reads from Vault on demand rather than from a rendered file.

## Refresh

Unlike the JFrog and Databricks engines, the `ghp` engine does **not** implement automatic refresh. The ghp session token does not expire on a fixed schedule and ghp exposes no unattended refresh endpoint for it. If a token is revoked or rotated server-side, re-enrol (`dotvault enrol ghp`, or the web UI's **Re-enrol** button) to acquire a fresh one — the same recovery model the GitHub engine uses for its OAuth token.
