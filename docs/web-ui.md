# Web UI

dotvault includes an optional web dashboard for browser-based authentication, status monitoring, secret inspection, enrolment, and managed SSH forwards. Every page is rendered on the server and has a real, bookmarkable URL.

Three surfaces sit behind one entry point at `/`, which decides where you land:

| You are | `/` shows you |
|---------|---------------|
| Not signed in | the [login view](#login-view) for the configured auth method |
| Signed in with nothing enrolled yet | the [first-run enrolment wizard](#first-run-enrolment-wizard) at `/setup/` |
| Signed in | the [main site](#main-site) at `/ui/` |

## Enabling the web UI

```yaml
web:
  enabled: true
  listen: "127.0.0.1:9000"
```

!!! danger "Loopback only"
    The `listen` address **must** be a loopback address (`127.0.0.1`, `[::1]`, or `localhost`). dotvault will refuse to start if a non-loopback address is configured. This is a hard security constraint that cannot be overridden.

## Login view

The login view lives at `/` and adapts to `vault.auth_method`. It deliberately uses **no JavaScript at all**: its waiting states advance with a meta refresh, so signing in works with scripting disabled.

The web UI supports every auth method:

- **OIDC** — "Login with OIDC" button redirects to the identity provider (via `/auth/oidc/start`, returning to `/auth/oidc/callback` — the redirect URI registered in Vault and your IdP is unchanged)
- **LDAP** — username/password form with inline MFA handling. After submitting, a progress page waits for a Duo push approval (refreshing itself until Vault answers) or prompts for a TOTP passcode. The passcode prompt does not auto-refresh, so it cannot wipe what you are typing
- **Token** — paste a Vault token to authenticate
- **mTLS** (`mtls`, `mtls+tpm`, `mtls+os`) — certificate auth needs no credential in normal operation, so there is no recurring login; the page simply reports that the daemon is signing in with its client certificate. The one and only interactive moment is the **one-time certificate bootstrap** on a new host, which presents whichever of the LDAP or OIDC forms above `vault.mtls.bootstrap_method` names, framed as an enrolment. Because the daemon still has to sign and install the certificate after that login returns, the page then reports that issuance is in flight and refreshes until the daemon holds a token. This is what lets a host with no terminal bootstrap — notably `dotvaultw.exe`, the GUI-subsystem Windows binary with no console.

Note that the token login (`POST /login/token`) is refused with **403** under certificate auth: there the operational token comes from the certificate login alone, so pasting one would install a credential the certificate flow never sanctioned.

## First-run enrolment wizard

On a host where **nothing has been enrolled yet**, signing in lands on `/setup/`: a single page listing every configured enrolment as a card you can Start or Skip, plus a control at the bottom that takes you out to the main site.

The wizard appears *only* while no enrolment has been completed. As soon as you have one credential from an enrolment that needed you — or you leave the wizard yourself — `/` takes you straight to the main site, and any outstanding enrolment waits for you on `/ui/enrolments/` instead of interrupting every visit. Skipping an enrolment counts as having dealt with it, so once every enrolment is either done or skipped the wizard stands aside on its own. The control at the bottom of the page always takes you out. With nothing left to do it is a plain link onward to the dashboard; with enrolments still outstanding it offers to skip the rest, which is a real decision rather than a navigation and so is a button.

Enrolments that need no interaction — the `copy` engine, which mirrors an existing Vault secret — do not appear here at all. One of them being outstanding will not raise the wizard, since there would be nothing for you to do in it; one of them completing does not count as your having been through setup, since it completes on its own without you; and neither does it take up a card on a page whose whole purpose is the things you have to do. You will find it, with its description and controls, under Enrolments on the main site.

Enrolments that need input (the SSH engine's passphrase, for example) prompt inside their card; a card waiting on you stops refreshing so it cannot wipe what you are typing.

## Main site

### Status dashboard

Shows at a glance:

- Authentication state and Vault token TTL
- Vault server address and KV mount configuration
- Per-rule sync status (last synced, secret version)
- Username and user prefix

### Secret inspection

Browse and inspect secrets synced by dotvault. Secrets are hidden by default and require explicit reveal (`?reveal=true`). Nested Vault paths — such as a grouped enrolment written under `databricks/prod` — render in the sidebar as expandable folders that lazy-load their contents on first open, mirroring the grouped layout on the enrolment screen.

### Manual sync

Trigger an immediate sync cycle from the dashboard without waiting for the next poll interval.

### Copy Vault token

A clipboard icon in the header bar allows you to copy the current active Vault token to the clipboard. This lets you authenticate directly to the Vault web UI using your existing token, avoiding a repeated multi-factor authentication flow.

## Customisable content

You can display markdown text on the login page and secret view page:

```yaml
web:
  enabled: true
  listen: "127.0.0.1:9000"
  login_text: |
    Welcome to **dotvault**. Click Login to authenticate via your
    organisation's single sign-on.
  secret_view_text: |
    These secrets are synchronised from Vault. Contact IT support
    if you need additional credentials provisioned.
```

### Pages

The main site lives under `/ui/` (e.g. `http://127.0.0.1:9000/ui/`). Navigation is a left-hand accordion — **Enrolments**, **Remotes**, **Secrets** — where each section expands when its route is active:

- `/ui/` — the index page: the header (version, connection state, Vault link on the left; live "Updated" time, Config, copy-token, and Sync Now on the right) plus the configured `secret_view_text` markdown in the content column. The "Updated" time is a live value streamed over Server-Sent Events.
- `/ui/secrets/` — Secrets panel expanded; `/ui/secrets/<key>` shows a secret (heading linked to the secret in the Vault UI, revision subheading, and a field/value/actions table). Values are masked until the eye icon reveals them — the reveal auto-hides after 30 seconds — and the clipboard icon copies the value **server-side**: the secret never travels to the browser at all.
- `/ui/enrolments/` — Enrolments panel expanded, grouped by engine (an engine nests into a folder only when it has more than one enrolment) with a status dot per entry: green = enrolled, orange = in progress, red = error, grey = not started. `/ui/enrolments/<engine>/<key>/` is where the enrolment itself runs.
- `/ui/remotes/` — managed SSH forwards with the same status-dot vocabulary (green = connected, orange = connecting, red = enabled but disconnected, grey = disabled) and an add form revealed by the Add button; `/ui/remotes/<host>/` edits one remote (port, remote socket, enabled switch, delete) and shows its pinned host key — the SHA256 fingerprint with the full key revealable on demand, or a note when trust comes from a configured certificate authority instead. Adding an unpinned host presents the same fingerprint-confirmation gesture the CLI uses. Both pages subscribe to a live state stream (`/ui/sse/ssh`), so state and configuration changes — a forward connecting or dropping, a remote edited, added, or removed, including asynchronously by `dotvault ssh` or the daemon's own reconnect loop — appear without refreshing the page.
- `/ui/config/` — the Effective Configuration view, with the left navigation kept in place.

Interactivity comes from [datastar](https://data-star.dev) patching server-rendered fragments over SSE; there is no client-side application state. An unauthenticated visit to any `/ui/` page redirects to `/`, which owns all login flows.

## Security

- **CSRF protection** — every browser POST (the login forms, the wizard, and the `/ui/` actions) requires a **present, same-origin `Origin` header**: browsers attach one to every POST, so a cross-site request — or one with no Origin at all — is rejected. This suits server-rendered forms and multi-tab use better than a one-shot token, and it protects the login forms too: without it a hostile page could post its own Vault token and have the daemon adopt an attacker-chosen identity. The JSON API endpoints used by `dotvault ssh` and scripts still use the token handshake (`GET /api/v1/csrf`), with three deliberate exceptions: the peer-action endpoints `POST /api/v1/remote/browse`, `POST /api/v1/remote/notify`, and `POST /api/v1/remote/clipboard` (see below)
- **Content Security Policy** — `default-src 'self'; frame-ancestors 'none'` prevents XSS via injected scripts and clickjacking via framing. The scripted pages (`/ui/` and `/setup/`) additionally allow `'unsafe-eval'` for scripts (datastar compiles its `data-*` attribute expressions with the Function constructor) and inline styles; the login view keeps the strict policy, and inline scripts are forbidden everywhere
- **X-Content-Type-Options** — `nosniff` header on all responses
- **Loopback binding** — enforced at startup; non-loopback addresses are rejected

## API endpoints

The web UI communicates with the dotvault daemon via a REST API:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/status` | Server status, auth state, token TTL, sync state, certificate-bootstrap state |
| `GET` | `/api/v1/rules` | Configured sync rules |
| `GET` | `/api/v1/token` | Current Vault token (authenticated sessions only) |
| `GET` | `/api/v1/secrets/{path}` | List or reveal a secret |
| `POST` | `/api/v1/sync` | Trigger immediate sync (CSRF-protected) |
| `POST` | `/api/v1/remote/browse` | Open a form-posted `url` in this host's default browser (not CSRF-protected) |
| `POST` | `/api/v1/remote/notify` | Raise a form-posted desktop notification on this host (not CSRF-protected) |
| `POST` | `/api/v1/remote/clipboard` | Put form-posted `text` on this host's clipboard (not CSRF-protected) |
| `GET` | `/api/v1/csrf` | Obtain a one-time CSRF token |

`POST /api/v1/remote/browse` is the outbound counterpart of `GET /api/v1/token`: over the same SSH-forwarded Unix socket that lets a headless peer borrow the workstation's token, it lets the peer hand a URL back so browser-driven flows open where a browser actually exists — see [`dotvault browse`](cli.md#dotvault-browse). It accepts a form POST (`url=https://...`, body only — the query string is ignored) and only `http`/`https` URLs with a host and no embedded `user:pass@` credentials; `file://` and custom protocol schemes are rejected before anything reaches the OS URL opener, and only one browser open runs at a time (concurrent requests get a 503). It is deliberately exempt from the CSRF handshake: its consumer is a bare `curl`/`dotvault browse` POST with no practical way to run the issue-then-spend token dance, and it reads no state and returns nothing sensitive. Cross-site browser traffic is rejected by an `Origin` check instead — browsers always attach an `Origin` header to cross-origin POSTs, and only the daemon's own origin (a loopback hostname on the daemon's own listener port — a page served by any *other* loopback server does not qualify) is accepted; curl and the CLI send no `Origin` and pass.

`POST /api/v1/remote/notify` is the same idea for desktop notifications — see [`dotvault notify`](cli.md#dotvault-notify). It accepts a form POST with `level` (one of `info`, `warning`, `error`, `attention`), `title`, an optional `body`, and an optional `action_url`, and raises a native notification (Windows toast / macOS Notification Center / Linux D-Bus). `action_url` (http/https, the same allowlist as browse) makes the notification open that URL when clicked on Windows, and is appended to the body on macOS/Linux where a one-shot notification cannot be made clickable. It shares the browse endpoint's security posture exactly: no CSRF, the same `Origin` check, body-only fields, and a single-flight bounded delivery. Its input-validation control restricts `level` to the known set, validates `action_url` against the http/https allowlist, and sanitizes `title`/`body` — stripping control characters and neutralizing the metacharacters that would otherwise break out of the Windows toast backends (an XML CDATA section and a PowerShell here-string), so a crafted notification cannot inject toast XML or execute a PowerShell subexpression on the delivering host. Log lines record the level and field lengths only, never the title/body text or the `action_url` (arbitrary, potentially capability-bearing content that may name secret systems).

`POST /api/v1/remote/clipboard` is the third peer action — see [`dotvault clipboard`](cli.md#dotvault-clipboard). It accepts a form POST with a single `text` field (body only — a URL is the last place a secret should travel) and places the value on this host's clipboard, so a headless peer can stage a one-time token or device code right where the user's paste is after `remote/browse` opened the page that asks for it. It shares the browse/notify security posture exactly: no CSRF, the same `Origin` check, and a single-flight bounded write. Validation rejects input no clipboard can carry faithfully (interior NULs, invalid UTF-8) or that signals a caller bug (empty, over 64 KiB); the text is otherwise written **verbatim** — clipboard content is data, never interpolated into an evaluated context, and the typical payload is a credential that must arrive byte-for-byte intact. This endpoint carries the most secret-bearing payload of the three, so log lines record the text's length only — never the content — and writer errors are additionally scrubbed of the exact text before logging or being returned (best-effort defense in depth; the writers never embed their input in errors).

Browser endpoints (present only when `web.enabled`; all POSTs are Origin-checked):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Login view, or a redirect onward to `/setup/` or `/ui/` |
| `GET` | `/auth/oidc/start` | Redirect to Vault OIDC auth URL |
| `GET` | `/auth/oidc/callback` | Handle OIDC callback |
| `POST` | `/login/ldap` | Start an async LDAP login |
| `GET` | `/login/ldap` | LDAP progress page (MFA wait or passcode prompt) |
| `POST` | `/login/ldap/totp` | Submit an MFA passcode |
| `POST` | `/login/token` | Validate and adopt a pasted token (403 under certificate auth) |
| `GET` | `/setup/` | First-run enrolment wizard |
| `POST` | `/setup/complete` | Abandon whatever is still outstanding and enter the main site |

## Removed endpoints

The browser surface above replaces a single-page application that drove login and enrolment through JSON endpoints. Those endpoints existed only to serve that application and have been removed along with it — the equivalent work is now done by the form POSTs and page GETs listed above.

| Removed | Replacement |
|---------|-------------|
| `POST /auth/ldap/login` | `POST /login/ldap` (form POST, redirects to the progress page) |
| `GET /auth/ldap/status` | `GET /login/ldap` (renders the state rather than returning it) |
| `POST /auth/ldap/mfa` | `POST /login/ldap/totp` |
| `POST /auth/token/login` | `POST /login/token` |
| `GET /api/v1/enrol` and the `/api/v1/enrol/*` action endpoints | `/setup/` and `/ui/enrolments/` with their form POSTs |

Nothing under `/api/v1/` other than the enrolment endpoints changed: the status, rules, config, secrets, sync, token, SSH-remote, and peer-action routes are unaffected, so anything scripting against those keeps working. If you were driving login or enrolment programmatically, use [`dotvault login`](cli.md) and [`dotvault enrol`](cli.md#dotvault-enrol) instead — those are the supported non-browser paths and always were.
