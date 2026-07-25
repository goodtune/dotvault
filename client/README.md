# dotvault public client API

`github.com/goodtune/dotvault/client` is dotvault's public, importable Go surface. It lets any Go module talk to the same Vault, authenticate the same way, and read from the exact path dotvault writes to, without re-implementing connectivity, token resolution, the login flow, or the user-path convention. dotvault stays the single source of truth; consumers can't silently diverge. A common use is a tool that needs to read a per-user credential (a token, an SSH key) that dotvault enrolled and keeps current — but the surface is deliberately generic and makes no assumptions about who is calling.

The package is a thin facade over dotvault's internals (`internal/config`, `internal/auth`, `internal/vault`). Those packages stay internal — the facade is the only supported import boundary, so dotvault can refactor freely behind it.

## Quick start

```go
import "github.com/goodtune/dotvault/client"

ctx := context.Background()

// DefaultConfigPath() returns the per-OS config *file* path:
// /etc/xdg/dotvault/config.yaml (Linux, honouring XDG_CONFIG_DIRS),
// %ProgramData%\dotvault\config.yaml (Windows), Application Support (macOS).
// LoadConfig reads that file — or, on Windows, the GPO registry instead when
// policy keys are present (it routes through config.LoadSystem).
cfg, err := client.LoadConfig(client.DefaultConfigPath())
if err != nil { /* fail closed */ }

cli, err := client.New(cfg)
if err != nil { /* fail closed */ }

// DOTVAULT_TOKEN env → token file → interactive login (OIDC browser / LDAP prompt).
// Authenticate logs in when no cached token works, so it returns ErrUnreachable
// or ErrAuthFailed — not ErrLoginRequired (that's AuthenticateCached's outcome).
if err := cli.Authenticate(ctx); err != nil {
    switch {
    case errors.Is(err, client.ErrUnreachable): // vault down — retry / back off
    case errors.Is(err, client.ErrAuthFailed):  // a login ran but failed
    }
    return err
}

// service is an enrolment path segment under kv/users/<user>/; field is a
// key within that secret. E.g. the github enrolment engine writes oauth_token.
tok, found, err := cli.ReadUserSecret(ctx, "gh", "oauth_token")
```

A runnable version of this flow, and a non-interactive-preflight variant, are in the package's `Example` functions (godoc / `example_test.go`). Prefer the `dotvault` import alias if you want a shorter qualifier: `import dotvault "github.com/goodtune/dotvault/client"`.

## Identity: it's the OS user, not the token

This is the one thing to internalise before depending on the package. dotvault derives the `<user>` segment of `kv/users/<user>/...` from the **OS account the process runs as** (the username with any `DOMAIN\` prefix stripped), *not* from the Vault token's `display_name`, entity name, or metadata. `IdentityName()` returns that OS-derived name, and `ReadUserSecret` composes paths with it.

The practical consequence: by default a consumer must run as the **same OS user** as the dotvault that populated the secrets. That is normally true — dotvault is a per-user daemon running in the user's own context — but it means a service account or container running as a different user will, by default, read from a different (probably empty) path. The failure mode is silent: a wrong identity reads a non-existent path, which surfaces as `found == false`, *not* an error.

If your deployment can't guarantee same-user, pass `client.WithIdentity("<name>")` to `New` to set the path segment explicitly: `cli, err := client.New(cfg, client.WithIdentity("alice"))`. This also makes downstream tests deterministic (no dependence on the host's OS account). It does not change the username used for an interactive LDAP prompt — only the `kv/users/<name>/...` path.

`IdentityName()` takes no context and makes no Vault call — the value is local (the override if set, else the OS user).

## Authentication entry points

| Method | Behaviour | Use when |
| --- | --- | --- |
| `Authenticate(ctx)` | `DOTVAULT_TOKEN` → token file → interactive login. Short-circuits with `ErrUnreachable` (no prompt) if Vault is down. | Normal startup where a human is present. |
| `AuthenticateCached(ctx)` | env → token file → peer socket borrow (if `TokenSocket` is set). Never prompts. `ErrLoginRequired` if no usable token. | Side-effect-free preflight (`doctor`), non-interactive / CI callers. |
| `Login(ctx)` | Unconditional fresh login (ignores cached token). Equivalent to `dotvault login`. | Forcing re-auth. |

> **`Authenticate` and `Login` are interactive.** They can open a browser (OIDC) or block reading a password and MFA code from the terminal (LDAP). That is surprising inside a library call: **do not call them from a non-interactive service or daemon.** In those contexts use `AuthenticateCached` and surface `ErrLoginRequired` to the operator, or arrange for a token to be present some other way. LDAP `Login` without a TTY returns an error wrapping `ErrAuthFailed` rather than hanging.

Token precedence and the login flow match the daemon's exactly. `VAULT_TOKEN` is deliberately ignored — including the Vault SDK's own automatic pickup, which the underlying client construction neutralises — so a concurrent `vault` CLI session's environment never leaks in; use `DOTVAULT_TOKEN` to supply a token via the environment. The token file location (`~/.dotvault-token`) is dotvault's built-in default rather than a configured value — it isn't carried in the YAML/registry config; `New` fills an empty `Config.TokenFile` from `DefaultTokenFile()`. Set `Config.TokenFile` explicitly to override it.

If `VaultConfig.TokenSocket` is set (dotvault's `vault.token_socket` — a peer dotvault daemon's web-API Unix socket), `AuthenticateCached` borrows a live token from the peer after `DOTVAULT_TOKEN` and the token file come up empty, before reporting `ErrLoginRequired`. The borrow is a plain HTTP GET over the socket with no browser or prompt, so it stays within the cached, side-effect-free contract — a consumer on a host with no local token but a live peer socket (the SSH `RemoteForward` topology) reads secrets without an interactive login of its own. It is best-effort: a missing or stale socket simply yields no token.

## Peer actions: Browse and Notify

Over the same `TokenSocket` peer, the client can ask the workstation dotvault to **open a URL in a browser** or **raise a desktop notification** — the programmatic equivalents of `dotvault browse`/`dotvault notify`. This is for the headless-consumer topology: a program on a machine with no browser hands a URL or a notification back over the forwarded socket, so a browser-driven flow (an OAuth page, a report link) or a "job finished" toast lands on the workstation where a human is looking.

```go
if err := cli.Browse(ctx, "https://example.com/report"); err != nil {
    // errors.Is(err, client.ErrPeerUnavailable) → no socket / peer down / open failed
}
if err := cli.Notify(ctx, "info", "Backup complete", "42 files, 0 errors", ""); err != nil {
    // same taxonomy as Browse
}
// Attach a clickable link (opens on click on Windows; appended to the body on macOS/Linux):
cli.Notify(ctx, "error", "Build failed", "click for the run", "https://ci.example/build/42")
```

`Browse`/`Notify` differ from the `dotvault` CLIs in two deliberate ways: there is **no local fallback** (a headless library has no local browser or notifier), so an unreachable peer is an error rather than a silent local open; and there is **no local validation** — the peer endpoint validates and sanitizes the URL / level / title authoritatively (that is where the action happens and where the security boundary belongs), so the facade stays a thin transport. A peer that is not configured, cannot be reached, or reports it could not perform the action returns `ErrPeerUnavailable`; a request the peer *rejects as invalid* (a non-`http(s)` URL, an unknown level, an empty title) returns a plain error carrying the peer's message. `Notify`'s level is one of `info`, `warning`, `error`, `attention`; its final argument is an optional `actionURL` — an http/https link the notification opens when clicked (on Windows; appended to the body on macOS/Linux). Pass `""` for no link.

## Error categories

Sentinels are `errors.Is`-able and map to a small, stable set of outcomes:

| Sentinel | Meaning | Suggested metric label |
| --- | --- | --- |
| `nil` | success | `success` |
| `ErrLoginRequired` | no usable cached token; login not run | `missing_token` |
| `ErrDenied` | Vault rejected the request (401/403) | `denied` |
| `ErrUnreachable` | DNS/connection/TLS/timeout/5xx | `unreachable` |
| `ErrAuthFailed` | interactive login ran but didn't yield a token | `denied` (your choice) |
| `ErrPeerUnavailable` | `Browse`/`Notify`: no socket, peer down, or action failed | `peer_unavailable` |
| `(value, false, nil)` from a read | secret/field absent | `missing_field` |

`ErrAuthFailed` is a distinct sentinel from `ErrDenied` so you *can* tell "wrong/declined credentials" from "token lacks the policy". Folding both into a `denied` metric label is reasonable but is your decision, not the library's.

A missing secret path and a missing field both return `found == false` with a `nil` error, so "the field isn't there" is never conflated with "couldn't reach Vault". On each error sentinel a consumer typically: `ErrLoginRequired` → tell the user to run `dotvault login` (or call `Authenticate` interactively); `ErrUnreachable` → retry / back off; `ErrDenied` / `ErrAuthFailed` → fail closed and surface the auth problem; `found == false` → treat the credential as not-yet-enrolled.

## KV mount and path layout

The KV v2 mount and user prefix come from dotvault's config (`vault.kv_mount`, default `kv`; `vault.user_prefix`, default `users/`). `ReadUserSecret(ctx, service, field)` reads `{kv_mount}/{user_prefix}{identity}/{service}` field `{field}`. Use `ReadKVField(ctx, mount, path, field)` directly if you need to address a non-standard layout.

Vault namespaces are not a dotvault config field; the underlying client honours `VAULT_NAMESPACE`.

## Testing on the consumer side

The package ships `client.Reader`, a narrow interface covering the read side (`IdentityName`, `ReadKVField`, `ReadUserSecret`) that `*client.Client` satisfies. Depend on `client.Reader` wherever your code consumes a secret, and substitute a hand-written fake in tests — no live Vault, no network. See the runnable `ExampleReader` in `example_test.go` for a ~15-line fake.

Authentication is intentionally left out of `Reader`: it has side effects (token-file writes, browser/terminal interaction) that belong in `main`, not in the unit under test. Construct and authenticate a real `*client.Client` at startup; pass it (as a `Reader`) into the code that reads.

One caveat: `Authenticate`/`AuthenticateCached` read process environment (`DOTVAULT_TOKEN`, `VAULT_NAMESPACE`), so tests that exercise the real client must use `t.Setenv` and can't run with `t.Parallel()`. The `Reader` fake sidesteps this entirely.
