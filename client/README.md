# dotvault public client API

`github.com/goodtune/dotvault/client` is dotvault's public, importable Go surface. It lets another tool — for example an agent runner that reads identity tokens out of Vault — talk to the same Vault, authenticate the same way, and read from the exact path dotvault writes to, without re-implementing connectivity, token resolution, the login flow, or the user-path convention. dotvault stays the single source of truth; consumers can't silently diverge.

The package is a thin facade over dotvault's internals (`internal/config`, `internal/auth`, `internal/vault`). Those packages stay internal — the facade is the only supported import boundary, so dotvault can refactor freely behind it.

## Quick start

```go
import "github.com/goodtune/dotvault/client"

// DefaultConfigPath() resolves per-OS: /etc/xdg/dotvault/config.yaml (Linux,
// honouring XDG_CONFIG_DIRS), %ProgramData%\dotvault\config.yaml (Windows, or
// the GPO registry if present), Application Support (macOS).
cfg, err := client.LoadConfig(client.DefaultConfigPath())
if err != nil { /* fail closed */ }

cli, err := client.New(cfg)
if err != nil { /* fail closed */ }

// VAULT_TOKEN env → token file → interactive login (OIDC browser / LDAP prompt).
if err := cli.Authenticate(ctx); err != nil {
    // errors.Is(err, client.ErrUnreachable | client.ErrAuthFailed | client.ErrLoginRequired)
}

gh, _, err := cli.ReadUserSecret(ctx, "gh",      "oauth_token") // → GITHUB_TOKEN
ll, _, err := cli.ReadUserSecret(ctx, "litellm", "token")       // → LITELLM_API_KEY / ANTHROPIC_AUTH_TOKEN
```

Prefer the `dotvault` alias if you want the proposal's spelling: `import dotvault "github.com/goodtune/dotvault/client"`.

## Identity: it's the OS user, not the token

This is the one thing to internalise before depending on the package. dotvault derives the `<user>` segment of `kv/users/<user>/...` from the **OS account the process runs as** (the username with any `DOMAIN\` prefix stripped), *not* from the Vault token's `display_name`, entity name, or metadata. `IdentityName()` returns that OS-derived name, and `ReadUserSecret` composes paths with it.

The practical consequence: a consumer must run as the **same OS user** as the dotvault that populated the secrets. That is normally true — dotvault is a per-user daemon running in the user's own context — but it means a service account or container running as a different user will read from a different (probably empty) path. If your deployment can't guarantee same-user, raise it; baking a token-derived identity into dotvault is a larger change with its own migration story.

`IdentityName()` takes no context and makes no Vault call — the value is local.

## Authentication entry points

| Method | Behaviour | Use when |
| --- | --- | --- |
| `Authenticate(ctx)` | `VAULT_TOKEN` → token file → interactive login. Short-circuits with `ErrUnreachable` (no prompt) if Vault is down. | Normal startup where a human is present. |
| `AuthenticateCached(ctx)` | env → file only. Never prompts. `ErrLoginRequired` if no usable token. | Side-effect-free preflight (`doctor`), CI-ish callers. |
| `Login(ctx)` | Unconditional fresh login (ignores cached token). Equivalent to `dotvault login`. | Forcing re-auth. |

Token precedence, the token file location (`~/.vault-token`), and the login flow are all dotvault's — unchanged.

## Error categories

Sentinels are `errors.Is`-able and map to a small, stable set of outcomes:

| Sentinel | Meaning | Suggested metric label |
| --- | --- | --- |
| `nil` | success | `success` |
| `ErrLoginRequired` | no usable cached token; login not run | `missing_token` |
| `ErrDenied` | Vault rejected the request (401/403) | `denied` |
| `ErrUnreachable` | DNS/connection/TLS/timeout/5xx | `unreachable` |
| `ErrAuthFailed` | interactive login ran but didn't yield a token | `denied` |
| `(value, false, nil)` from a read | secret/field absent | `missing_field` |

A missing secret path and a missing field both return `found == false` with a `nil` error, so "the field isn't there" is never conflated with "couldn't reach Vault".

## KV mount and path layout

The KV v2 mount and user prefix come from dotvault's config (`vault.kv_mount`, default `kv`; `vault.user_prefix`, default `users/`). `ReadUserSecret(ctx, service, field)` reads `{kv_mount}/{user_prefix}{identity}/{service}` field `{field}`. Use `ReadKVField(ctx, mount, path, field)` directly if you need to address a non-standard layout.

Vault namespaces are not a dotvault config field; the underlying client honours `VAULT_NAMESPACE`.

## Testing on the consumer side

The methods you'll call (`Authenticate`, `AuthenticateCached`, `ReadUserSecret`, `IdentityName`) are a small set — define your own interface over them in your tests and substitute a fake. No live Vault required. dotvault's own tests for this package stand up an `httptest` server (`client/client_test.go`) if you want a reference.
