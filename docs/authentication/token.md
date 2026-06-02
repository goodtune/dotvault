# Token Authentication

Token authentication is the simplest method. It uses an existing Vault token rather than performing an interactive login flow.

## Configuration

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "token"
```

## Token sources

dotvault checks for a token in this order:

1. **`VAULT_TOKEN` environment variable** — takes highest precedence
2. **`~/.dotvault-token` file** — dotvault's own token file

## Use cases

Token auth is most useful for:

- **Development** — using a Vault dev server token
- **CI/CD pipelines** — where a token is injected via environment
- **Service accounts** — where interactive login is not possible

For production desktop environments, [OIDC](oidc.md) or [LDAP](ldap-mfa.md) are preferred.

## Web UI token login

When the web UI is enabled with token auth, users can paste a Vault token into the login form. This is validated against the Vault server before being accepted.

## Token file permissions

dotvault writes tokens to `~/.dotvault-token` with `0600` permissions and warns if the file has different permissions. This mirrors the `0600` convention of the Vault CLI's own `~/.vault-token`, but uses a dotvault-specific filename so running the upstream `vault` CLI in another context cannot overwrite (or be overwritten by) the daemon's cached token.

## Upgrading from earlier releases

Earlier releases read and wrote the Vault default `~/.vault-token`. There is no migration: on first start after upgrading, dotvault looks for the new `~/.dotvault-token`, finds nothing, and re-authenticates once via the configured method. Any token dotvault previously wrote to `~/.vault-token` is left untouched — it is no longer used by dotvault and will sit on disk (at `0600`) until it expires server-side or you remove it. If dotvault was the only thing writing that file, delete it after upgrading to avoid leaving a stale credential around.
