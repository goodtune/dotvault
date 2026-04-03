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
2. **`~/.vault-token` file** — the standard Vault token file

## Use cases

Token auth is most useful for:

- **Development** — using a Vault dev server token
- **CI/CD pipelines** — where a token is injected via environment
- **Service accounts** — where interactive login is not possible

For production desktop environments, [OIDC](oidc.md) or [LDAP](ldap-mfa.md) are preferred.

## Web UI token login

When the web UI is enabled with token auth, users can paste a Vault token into the login form. This is validated against the Vault server before being accepted.

## Token file permissions

dotvault writes tokens to `~/.vault-token` with `0600` permissions and warns if the file has different permissions. This matches the behaviour of the Vault CLI.
