# Token Authentication

Token authentication is the simplest method. It uses an existing Vault token rather than performing an interactive login flow.

## Configuration

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "token"
```

!!! note "The `+tpm` suffix has no effect here"
    Sealing applies to the token file dotvault *writes*, but the `token` method only *reads* a token you supply — so `token+tpm` seals nothing. dotvault will still transparently read and unseal a TPM-sealed file written by another method. See [TPM-Backed Protection](tpm.md).

## Token sources

dotvault checks for a token in this order:

1. **`DOTVAULT_TOKEN` environment variable** — takes highest precedence
2. **`~/.dotvault-token` file** — dotvault's own token file

The standard `VAULT_TOKEN` environment variable is **deliberately ignored** — including the Vault SDK's automatic pickup of it. It belongs to the upstream `vault` CLI, and honouring it would let an unrelated shell session's token silently leak into the daemon (the same isolation rationale as the dotvault-specific token filename below).

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

<!-- TRANSITIONAL: added in v0.20.0 for the ~/.vault-token -> ~/.dotvault-token move. Remove this section around v0.23.0 (≈3 minor releases) once upgrading installs are unlikely. -->
## Upgrading from earlier releases

!!! note "Transitional — applies only when upgrading from v0.19.0 or earlier"
    This note covers the one-time move from Vault's default `~/.vault-token` to dotvault's own `~/.dotvault-token` and will be removed in a future release (around v0.23.0).

    Earlier releases read and wrote the Vault default `~/.vault-token`. There is no migration: on first start after upgrading, dotvault looks for the new `~/.dotvault-token`, finds nothing, and re-authenticates once via the configured method. Any token dotvault previously wrote to `~/.vault-token` is left untouched — it is no longer used by dotvault and will sit on disk (at `0600`) until it expires server-side or you remove it. If dotvault was the only thing writing that file, delete it after upgrading to avoid leaving a stale credential around.

!!! warning "Breaking change — `VAULT_TOKEN` is no longer honoured"
    Earlier releases read the token from the standard `VAULT_TOKEN` environment variable. That variable is now **ignored entirely** (see [Token sources](#token-sources) above for the rationale). If your CI pipeline, service account, or dev environment injects a token via `VAULT_TOKEN`, authentication will silently fall back to the token file or the configured interactive flow after upgrading — there is no warning when an ignored `VAULT_TOKEN` is present. Rename the variable to `DOTVAULT_TOKEN` to restore the previous behaviour.
