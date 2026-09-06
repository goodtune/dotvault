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

## Tokens Vault has already refused

A cached token that Vault refuses is not retried on every poll. The first time Vault answers a lookup with `403 permission denied` — or reports the token as expired — dotvault records that answer and stops presenting *that token* until something changes. Every step that tries a token records the refusal (the startup reuse check, the peer-socket borrow, the headless idle loop, the token-lifecycle poll); the two that run repeatedly — the idle loop and the lifecycle poll — also check the record before going to Vault at all. A daemon holding no token likewise stops asking, rather than sending a tokenless lookup every ten seconds to be told what it already knows.

Without this, an expired `~/.dotvault-token` on a host nobody is logged into produced a lookup every ten seconds for as long as the daemon ran — tens of thousands of denied requests per host per week, and a Vault-side traffic problem once a fleet was in that state.

The suppression is per token *value*, so a genuinely new token is never affected: rewrite the token file (`dotvault login`, or anything else that writes it) and the new value is picked up on the next poll on every platform, with nothing needing to notice the write. Rewriting the *same* bytes is the case that needs a nudge, and the running daemon gets one from the Linux file watcher, from a peer socket reconnecting while it needs a token, or from `SIGHUP` (`systemctl --user reload dotvault.service`; the tray's "Reload config" entry on Windows). During the pre-authentication idle on macOS and Windows there is no such nudge — a *new* token is still picked up on the poll, but an unchanged one waits for the backstop below. If the token is refused again, it is suppressed again.

As a backstop for changes dotvault cannot observe — a policy corrected at Vault, a failover completing — a suppressed token is re-probed once every 15 minutes regardless. So a daemon whose token becomes usable again heals on its own; it just does so at that cadence instead of every ten seconds. Note that while a token is suppressed it is not being renewed either; that was already true of any token failing its lookup, since renewal happens after a successful one.

Nothing about which tokens are tried, or in what order, changes — only how often a refused one is re-asked about. `dotvault status` still reports the real state, and the daemon still signals that re-authentication is required.

!!! note "If you alert on the re-authentication log line"
    `vault token invalid, re-authentication required` (WARN) is now logged when the daemon *enters* that state rather than on every retry; subsequent retries log at DEBUG. Alerting rules that counted repeats of that line will see one occurrence per episode instead of one every ten seconds.

!!! tip "Watching this in a metrics backend"
    The `dotvault.token.denylist` counter carries an `event` attribute: `denied` (a token entering suppression), `suppressed` (a lookup that was *not* sent), and `cleared` (suppression dropped after a token file write, socket reconnect, or SIGHUP). A rising `suppressed` against a flat `denied` is a host sitting without a usable token — the condition that used to show up as request volume on `dotvault.vault.calls`.

## Token file permissions

dotvault writes tokens to `~/.dotvault-token` with `0600` permissions and warns if the file has different permissions. (The exception is `auth_method: mtls+os`, which writes no token file at all — see [mTLS](mtls.md#no-token-at-rest-mtlsos).) This mirrors the `0600` convention of the Vault CLI's own `~/.vault-token`, but uses a dotvault-specific filename so running the upstream `vault` CLI in another context cannot overwrite (or be overwritten by) the daemon's cached token.

<!-- TRANSITIONAL: added in v0.20.0 for the ~/.vault-token -> ~/.dotvault-token move. Remove this section around v0.23.0 (≈3 minor releases) once upgrading installs are unlikely. -->
## Upgrading from earlier releases

!!! note "Transitional — applies only when upgrading from v0.19.0 or earlier"
    This note covers the one-time move from Vault's default `~/.vault-token` to dotvault's own `~/.dotvault-token` and will be removed in a future release (around v0.23.0).

    Earlier releases read and wrote the Vault default `~/.vault-token`. There is no migration: on first start after upgrading, dotvault looks for the new `~/.dotvault-token`, finds nothing, and re-authenticates once via the configured method. Any token dotvault previously wrote to `~/.vault-token` is left untouched — it is no longer used by dotvault and will sit on disk (at `0600`) until it expires server-side or you remove it. If dotvault was the only thing writing that file, delete it after upgrading to avoid leaving a stale credential around.

!!! warning "Breaking change — `VAULT_TOKEN` is no longer honoured"
    Earlier releases read the token from the standard `VAULT_TOKEN` environment variable. That variable is now **ignored entirely** (see [Token sources](#token-sources) above for the rationale). If your CI pipeline, service account, or dev environment injects a token via `VAULT_TOKEN`, authentication will silently fall back to the token file or the configured interactive flow after upgrading — there is no warning when an ignored `VAULT_TOKEN` is present. Rename the variable to `DOTVAULT_TOKEN` to restore the previous behaviour.
