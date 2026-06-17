# Authentication Overview

dotvault supports five methods for authenticating to HashiCorp Vault:

| Method | Best for | How it works |
|--------|----------|-------------|
| [OIDC](oidc.md) | Desktop users with SSO | Opens a browser for identity provider login |
| [LDAP](ldap-mfa.md) | Environments with LDAP/AD and MFA | Terminal prompt for password + optional MFA |
| [Token](token.md) | Automation, CI/CD, development | Uses a pre-existing Vault token |
| [mTLS](mtls-tpm.md) | Long-lived unattended auth | A TLS client certificate authenticates; LDAP/OIDC is a one-time bootstrap |
| [mTLS+TPM](mtls-tpm.md) | Hardware-bound unattended auth | As mTLS, but the private key is sealed in the TPM |

Set the method in your config file:

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"    # or "ldap", "token", "mtls", "mtls+tpm"
```

### TPM-sealed token (`+tpm` suffix)

Append `+tpm` to a token-minting method — `oidc+tpm`, `ldap+tpm`, or `mtls+tpm` — to seal the cached token in `~/.dotvault-token` under the machine's TPM. The login flow is otherwise unchanged; only how the token rests on disk differs. (The bare `token` method has no token of its own to seal, so `token+tpm` has no sealing effect.) See [mTLS / mTLS+TPM](mtls-tpm.md#tpm-sealed-token) for the full behaviour, including the no-plaintext-fallback contract and the requirement for a working TPM.

## Authentication flow

### CLI mode

When running without the web UI, dotvault authenticates directly:

- **OIDC** — opens a browser window and listens on a random localhost port for the callback
- **LDAP** — prompts for a password in the terminal; handles MFA challenges inline
- **Token** — reads from the `DOTVAULT_TOKEN` environment variable or `~/.dotvault-token` file

### Web UI mode

When the web UI is enabled (`web.enabled: true`), all authentication is handled through the browser-based SPA. If the daemon starts without a valid token, it opens the web UI in the user's browser where they can log in.

## Token lifecycle

After successful authentication, dotvault manages the Vault token automatically:

- **Token renewal** — the token is renewed at 75% of its remaining TTL
- **TTL monitoring** — checked every 5 minutes
- **Automatic re-auth** — if the token expires or a `403 Forbidden` is received, dotvault triggers re-authentication
- **Exponential backoff** — on renewal failure, retries with backoff from 1 second to 5 minutes

In web mode, re-authentication opens the browser to the web UI login page. In CLI mode, re-authentication uses the configured auth method directly.

## Token persistence

Vault tokens are persisted to `~/.dotvault-token` with `0600` permissions — a dotvault-specific filename rather than Vault's default `~/.vault-token`, so a concurrent `vault` CLI session cannot clobber the daemon's cached token. On restart, dotvault attempts to reuse this token before initiating a new authentication flow. The `DOTVAULT_TOKEN` environment variable takes precedence if set; the upstream `VAULT_TOKEN` variable is deliberately ignored for the same isolation reason as the filename.

When the auth method carries the `+tpm` suffix, the token file holds a TPM-sealed envelope instead of the plaintext token. The file is self-describing, so reuse-on-restart and the public `client` library unseal it transparently — no extra configuration on the reader side. The `DOTVAULT_TOKEN` environment variable is always plaintext (an environment value cannot be sealed), so the seal protects the on-disk file only.
