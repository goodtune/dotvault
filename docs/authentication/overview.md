# Authentication Overview

dotvault supports three methods for authenticating to HashiCorp Vault:

| Method | Best for | How it works |
|--------|----------|-------------|
| [OIDC](oidc.md) | Desktop users with SSO | Opens a browser for identity provider login |
| [LDAP](ldap-mfa.md) | Environments with LDAP/AD and MFA | Terminal prompt for password + optional MFA |
| [Token](token.md) | Automation, CI/CD, development | Uses a pre-existing Vault token |

Set the method in your config file:

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"    # or "ldap" or "token"
```

## Authentication flow

### CLI mode

When running without the web UI, dotvault authenticates directly:

- **OIDC** — opens a browser window and listens on a random localhost port for the callback
- **LDAP** — prompts for a password in the terminal; handles MFA challenges inline
- **Token** — reads from the `VAULT_TOKEN` environment variable or `~/.vault-token` file

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

Vault tokens are persisted to `~/.vault-token` with `0600` permissions. On restart, dotvault attempts to reuse this token before initiating a new authentication flow. The `VAULT_TOKEN` environment variable takes precedence if set.
