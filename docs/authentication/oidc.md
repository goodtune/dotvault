# OIDC & SSO Authentication

OIDC (OpenID Connect) is the recommended authentication method for desktop users. It provides a seamless browser-based login flow that integrates with your organisation's identity provider.

## Configuration

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"
  auth_mount: "oidc"       # optional, defaults to the method name
  auth_role: "default"     # optional, Vault role to request
  oidc_callback_port: 8250 # optional, defaults to 8250 (see "Redirect URIs" below)
```

!!! tip "Seal the cached token under the TPM"
    Use `auth_method: "oidc+tpm"` to seal the cached Vault token at rest under the machine's TPM. The OIDC login flow is unchanged — only how the token rests on disk differs. See [TPM-Backed Protection](tpm.md).

## How it works

1. dotvault requests an authentication URL from Vault's OIDC auth method, passing a `redirect_uri` that points at a local HTTP listener
2. A browser window opens to the identity provider's login page
3. dotvault listens on `127.0.0.1:8250` (or `oidc_callback_port`, see below) for the OAuth callback
4. After successful login, the callback delivers an authorisation code
5. dotvault exchanges the code for a Vault token

In web UI mode, the OIDC flow is initiated from the web dashboard instead:

1. User clicks "Login with OIDC" in the web UI
2. Browser redirects to the identity provider
3. After login, the callback returns to the web UI
4. The web UI stores the session and the daemon receives the Vault token

## Redirect URIs

Vault's OIDC auth method forwards the `redirect_uri` dotvault supplies straight through to the identity provider's authorization request, so the callback lands directly on dotvault (or the browser) rather than being proxied back through Vault. Both Vault's `allowed_redirect_uris` on the role **and** the identity provider must therefore allow-list the exact URI dotvault is going to use — there are two distinct URIs depending on how dotvault is running:

| Flow | Redirect URI | Notes |
|------|---------------|-------|
| `dotvault login` / CLI (`oidc`, `oidc+tpm`) | `http://127.0.0.1:<oidc_callback_port>/oidc/callback` | Port defaults to **8250** — the same default the `vault` CLI itself uses (`vault login -method=oidc`), so a role/IdP already configured for the `vault` CLI typically works for dotvault unchanged. Configurable via `vault.oidc_callback_port`. |
| Daemon web UI | `http://<web.listen>/auth/oidc/callback` | Fixed at the configured `web.listen` address (e.g. `127.0.0.1:9000/auth/oidc/callback`); not affected by `oidc_callback_port`. |

Vault's own redirect matcher (`vault-plugin-auth-jwt`) ignores only the **port** on a loopback host — scheme, host, and path must match exactly, and it treats `127.0.0.1` and `localhost` as different hosts. Not every identity provider implements the same RFC 8252 loopback leniency (some validate the redirect URI, including the port, exactly), which is why dotvault binds a **fixed** port by default rather than a random one: it lets you register one predictable URI with both Vault and the IdP instead of guessing at a port range. If the configured (or default) port is already bound by another process (e.g. a concurrent login, or the `vault` CLI itself mid-flow), dotvault falls back to an OS-assigned random port and logs why — that fallback only works end-to-end against an IdP/Vault role that does implement port-agnostic matching. Any other bind failure (for example, a privileged port below 1024 on Linux/macOS without the capability to bind one, or a firewall/policy block) is a hard login error rather than a silent fallback, since that kind of failure won't clear itself on the next login — pick a port `>= 1024` unless dotvault runs with the privilege to bind lower ones.

If Vault returns a 200 response to the `auth_url` request but the response carries no `auth_url` field, this almost always means the `redirect_uri` dotvault sent was rejected — Vault fails this way (success status, empty body) rather than returning an error. dotvault's error message names the exact `redirect_uri` it sent plus the auth mount and role, so check that value against `allowed_redirect_uris` on the role and against the redirect URIs registered with the identity provider.

## Identity providers

Vault's OIDC auth method works with any OpenID Connect-compliant identity provider. Common choices include:

- **Okta** — widely used enterprise SSO; provides a seamless experience when users are already signed in
- **Azure AD / Entra ID** — native integration for Microsoft environments
- **Google Workspace** — for organisations using Google as their identity provider
- **Dex** — open-source OIDC connector that can federate multiple upstream identity providers
- **Keycloak** — open-source identity and access management

### Vault-side OIDC setup

The OIDC auth method must be configured in Vault. The key steps are:

1. Enable the OIDC auth method:

    ```sh
    vault auth enable oidc
    ```

2. Configure the OIDC provider:

    ```sh
    vault write auth/oidc/config \
        oidc_discovery_url="https://login.example.com" \
        oidc_client_id="vault-app-id" \
        oidc_client_secret="vault-app-secret" \
        default_role="default"
    ```

3. Create a role mapping. List every redirect URI a client of this role will use — dotvault's CLI flow, dotvault's own web UI (if enabled), and Vault's own web UI login (if used) each need a separate entry:

    ```sh
    vault write auth/oidc/role/default \
        allowed_redirect_uris="http://127.0.0.1:8250/oidc/callback" \
        allowed_redirect_uris="http://127.0.0.1:9000/auth/oidc/callback" \
        allowed_redirect_uris="https://vault.example.com:8200/ui/vault/auth/oidc/oidc/callback" \
        user_claim="email" \
        policies="dotvault-user"
    ```

    !!! note
        `http://127.0.0.1:8250/oidc/callback` is dotvault's CLI flow (`dotvault login`) — see the "Redirect URIs" table above; use `127.0.0.1`, not `localhost` (Vault treats them as different hosts and ignores only the port, not the host). `http://127.0.0.1:9000/auth/oidc/callback` is dotvault's own web UI, present only if `web.enabled` and adjusted to match `web.listen`. `.../ui/vault/auth/oidc/oidc/callback` is unrelated to dotvault — it's Vault's own browser-based UI login — and is only needed if operators also log in to the Vault UI directly.

    Register the same URIs with the identity provider (Okta, Azure AD, etc.) — Vault forwards the `redirect_uri` straight through, so the IdP validates it independently and may not tolerate a mismatched port the way Vault does.

For detailed Vault OIDC configuration, see the [HashiCorp OIDC Auth Method documentation](https://developer.hashicorp.com/vault/docs/auth/jwt).

## SSO experience

When wired up to an SSO provider like Okta, the authentication experience is largely transparent:

- If the user has an active SSO session, the browser briefly opens and closes — no password entry needed
- The Vault token is cached locally, so re-authentication only happens when the token expires
- Token renewal is automatic, extending the session without user interaction

This makes dotvault suitable for environments where users should not need to think about Vault authentication at all.
