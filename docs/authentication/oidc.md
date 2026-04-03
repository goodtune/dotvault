# OIDC & SSO Authentication

OIDC (OpenID Connect) is the recommended authentication method for desktop users. It provides a seamless browser-based login flow that integrates with your organisation's identity provider.

## Configuration

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"
  auth_mount: "oidc"       # optional, defaults to the method name
  auth_role: "default"     # optional, Vault role to request
```

## How it works

1. dotvault requests an authentication URL from Vault's OIDC auth method
2. A browser window opens to the identity provider's login page
3. dotvault listens on a random localhost port for the OAuth callback
4. After successful login, the callback delivers an authorisation code
5. dotvault exchanges the code for a Vault token

In web UI mode, the OIDC flow is initiated from the web dashboard instead:

1. User clicks "Login with OIDC" in the web UI
2. Browser redirects to the identity provider
3. After login, the callback returns to the web UI
4. The web UI stores the session and the daemon receives the Vault token

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

3. Create a role mapping:

    ```sh
    vault write auth/oidc/role/default \
        allowed_redirect_uris="https://vault.example.com:8200/ui/vault/auth/oidc/oidc/callback" \
        allowed_redirect_uris="http://localhost:8250/oidc/callback" \
        user_claim="email" \
        policies="dotvault-user"
    ```

    !!! note
        The `allowed_redirect_uris` must include `http://localhost:8250/oidc/callback` (or the port range dotvault uses) to support the CLI-based OIDC flow. The web UI callback must also be listed if using web-based login.

For detailed Vault OIDC configuration, see the [HashiCorp OIDC Auth Method documentation](https://developer.hashicorp.com/vault/docs/auth/jwt).

## SSO experience

When wired up to an SSO provider like Okta, the authentication experience is largely transparent:

- If the user has an active SSO session, the browser briefly opens and closes — no password entry needed
- The Vault token is cached locally, so re-authentication only happens when the token expires
- Token renewal is automatic, extending the session without user interaction

This makes dotvault suitable for environments where users should not need to think about Vault authentication at all.
