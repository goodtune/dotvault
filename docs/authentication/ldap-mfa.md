# LDAP Authentication & MFA

LDAP authentication is suited to environments where users authenticate against Active Directory or another LDAP directory, optionally with multi-factor authentication.

## Configuration

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "ldap"
  auth_mount: "ldap"       # optional, defaults to the method name
```

## How it works

### CLI mode

1. dotvault prompts for a password in the terminal (using secure input that doesn't echo characters)
2. The credentials are submitted to Vault's LDAP auth method
3. If MFA is required, dotvault handles the challenge (see below)
4. On success, a Vault token is issued

### Web UI mode

1. User enters their username and password in the web UI login form
2. The web UI submits credentials to the dotvault API
3. MFA challenges are presented in the browser
4. On success, the daemon receives the Vault token

## Multi-factor authentication

dotvault supports MFA via Vault's identity-based MFA system. Two MFA types are supported:

### Duo Push

When Duo MFA is configured, Vault sends a push notification to the user's registered Duo device. dotvault polls for the result automatically.

In CLI mode, you'll see:

```
Password:
MFA required — waiting for Duo push approval...
✓ Authenticated
```

### TOTP

For TOTP-based MFA (e.g. Google Authenticator, Authy), dotvault prompts for the one-time passcode:

In CLI mode:

```
Password:
MFA required — enter TOTP code: 123456
✓ Authenticated
```

In web UI mode, a TOTP input field appears in the browser.

## Login state machine

The LDAP login flow is managed by an asynchronous state machine (the LoginTracker) that transitions through the following states:

```
pending → mfa_required → authenticated
                       → failed
```

This allows the web UI to poll for status updates while the MFA flow completes. In CLI mode, the same state machine is used but polled at 500ms intervals internally.

## Vault-side LDAP setup

The LDAP auth method must be configured in Vault:

1. Enable the LDAP auth method:

    ```sh
    vault auth enable ldap
    ```

2. Configure the LDAP connection:

    ```sh
    vault write auth/ldap/config \
        url="ldaps://ldap.example.com" \
        userdn="ou=Users,dc=example,dc=com" \
        userattr="sAMAccountName" \
        groupdn="ou=Groups,dc=example,dc=com" \
        groupattr="cn" \
        insecure_tls=false \
        certificate=@/path/to/ldap-ca.pem
    ```

3. Map LDAP groups to Vault policies:

    ```sh
    vault write auth/ldap/groups/developers policies="dotvault-user"
    ```

For detailed Vault LDAP configuration, see the [HashiCorp LDAP Auth Method documentation](https://developer.hashicorp.com/vault/docs/auth/ldap).
