# Vault KV Engine & Policies

dotvault stores per-user secrets in a KVv2 secrets engine under a user prefix. This page describes how to set up the KV namespace and write a template policy so each user can only access their own secrets.

## KV namespace layout

The default layout uses the `kv` mount with a `users/` prefix:

```
kv/
  data/
    users/
      jane/
        gh          ← GitHub credentials
        ssh         ← SSH private key
        aws         ← AWS credentials
      bob/
        gh
        ssh
```

Each user has their own subtree under `users/{username}/`. The username is determined by the auth method — for OIDC it typically comes from the `email` or `preferred_username` claim; for LDAP it's the login name.

## Enable the KVv2 secrets engine

If not already enabled:

```sh
vault secrets enable -version=2 -path=kv kv
```

## Template policy

Vault's [template policies](https://developer.hashicorp.com/vault/docs/concepts/policies#templated-policies) let you write a single policy that dynamically scopes access to the authenticated user's identity. This avoids creating per-user policies.

Create a file `dotvault-user.hcl`:

```hcl
# Allow users to manage their own secrets under the user prefix.
# The {{identity.entity.aliases.<MOUNT_ACCESSOR>.name}} template
# resolves to the authenticated username.

# List the user's own secret keys
path "kv/metadata/users/{{identity.entity.aliases.<MOUNT_ACCESSOR>.name}}/*" {
  capabilities = ["list", "read"]
}

# Read and write the user's own secrets
path "kv/data/users/{{identity.entity.aliases.<MOUNT_ACCESSOR>.name}}/*" {
  capabilities = ["create", "update", "read"]
}

# Allow deleting the user's own secrets
path "kv/delete/users/{{identity.entity.aliases.<MOUNT_ACCESSOR>.name}}/*" {
  capabilities = ["update"]
}
```

!!! important "Replace the mount accessor"
    The `<MOUNT_ACCESSOR>` placeholder must be replaced with the actual accessor for your auth method. Find it with:

    ```sh
    vault auth list -format=json | jq -r '."oidc/".accessor'
    ```

    For example, if the accessor is `auth_oidc_12345678`, the path becomes:
    ```
    kv/data/users/{{identity.entity.aliases.auth_oidc_12345678.name}}/*
    ```

Apply the policy:

```sh
vault policy write dotvault-user dotvault-user.hcl
```

Then attach it to the auth method role:

```sh
# For OIDC
vault write auth/oidc/role/default \
    token_policies="dotvault-user" \
    ...

# For LDAP (via group mapping)
vault write auth/ldap/groups/developers \
    policies="dotvault-user"
```

## Seeding secrets

Administrators or users can pre-populate secrets using the Vault CLI:

```sh
vault kv put kv/users/jane/gh oauth_token="ghp_xxxxxxxxxxxx" user="jane"
vault kv put kv/users/jane/ssh private_key=@~/.ssh/id_ed25519
```

Or through the Vault UI, if available.

dotvault's [service onboarding](../services/overview.md) feature can also automate this — for example, running a GitHub OAuth device flow to obtain a token and writing it to Vault automatically.

## Customising the namespace

The KV mount and user prefix are configurable:

```yaml
vault:
  kv_mount: "secrets"          # use a different mount
  user_prefix: "personal/"     # use a different prefix
```

With these settings, secrets are read from `secrets/data/personal/{username}/{vault_key}`.

!!! note
    The `user_prefix` must end with a trailing slash. dotvault enforces this — if you omit the slash, it is appended automatically.

## Further reading

- [HashiCorp Vault KVv2 documentation](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2)
- [Vault Policies](https://developer.hashicorp.com/vault/docs/concepts/policies)
- [Templated Policies tutorial](https://developer.hashicorp.com/vault/tutorials/policies/policy-templating)
- [Identity Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/identity)
