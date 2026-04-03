# Templates

Templates let you reshape Vault secret data before it is written to a target file. They use [Go's `text/template`](https://pkg.go.dev/text/template) syntax and receive the Vault KV data map as the dot (`.`) context.

When no template is specified, the raw Vault secret data is passed directly to the format handler.

## Template functions

In addition to the standard Go template functions, dotvault provides:

| Function | Signature | Description |
|----------|-----------|-------------|
| `env` | `env(key)` | Look up an environment variable |
| `base64encode` | `base64encode(s)` | Base64-encode a string |
| `base64decode` | `base64decode(s)` | Base64-decode a string |
| `default` | `default(fallback, val)` | Return `val` if non-empty, otherwise `fallback` |
| `quote` | `quote(s)` | Shell-safe single quoting |

The `default` function follows the [Sprig](https://masterminds.github.io/sprig/) convention where the fallback comes first, enabling idiomatic piping:

```
{{ .port | default "8080" }}
```

## Examples by format

### YAML

Sync a GitHub CLI credential into `~/.config/gh/hosts.yml`:

```yaml
rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{ .oauth_token }}"
          user: "{{ .user }}"
          git_protocol: https
```

If the user already has other entries in `hosts.yml` (e.g. for GitHub Enterprise), those entries are preserved. Only the `github.com` key is merged.

**Vault secret** (`kv/data/users/jane/gh`):

```json
{ "oauth_token": "ghp_xxxx", "user": "jane" }
```

**Result** (merged with existing file):

```yaml
github.com:
  oauth_token: "ghp_xxxx"
  user: "jane"
  git_protocol: https
github.enterprise.com:
  oauth_token: "gho_yyyy"   # preserved from existing file
```

### JSON

Sync database credentials into a JSON config file:

```yaml
rules:
  - name: db-config
    vault_key: "db"
    target:
      path: "~/.myapp/config.json"
      format: json
      template: |
        {
          "database": {
            "host": "{{ .host | default "localhost" }}",
            "port": {{ .port | default "5432" }},
            "username": "{{ .username }}",
            "password": "{{ .password }}"
          }
        }
```

**Vault secret:**

```json
{ "host": "db.internal", "port": "5432", "username": "jane", "password": "s3cret" }
```

**Result** (merged with existing file):

```json
{
  "database": {
    "host": "db.internal",
    "port": 5432,
    "username": "jane",
    "password": "s3cret"
  },
  "logging": {
    "level": "info"
  }
}
```

The `logging` section from the existing file is preserved.

### TOML

Sync credentials into a TOML configuration:

```yaml
rules:
  - name: cargo-registry
    vault_key: "cargo"
    target:
      path: "~/.cargo/credentials.toml"
      format: toml
      template: |
        [registries.my-registry]
        token = "{{ .token }}"
```

**Vault secret:**

```json
{ "token": "cargo_xxxxxxxxxxxx" }
```

**Result:**

```toml
[registries.my-registry]
token = "cargo_xxxxxxxxxxxx"

[registries.crates-io]
token = "existing_token"    # preserved from existing file
```

### INI

Sync AWS credentials into `~/.aws/credentials`:

```yaml
rules:
  - name: aws-creds
    vault_key: "aws"
    target:
      path: "~/.aws/credentials"
      format: ini
      template: |
        [default]
        aws_access_key_id = {{ .access_key }}
        aws_secret_access_key = {{ .secret_key }}
```

**Vault secret:**

```json
{ "access_key": "AKIAXXXXXXXX", "secret_key": "wJalrXxxxxxxxx" }
```

**Result** (merged with existing file):

```ini
[default]
aws_access_key_id = AKIAXXXXXXXX
aws_secret_access_key = wJalrXxxxxxxxx

[profile staging]
aws_access_key_id = AKIA_OTHER    # preserved from existing file
aws_secret_access_key = other_key
```

### Netrc

Sync machine credentials into `~/.netrc`:

```yaml
rules:
  - name: netrc
    vault_key: "netrc"
    target:
      path: "~/.netrc"
      format: netrc
      template: |
        machine github.com
          login {{ .user }}
          password {{ .oauth_token }}
```

**Vault secret:**

```json
{ "user": "jane", "oauth_token": "ghp_xxxx" }
```

**Result** (merged with existing file):

```
machine github.com
  login jane
  password ghp_xxxx

machine gitlab.com
  login jane
  password glpat-yyyy
```

Entries are merged by machine name. The existing `gitlab.com` entry is preserved.

### Text (plain)

Sync a private key or certificate:

```yaml
rules:
  - name: ssh-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519"
      format: text
      template: "{{ .private_key }}"
```

**Vault secret:**

```json
{ "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn..." }
```

Text format uses full replacement — the entire file content is overwritten. This is appropriate for opaque blobs like private keys and certificates where merging is not meaningful.

## Templates without the template field

If no `template` is specified, dotvault passes the raw Vault KV data map to the format handler. For YAML and JSON, this means all fields from the Vault secret are written to the file:

```yaml
rules:
  - name: app-secrets
    vault_key: "myapp"
    target:
      path: "~/.myapp/secrets.yaml"
      format: yaml
```

If the Vault secret at `kv/data/users/jane/myapp` contains `{"api_key": "xxx", "db_pass": "yyy"}`, the resulting file would have both fields merged into it.

## Tips

- Use `default` to provide fallback values for optional fields
- Use `base64encode` for credentials that need to be base64-encoded in the target format (e.g. Kubernetes secrets)
- Use `quote` when embedding values in shell scripts or contexts where quoting matters
- Use `env` sparingly — it reads from the dotvault process environment, not the user's shell
