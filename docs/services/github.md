# GitHub CLI Onboarding

The `github` enrolment engine automates GitHub OAuth token acquisition using the [device authorisation flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow). This is the same flow used by the `gh auth login` command.

## Configuration

### Minimal

```yaml
enrolments:
  gh:
    engine: github

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

### With custom settings

```yaml
enrolments:
  gh:
    engine: github
    settings:
      client_id: "your-oauth-app-client-id"    # default: GitHub CLI's OAuth app
      host: "github.example.com"                # default: github.com
      scopes:                                    # default: repo, read:org, gist
        - repo
        - read:org
        - gist
        - workflow
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `client_id` | `178c6fc778ccc68e1d6a` (GitHub CLI's app) | OAuth application client ID |
| `host` | `github.com` | GitHub host (for GitHub Enterprise Server) |
| `scopes` | `repo`, `read:org`, `gist` | OAuth scopes to request |

## How the device flow works

1. dotvault requests a device code from GitHub
2. A one-time user code is displayed (and copied to clipboard if possible)
3. The user opens `https://github.com/login/device` in their browser
4. The user enters the code and authorises the application
5. dotvault polls GitHub until the authorisation completes
6. The resulting OAuth token and username are written to Vault

### Terminal output

```
! First, copy your one-time code: ABCD-1234
- Press Enter to open https://github.com/login/device in your browser...
✓ Opened https://github.com/login/device in browser
⠼ Waiting for authentication...
✓ Authentication complete!
```

## Credentials stored in Vault

The engine writes these fields to the Vault KV secret:

| Field | Description |
|-------|-------------|
| `oauth_token` | The GitHub OAuth access token |
| `user` | The authenticated GitHub username |

## GitHub Enterprise Server

For GitHub Enterprise Server, set the `host` in settings:

```yaml
enrolments:
  gh-enterprise:
    engine: github
    settings:
      host: "github.example.com"
      client_id: "your-ghe-oauth-app-id"

rules:
  - name: gh-enterprise
    vault_key: "gh-enterprise"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.example.com:
          oauth_token: "{{ .oauth_token }}"
          user: "{{ .user }}"
          git_protocol: https
```

You can have both `github.com` and GitHub Enterprise entries — the YAML merge strategy preserves both host entries in the `hosts.yml` file.

## Combining enrolment with sync

A typical setup pairs the enrolment with a sync rule so the workflow is:

1. User starts dotvault for the first time
2. dotvault checks Vault for `users/{username}/gh` — it's empty
3. The enrolment wizard runs the GitHub device flow
4. Credentials are written to Vault
5. The sync rule picks up the new secret and writes `~/.config/gh/hosts.yml`
6. `gh` CLI now works without manual `gh auth login`

On subsequent starts, the enrolment check finds the credentials already present and skips the flow.
