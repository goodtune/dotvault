# Configuration Reference

dotvault uses a YAML configuration file. The file location depends on your platform:

| Platform | Path |
|----------|------|
| Linux    | `/etc/xdg/dotvault/config.yaml` (also checks `$XDG_CONFIG_DIRS`) |
| macOS    | `/Library/Application Support/dotvault/config.yaml` |
| Windows  | `%ProgramData%\dotvault\config.yaml` |

You can override the config path with `--config`:

```sh
dotvault run --config /path/to/config.yaml
```

!!! warning "`--config` is gated by the system-wide configuration"
    `--config` is honoured only when there is **no system-wide configuration**, or the system-wide configuration explicitly opts in with `bypass_system_config: true`. If a system config is present and does not set the flag, dotvault refuses the override and exits with an error rather than silently loading the command-line file. This is identical on every platform; the "system-wide configuration" is the Windows Group Policy registry policy when present, otherwise the system YAML file. See [`bypass_system_config`](#bypass_system_config) below.

!!! warning "Windows Group Policy"
    On Windows, if Group Policy registry keys exist at `HKLM\SOFTWARE\Policies\goodtune\dotvault`, dotvault loads all configuration from the registry and **ignores the YAML file entirely**. Pointing dotvault at a different file with `--config` requires `bypass_system_config: true` in that policy (the registry equivalent is a `BypassSystemConfig` REG_DWORD of `1` directly under the policy key). See [Windows Group Policy](../admin/windows-gpo.md) for details.

## Full example

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"
  auth_role: "default"
  auth_mount: "oidc"
  oidc_callback_port: 8250
  kv_mount: "kv"
  user_prefix: "users/"
  ca_cert: "/etc/ssl/certs/internal-ca.pem"
  tls_skip_verify: false

sync:
  interval: "15m"

web:
  enabled: true
  listen: "127.0.0.1:9000"
  login_text: |
    Welcome to dotvault. Click **Login** to authenticate via SSO.
  secret_view_text: |
    These secrets are synchronised from Vault to your local machine.

api:
  enabled: true
  unix:
    path: ""    # default: $XDG_RUNTIME_DIR/dotvault/api.sock

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{ .oauth_token }}"

  - name: ssh-key
    vault_key: "ssh"
    target:
      path: "~/.ssh/id_ed25519"
      format: text

  - name: netrc
    vault_key: "netrc"
    target:
      path: "~/.netrc"
      format: netrc

enrolments:
  gh:
    engine: github
    settings:
      scopes:
        - repo
        - read:org
        - gist
```

## Top-level options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bypass_system_config` | bool | `false` | Permit the `--config` command-line override on this machine (see below) |

### `bypass_system_config`

By default, when a system-wide configuration is present, the `--config` command-line flag is **refused** — a managed deployment (a Windows Group Policy registry policy, or a system config file shipped by configuration management) cannot be sidestepped from the command line. Setting `bypass_system_config: true` in the **system-wide** config re-enables the override on that machine.

The intended workflow: an administrator normally pins the system config, but flips this flag when they need to trial a hand-edited config without un-deploying the policy. It only has an effect when set in the authoritative system config — setting it inside a file passed to `--config` is meaningless, because that file is only loaded once the override has already been allowed.

The behaviour is identical on every platform. On Windows GPO the equivalent registry value is a `BypassSystemConfig` REG_DWORD of `1` directly under `HKLM\SOFTWARE\Policies\goodtune\dotvault`.

## Vault section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | string | *(required)* | Vault server URL |
| `auth_method` | string | — | Authentication method: `oidc`, `ldap`, `token`, `mtls`, or `mtls+tpm` (any base method also accepts a `+tpm` suffix) |
| `auth_mount` | string | — | Vault auth mount path (e.g. `oidc`, `ldap`) |
| `auth_role` | string | — | Vault auth role to request |
| `oidc_callback_port` | int | `8250` | Fixed local TCP port the OIDC CLI flow (`dotvault login`) binds for the OAuth redirect_uri; falls back to a random port if unavailable. See [OIDC & SSO Authentication](../authentication/oidc.md#redirect-uris) |
| `policies` | list | — | Least-privilege policy set the working token should carry (see below) |
| `no_default_policy` | bool | `false` | Strip the implicit `default` policy from the working token (see below) |
| `kv_mount` | string | `kv` | KVv2 secrets engine mount path |
| `user_prefix` | string | `users/` | Prefix for per-user secret paths (trailing slash enforced) |
| `ca_cert` | string | — | Path to CA certificate for TLS verification |
| `tls_skip_verify` | bool | `false` | Skip TLS certificate verification (development only) |
| `disable_token_renewal` | bool | `false` | Never call `RenewSelf`; TTL expiry still triggers re-auth |
| `token_socket` | string | — | Optional path to a peer dotvault's web-API Unix socket to borrow a token from (see below) |

Secret paths are constructed as: `{kv_mount}/data/{user_prefix}{username}/{vault_key}`

### `policies` / `no_default_policy` — least-privilege tokens

By default dotvault runs with whatever policies its auth role (OIDC/LDAP/cert) grants the user. For a human that is often the union of everything that user can do in Vault — far more than dotvault needs to mirror a handful of secrets. A token that is cached on disk (`~/.dotvault-token`) is a standing credential; over-provisioning it widens the blast radius if the file ever leaks.

Set `policies` to the minimal set dotvault actually needs (typically a read-only policy over the user's KV prefix). When it is non-empty, dotvault does **not** use the login token directly: immediately after authenticating it exchanges that token for a **child token restricted to exactly those policies** and runs with — and persists — the child. Vault enforces that the requested set is a subset of the login token's own policies, so this can only ever *drop* privilege, never escalate it. The narrowing applies identically on every auth path (CLI OIDC/LDAP/mTLS and the web UI). The `token` auth method is exempt — there you supply the token and own its scope.

`no_default_policy: true` additionally strips Vault's implicit `default` policy from the working token. Combine the two to pin the token to precisely the capabilities dotvault uses.

```yaml
vault:
  address: "https://vault.example.com:8200"
  auth_method: "oidc"
  policies:
    - dotvault-sync   # a read-only policy over kv/data/users/<you>/*
  no_default_policy: true
```

This is a **per-deployment** concern — dotvault ships no default policy list, because the right policy name(s) depend entirely on your Vault policy layout. The downscoped child token is renewable and managed by the normal token lifecycle; when it expires dotvault re-authenticates and re-narrows.

!!! note "Staged rollout toward 1.0"
    Today `no_default_policy` defaults to `false` and an unset `policies` keeps the historical "carry every granted policy" behaviour — so existing installs are unaffected. dotvault logs a one-line warning at each fresh login when no restriction is configured, nudging operators to opt in. A future release will flip the `no_default_policy` default to `true`, and the 1.0 release will remove the ability to run with the `default` policy attached at all. dotvault is pre-1.0, so this deliberately-breaking transition runs over a few releases; configure `policies` now to be ready. On Windows GPO the equivalents are a `Policies` REG_MULTI_SZ and a `NoDefaultPolicy` REG_DWORD under `HKLM\SOFTWARE\Policies\goodtune\dotvault\Vault`.

### `token_socket` — dotvault-to-dotvault token sharing

When `token_socket` points at a Unix-domain socket served by another dotvault daemon's web API, dotvault tries to **borrow a live Vault token from that peer** before falling back to its own authentication. The borrow is attempted everywhere dotvault would otherwise authenticate interactively or block waiting for a token: on a **fresh login** (`dotvault login`, or daemon/CLI startup when no cached token is usable — a still-valid cached token short-circuits first and never reaches the borrow); during **headless daemon startup**, where a daemon with no web UI and no terminal borrows directly instead of idling until a token file is written; and on the lifecycle manager's **recovery path** after a cached token has gone invalid. A healthy token that is merely being renewed at 75% TTL (`RenewSelf`) does **not** trigger a borrow. It is the programmatic equivalent of:

```sh
curl --unix-socket ~/.ssh/dotvault.sock http://localhost/api/v1/token
```

The intended deployment: a workstation (e.g. Windows) runs dotvault with the [web UI](#web-section) enabled and authenticates interactively. You then SSH **from the workstation to** a second machine (e.g. a Linux dev box or server), and the SSH `RemoteForward` exposes the workstation daemon's loopback HTTP listener as a Unix socket **created on the remote (devbox) side**:

```
# ~/.ssh/config on the workstation, where `ssh devbox` runs
Host devbox
    # Creates /home/me/.ssh/dotvault.sock ON devbox, forwarding to the
    # workstation's web UI at 127.0.0.1:9000.
    RemoteForward /home/me/.ssh/dotvault.sock 127.0.0.1:9000
```

The remote dotvault then sets `token_socket: ~/.ssh/dotvault.sock` and borrows the workstation's token instead of needing its own browser or TTY to authenticate. Because the socket *listener* lives on the borrowing host, this side should be Linux or macOS, where `AF_UNIX` is fully supported; the workstation only needs the loopback TCP web UI.

On Linux the daemon also **watches the socket** (inotify) and re-borrows as soon as it materialises or is replaced — so an SSH `RemoteForward` that connects after the daemon started, or drops and reconnects, is picked up within moments rather than only on the next periodic check.

!!! tip "This socket dies with the SSH session"
    Everything above depends on the SSH connection being up. A process that outlives the session it was started in — a `tmux` job, a long-running service — will fail its next borrow once the forward is gone. Enable the [`api` section](#api-section) on the remote host so the long-lived daemon serves the borrow endpoint from a stable path, and local clients keep working across disconnects.

One behaviour change for existing deployments: a peer's `/api/v1/token` now returns 401 once that peer's daemon knows its own token has gone invalid and is awaiting re-authentication, instead of handing out a credential it knows is dead. Borrowers already validate what they receive, so this only removes a known-bad answer earlier.

The borrow is **best-effort and never fatal**: if the socket path is empty, the socket file is missing, the socket is stale (left over from a dead SSH session, no listener), the peer is reachable but holds no token, or the response is malformed, dotvault silently carries on with its normal auth flow. A leading `~` is expanded to the user's home directory. The borrowed token is held in memory only — it is not written to the local token file, so the peer remains the single owner and the remote re-borrows on its next login or recovery rather than caching a copy that could go stale.

The same borrow is available to the **dotvault client libraries** (Go `client/` and the Python bindings): their cached-auth entry point (`AuthenticateCached`) borrows from the configured peer socket after the `DOTVAULT_TOKEN` env var and token file come up empty, before reporting that a login is required. Because it is a plain socket read with no browser or prompt, a Go or Python program on a host with no local token but a live peer socket reads secrets without an interactive login of its own.

The socket carries traffic the other way too. [`dotvault browse <url>`](../cli.md#dotvault-browse) posts a URL to the peer's `POST /api/v1/remote/browse` endpoint so the browser opens on the workstation — the machine that actually has one — falling back to the local browser when the peer is unreachable. Set `BROWSER="dotvault browse"` on the headless host and OAuth login pages launched there land in the workstation's browser. [`dotvault notify <level> <title> [description]`](../cli.md#dotvault-notify) is the same shape for desktop notifications (`POST /api/v1/remote/notify`), so a long-running job on the headless box can raise a toast/notification on the workstation where a human is looking. [`dotvault clipboard [text]`](../cli.md#dotvault-clipboard) completes the set (`POST /api/v1/remote/clipboard`): it puts a value — a one-time token, a device code — on the workstation's clipboard, so after `browse` opens a login page the user's paste is already loaded with what the page asks for.

`dotvault status` reflects the borrow too. When no local token is present but the configured peer socket holds one, the auth line reports `authenticated` and adds a `source: borrowed from peer socket (<path>)` line, so a host that authenticates purely by borrowing — with no token file at rest — no longer misreports as `not authenticated`. If the socket is configured but the peer holds no token, status says so explicitly and prints the socket path rather than the bare `no token` message.

!!! warning "The socket grants the token to anyone who can connect"
    Any local process or user that can `connect()` to the forwarded socket can read the Vault token from it — and, via `POST /api/v1/remote/browse`, `POST /api/v1/remote/notify`, and `POST /api/v1/remote/clipboard`, open arbitrary web pages (including phishing pages) in the workstation's browser, raise arbitrary desktop notifications on it, and replace the workstation's clipboard contents (a paste-hijacking primitive — e.g. swapping a copied wallet address or command). dotvault does **not** create the socket and cannot enforce its permissions — that is the SSH `RemoteForward`'s responsibility (it creates the socket owned by, and typically readable only by, the SSH user). Only enable `token_socket` on hosts whose other local users you trust, and rely on the remote host's filesystem permissions on the socket path.

For example, with defaults and username `jane`, the rule `vault_key: "gh"` reads from `kv/data/users/jane/gh`.

## Sync section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interval` | string | `15m` | Polling interval as a Go duration (e.g. `5m`, `1h`, `30s`) |

On Enterprise Vault, dotvault also subscribes to the Events API via WebSocket for near-instant sync on secret changes. The polling interval serves as a fallback.

## Web section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the local web UI |
| `listen` | string | — | Listen address (must be loopback, e.g. `127.0.0.1:9000`) |
| `login_text` | string | — | Markdown text displayed on the login page |
| `secret_view_text` | string | — | Markdown text displayed on the secret view page |

!!! danger "Loopback only"
    The `listen` address **must** resolve to a loopback address (`127.0.0.1`, `[::1]`, or `localhost`). dotvault will refuse to start if a non-loopback address is configured. This is a hard security invariant.

## API section

The `api` section serves dotvault's web API over a per-user **Unix domain socket**, in addition to (or instead of) the loopback TCP listener the [web section](#web-section) controls.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Serve the API over a Unix socket |
| `unix.path` | string | `$XDG_RUNTIME_DIR/dotvault/api.sock` | Socket path; must be absolute (or `~`-relative). Falls back to the cache directory when `XDG_RUNTIME_DIR` is unset (typical on macOS) |

```yaml
api:
  enabled: true
  unix:
    path: ""    # default: $XDG_RUNTIME_DIR/dotvault/api.sock
```

### Why it exists: surviving a dropped SSH session

[`vault.token_socket`](#token_socket-dotvault-to-dotvault-token-sharing) lets a headless host borrow a token from a workstation over an SSH `RemoteForward`. That socket **dies with the SSH session**. A process started inside that session but outliving it — a job in `tmux`, a long-running service — succeeds at first and then fails the moment it next needs a token, because the only socket it knew about is gone.

Enabling `api` fixes that by putting a second, stable dotvault on the near side of the problem. The long-lived per-user daemon serves the same borrow endpoint from a path that no disconnect can take away, keeps its own token alive, and re-borrows across the forwarded socket whenever the SSH session comes back. Local clients borrow from the daemon instead of from the forward:

```
workstation (interactive login)
   │  SSH RemoteForward → ~/.ssh/dotvault.sock   ← comes and goes with the session
   ▼
devbox: dotvault daemon (vault.token_socket + api.enabled)
   │  $XDG_RUNTIME_DIR/dotvault/api.sock          ← always there while the daemon runs
   ▼
devbox: your tmux job, scripts, Python bindings
```

Configuration on the devbox is both settings together — borrow from the workstation, serve to everything local:

```yaml
vault:
  token_socket: ~/.ssh/dotvault.sock   # borrow from the workstation
api:
  enabled: true                        # serve the borrow endpoint locally
```

Clients on that host need no extra configuration: they read the same config and derive the same socket path.

### Borrow order

When both are configured, a token borrow tries the **local API socket first**, then `vault.token_socket`. The local socket is preferred because it is the more stable of the two, which is the entire point. This ordering applies to the daemon, the CLI, the Go `client/` facade and the Python bindings alike. The daemon excludes its *own* socket from its list — it serves that one.

The [peer actions](../cli.md#dotvault-browse) (`browse`, `notify`, `clipboard`) deliberately keep using `vault.token_socket` **only**. Their purpose is to reach the workstation where a human is looking; sending them to the local daemon would open a browser on the headless host nobody is sitting at.

### Separate from `web.enabled`

The two surfaces are enabled independently because they have different audiences and different exposure. The TCP listener serves a browser UI and is reachable by **every user on the machine**; the Unix socket is created `0600` inside a `0700` directory and is reachable only by its owner. A headless host should not have to stand up a web UI to get the borrow endpoint, and turning the socket on does not widen anything `web.enabled` already exposes — if anything it is the tighter of the two.

With `web.enabled: false`, the socket serves the API routes (`/api/v1/token`, `/api/v1/status`, `/healthz`, `/readyz`, the peer actions, …) but **not** the browser-facing routes. The SPA and the interactive login flows build redirect URIs from a bound TCP address that does not exist in that mode, so they are not registered at all rather than being published as a login flow that cannot complete.

### systemd socket activation

On Linux, the packaged `dotvault-api.socket` unit (optional, not enabled by default) lets **systemd bind this socket and hold the fd across daemon restarts**, so borrowers queue instead of getting connection-refused while the daemon is down. `api.enabled` remains the master switch — the socket unit decides who binds, not whether the surface exists — and under activation the unit's `ListenStream=` path wins over `unix.path`, with the daemon logging any divergence and refusing an inherited socket whose mode is wider than `0600`. See [Socket activation](../admin/deployment.md#socket-activation-optional) in the deployment guide.

### Running as a service

The socket lives in `$XDG_RUNTIME_DIR`, which systemd tears down when the user's last session ends — **unless lingering is enabled**:

```sh
loginctl enable-linger $USER
```

This is required for any user service meant to outlive an SSH session, which is exactly the case here. The packaged `dotvault.service` also declares `RuntimeDirectory=dotvault`, so systemd creates `$XDG_RUNTIME_DIR/dotvault` at `0700` before the daemon starts and removes it on stop — a killed daemon leaves no stale socket behind.

`dotvault status` reports the socket path and whether it is currently present, which is the first thing to check when a client on the host cannot get a token.

!!! warning "The socket grants the token to anyone who can open it"
    Any process that can `connect()` to the socket can read the Vault token. The `0600`/`0700` permissions restrict that to the owning user, and dotvault enforces them on every bind (refusing to clobber a socket a live instance already owns). Do not relax them, and do not forward this socket onward unless you intend the far end to hold your token.

!!! note "Unix only"
    `api.enabled` has no effect on Windows: the daemon logs a warning and serves nothing, so a config shared across a mixed-platform fleet is safe. The Windows analogue would be a named pipe with a protected DACL, as the [SSH agent](../guide/ssh-agent.md) already serves; it is not implemented yet.

On Windows GPO, the equivalents are `Enabled` (REG_DWORD) and `UnixPath` (REG_SZ) under `HKLM\SOFTWARE\Policies\goodtune\dotvault\API`, and the section round-trips through `reg-import`/`reg-export` like every other.

## Observability section

Exports OpenTelemetry **metrics and logs** over OTLP. Each signal is configured in its own nested `metrics:` / `logs:` block, so the two signals can go to separate backends or one can be switched off. See [Observability](../admin/deployment.md#observability) in the deployment guide for the exported instruments and worked examples.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for both signals. A per-signal `enabled: true` cannot resurrect a disabled subsystem |
| `endpoint` | string | — | **Deprecated** shared default (see note below). OTLP collector endpoint; same value contract as the per-signal `endpoint` |
| `protocol` | string | — | **Deprecated** shared default. `grpc` or `http/protobuf`. Empty falls through to the standard `OTEL_EXPORTER_OTLP_*` env vars |
| `insecure` | bool | `false` | **Deprecated** shared default. Disable transport TLS |
| `headers` | map | — | **Deprecated** shared default. OTLP headers, typically a vendor bearer token — treat as a credential |
| `export_interval` | string | SDK default | Metric export cadence as a Go duration (e.g. `30s`). Not deprecated |
| `metrics` / `logs` | block | — | Per-signal configuration, fields below — the supported home for exporter settings |

!!! warning "Shared exporter fields are deprecated"
    The top-level `endpoint` / `protocol` / `insecure` / `headers` fields still work as shared defaults the per-signal blocks layer onto, but they are being retired in stages ([#140](https://github.com/goodtune/dotvault/issues/140)): this release warns at startup and counts each use on the `dotvault.config.deprecated` metric (attribute `field`), a later release makes the warning louder, and 1.0 removes them. Configure each signal in its own block, or use the standard `OTEL_EXPORTER_OTLP_*` environment variables for values shared across both signals — the env-var fallthrough remains fully supported.

Per-signal override block (`metrics:` / `logs:`):

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | inherit | Tri-state: unset inherits the master switch, explicit `false` turns this signal off |
| `endpoint` | string | inherit | Non-empty overrides the shared endpoint (separate backend). A **full URL is the recommended form**: the scheme carries TLS intent (`https` → TLS, `http` → plaintext, on both protocols) and an explicit path is used verbatim — no mount path assumed; a path-less URL gets the standard `/v1/metrics` / `/v1/logs` appended (http/protobuf). Bare `host:port` (canonical gRPC) leaves TLS to `insecure`; `dns:///` passes through to the gRPC resolver |
| `protocol` | string | inherit | Non-empty overrides the shared protocol |
| `insecure` | bool | inherit | Tri-state: unset inherits the shared value. Meaningful for scheme-less endpoints; an endpoint URL's scheme already carries the TLS intent, and an explicit `true` forces plaintext even over `https://` — prefer stating the intent in the scheme |
| `headers` | map | inherit | **Replaces** the shared map wholesale — never merged, so one backend's token is not sent to the other. An explicitly empty `headers: {}` means "this signal sends no headers", distinct from omitting the field (inherit) |
| `temporality` | string | `cumulative` | Metric temporality preference: `cumulative`, `delta`, or `lowmemory` — the `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE` vocabulary and instrument-kind mapping (empty falls through to that env var). `delta` reports counters/observable counters/histograms as per-interval deltas, as Datadog and some other vendors expect. **Metrics block only** — setting it under `logs:` is a config error |

```yaml
observability:
  enabled: true
  metrics:
    endpoint: https://otel.internal.example
    protocol: http/protobuf
    temporality: delta                         # e.g. for a Datadog-fronted collector
    headers:
      authorization: "Bearer metrics-token"
  logs:
    endpoint: https://logs.vendor.example      # separate backend
    protocol: http/protobuf
    headers:                                   # with its own credentials
      x-api-key: "logs-token"
```

While the deprecated shared fields remain in play, a signal that overrides `endpoint` without setting its own `headers` inherits the shared map — including any shared bearer token, which then goes to the overridden backend. The daemon warns at startup when it sees that combination; state the intent with an explicit per-signal `headers:` (`{}` for none) to silence it. `enabled: true` with both signals explicitly off is rejected at config load.

## Remote config section

See [Remote Configuration](remote-config.md) for details. When `remote_config.url` is set, the local file/registry config becomes a base that is overlaid with dynamic sections (`rules`, `enrolments`, `sync`) fetched from a `dotvault-config` service.

## Rules section

See [Sync Rules](sync-rules.md) for details.

## Enrolments section

See [Service Onboarding](../services/overview.md) for details.

## Validation

dotvault validates the configuration on startup and exits with an error if:

- `vault.address` is missing
- No rules are defined (waived when `remote_config.url` is set — the remote document may supply them)
- Rule names are not unique
- A rule omits `vault_key` (a [keyless rule](sync-rules.md#rules-without-a-vault-key)) but also omits `target.template` — there is no secret data to write
- A `target.format` is not one of: `yaml`, `json`, `ini`, `toml`, `text`, `netrc`, `ssh_config`
- `web.listen` resolves to a non-loopback address (when web is enabled)
- An enrolment entry has an empty `engine` field
- `api.unix.path` is set to a relative path (it would resolve against each process's working directory, so the daemon and a client started elsewhere would disagree about where the socket is)
