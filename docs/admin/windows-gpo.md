# Windows Group Policy

On Windows, dotvault can be fully configured via Group Policy using the Windows Registry. This allows centralised management of dotvault settings across a domain without deploying YAML config files.

## How it works

When HKLM registry keys exist at `SOFTWARE\Policies\goodtune\dotvault`, dotvault loads **all** configuration from the registry and ignores the YAML config file entirely. Only machine-level policy (HKLM) is read — HKCU is intentionally skipped because it is user-writable and therefore cannot be trusted for enforced configuration.

!!! important "The `--config` flag always wins"
    If a user invokes dotvault with `--config path/to/config.yaml`, the specified file is used regardless of whether registry keys exist. This is useful for development and troubleshooting but means the user can bypass the managed configuration. In environments where strict enforcement is required, restrict access to the dotvault binary's command-line options.

## Authoring the registry values

dotvault does **not** ship an ADMX administrative template. Instead, admins author the registry values directly under `SOFTWARE\Policies\goodtune\dotvault` and deploy them via **Group Policy Preferences > Registry** (or any registry-deployment tool: SCCM, Intune, a `.reg` import, etc.).

The supported authoring workflow is to write the configuration as YAML and convert it to a `.reg` file with `dotvault reg-import`:

```powershell
dotvault reg-import config.yaml --output dotvault-policy.reg
```

This emits a canonical `Windows Registry Editor Version 5.00` file (UTF-16LE with BOM, matching regedit.exe) targeting `HKLM\SOFTWARE\Policies\goodtune\dotvault`. Import it into the policy hive, or load it into a GPO's registry preferences. The reverse direction — pulling an existing policy hive back into YAML for review — is `dotvault reg-export`:

```powershell
dotvault reg-export dotvault-policy.reg --output config.yaml
```

Both commands round-trip the **entire** configuration without loss — including observability header values (see the credential note below) — so the YAML and `.reg` forms are interchangeable. The web UI's Effective Configuration screen exposes the same conversion via download buttons.

## Registry schema

Every YAML field has a registry equivalent. The tables below give the value names; `reg-import` writes exactly these, and the live loader reads exactly these.

### Vault settings (`Vault\` subkey)

| Registry value | Type | Description |
|---------------|------|-------------|
| `Vault\Address` | REG_SZ | Vault server URL (required) |
| `Vault\CACert` | REG_SZ | Path to CA certificate |
| `Vault\TLSSkipVerify` | REG_DWORD | Skip TLS verification (0/1) |
| `Vault\KVMount` | REG_SZ | KVv2 mount path |
| `Vault\UserPrefix` | REG_SZ | Per-user path prefix |
| `Vault\AuthMethod` | REG_SZ | `oidc`, `ldap`, or `token` |
| `Vault\AuthRole` | REG_SZ | Vault auth role |
| `Vault\AuthMount` | REG_SZ | Vault auth mount path |
| `Vault\DisableTokenRenewal` | REG_DWORD | Disable RenewSelf (0/1) |

### Sync settings (`Sync\` subkey)

| Registry value | Type | Description |
|---------------|------|-------------|
| `Sync\Interval` | REG_SZ | Go duration string (e.g. `15m`) |

### Web UI settings (`Web\` subkey)

| Registry value | Type | Description |
|---------------|------|-------------|
| `Web\Enabled` | REG_DWORD | Enable web UI (0/1) |
| `Web\Listen` | REG_SZ | Listen address (loopback only) |
| `Web\LoginText` | REG_SZ | Login-page markdown (multi-line via `hex(1)`) |
| `Web\SecretViewText` | REG_SZ | Secret-view markdown (multi-line via `hex(1)`) |

### Observability settings (`Observability\` subkey)

| Registry value | Type | Description |
|---------------|------|-------------|
| `Observability\Enabled` | REG_DWORD | Enable the OTLP metrics exporter (0/1) |
| `Observability\Endpoint` | REG_SZ | OTLP collector endpoint |
| `Observability\Protocol` | REG_SZ | `grpc` or `http/protobuf` |
| `Observability\Insecure` | REG_DWORD | Disable transport TLS (0/1) |
| `Observability\ExportInterval` | REG_SZ | Export interval (e.g. `30s`, `1m`) |
| `Observability\Headers\<name>` | REG_SZ | OTLP header value (see note) |

The block drives both signals (metrics and logs) against the same collector. For `http/protobuf`, `Endpoint` must be a *base* URL like `https://otel.example` — the exporters append `/v1/metrics` and `/v1/logs` themselves; a URL that already ends in a signal-specific path routes both signals to the wrong route.

!!! warning "Observability headers carry credentials"
    OTLP `headers` typically hold bearer tokens (Datadog / Grafana Cloud / Honeycomb, etc.). Config conversion is lossless in every direction, so `reg-export` and `reg-import` **do** round-trip header values verbatim (each as a REG_SZ value under `Observability\Headers`) — which means a generated `.reg` artefact contains the live tokens. Treat it as a secret: store it at restricted permissions and don't check it in. If you would rather keep tokens out of the policy hive and out of any exported artefact, leave `headers` empty and set them via the per-user `EnvironmentFile` (`OTEL_EXPORTER_OTLP_HEADERS`) instead — the SDK falls through to those env vars.

### Rules (`Rules\{RuleName}` subkeys)

Each rule is a subkey under `Rules\{RuleName}`:

```
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\VaultKey         (REG_SZ)    "gh"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetPath       (REG_SZ)    "~/.config/gh/hosts.yml"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetFormat     (REG_SZ)    "yaml"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetTemplate   (REG_SZ)    "github.com:\n  oauth_token: \"{{.oauth_token}}\""
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\Description      (REG_SZ)    "GitHub CLI credentials"
```

Optional OAuth subkey for rules with service onboarding:

```
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\OAuth\EnginePath (REG_SZ)
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\OAuth\Provider   (REG_SZ)
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\OAuth\Scopes     (REG_MULTI_SZ)
```

### Enrolments (`Enrolments\{Name}` subkeys)

Each enrolment is a subkey under `Enrolments\{Name}`:

```
SOFTWARE\Policies\goodtune\dotvault\Enrolments\gh\Engine                    (REG_SZ)        "github"
SOFTWARE\Policies\goodtune\dotvault\Enrolments\gh\Settings\client_id        (REG_SZ)        "178c6fc778ccc68e1d6a"
SOFTWARE\Policies\goodtune\dotvault\Enrolments\gh\Settings\scopes           (REG_MULTI_SZ)  "repo\0read:org\0gist"
SOFTWARE\Policies\goodtune\dotvault\Enrolments\gh\Settings\https_proxy      (REG_SZ)        "http://squid.example.com:3128"
```

The `https_proxy` value (or its `http_proxy` alias) is optional. When unset, the engine consults the machine's IE / WinHTTP proxy configuration — including any deployed PAC script — once per outbound request. Set it explicitly here only when you want this enrolment pinned to a specific proxy regardless of the system-level policy.

### SSH agent (`Agent\` subkey)

The scalar transport settings live directly under `Agent\`; the ordered key sources are subkeys under `Agent\Keys\{N}` where `{N}` is the zero-based list index:

```
SOFTWARE\Policies\goodtune\dotvault\Agent\Enabled        (REG_DWORD)
SOFTWARE\Policies\goodtune\dotvault\Agent\UnixPath       (REG_SZ)
SOFTWARE\Policies\goodtune\dotvault\Agent\WindowsPipe    (REG_SZ)
SOFTWARE\Policies\goodtune\dotvault\Agent\Keys\0\Source      (REG_SZ)        "vault-ca"
SOFTWARE\Policies\goodtune\dotvault\Agent\Keys\0\Mount       (REG_SZ)        "ssh-client-signer"
SOFTWARE\Policies\goodtune\dotvault\Agent\Keys\0\Role        (REG_SZ)        "dotvault-user"
SOFTWARE\Policies\goodtune\dotvault\Agent\Keys\0\Principals  (REG_MULTI_SZ)
```

Authoring these by hand is fiddly; prefer `reg-import` from a YAML config.

## Example: deploying via GPO

A typical deployment workflow:

1. **Author the configuration as YAML** and convert it with `dotvault reg-import config.yaml --output dotvault-policy.reg`.
2. **Create a new GPO** linked to the target OU (e.g. "Developer Workstations").
3. **Deploy the registry values** under `SOFTWARE\Policies\goodtune\dotvault` via Group Policy Preferences > Registry (import the `.reg`, or recreate the values from it).
4. **Deploy the binary** via SCCM, Intune, or a similar tool.
5. **Create a scheduled task** (via GPO Preferences or a script) to run `dotvaultw.exe` at user logon.

## Verifying the configuration

On a managed machine, verify that dotvault is reading from the registry:

```powershell
dotvault status
```

To dump the effective policy back to YAML for review:

```powershell
dotvault reg-export dotvault-policy.reg
```

To test with a YAML config file instead (bypassing the registry):

```powershell
dotvault status --config C:\path\to\test-config.yaml
```
