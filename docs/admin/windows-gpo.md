# Windows Group Policy

On Windows, dotvault can be fully configured via Group Policy using the Windows Registry. This allows centralised management of dotvault settings across a domain without deploying YAML config files.

## How it works

When HKLM registry keys exist at `SOFTWARE\Policies\goodtune\dotvault`, dotvault loads **all** configuration from the registry and ignores the YAML config file entirely. Only machine-level policy (HKLM) is read — HKCU is intentionally skipped because it is user-writable and therefore cannot be trusted for enforced configuration.

!!! important "The `--config` flag is blocked under Group Policy by default"
    When a policy is present, dotvault **refuses** a `--config path/to/config.yaml` override and exits with an error — a managed machine cannot be pointed at an arbitrary config from the command line. To allow the override (for development or troubleshooting on a specific machine), set a `BypassSystemConfig` REG_DWORD of `1` directly under `SOFTWARE\Policies\goodtune\dotvault` (the `bypass_system_config: true` YAML equivalent). With the flag set, an invocation with `--config` loads the named file and ignores the registry; without it, `--config` is rejected. The flag is part of the policy, so it stays under the administrator's control rather than the user's.

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

### Top-level settings (policy root key)

| Registry value | Type | Description |
|---------------|------|-------------|
| `BypassSystemConfig` | REG_DWORD | Allow the `--config` command-line override on this machine (0/1; default 0). Lives directly under the policy root key, not in a subkey. |

### Vault settings (`Vault\` subkey)

| Registry value | Type | Description |
|---------------|------|-------------|
| `Vault\Address` | REG_SZ | Vault server URL (required) |
| `Vault\CACert` | REG_SZ | Path to CA certificate |
| `Vault\TLSSkipVerify` | REG_DWORD | Skip TLS verification (0/1) |
| `Vault\KVMount` | REG_SZ | KVv2 mount path |
| `Vault\UserPrefix` | REG_SZ | Per-user path prefix |
| `Vault\AuthMethod` | REG_SZ | `oidc`, `ldap`, `token`, `mtls`, or `mtls+tpm` |
| `Vault\AuthRole` | REG_SZ | Vault auth role |
| `Vault\AuthMount` | REG_SZ | Vault auth mount path |
| `Vault\OIDCCallbackPort` | REG_DWORD | Fixed local TCP port for the OIDC CLI redirect_uri (0 = built-in default of 8250) |
| `Vault\Policies` | REG_MULTI_SZ | Least-privilege policy set the working token is downscoped to (empty = carry every granted policy) |
| `Vault\NoDefaultPolicy` | REG_DWORD | Strip the implicit `default` policy from the working token (0/1) |
| `Vault\DisableTokenRenewal` | REG_DWORD | Disable RenewSelf (0/1) |
| `Vault\TokenSocket` | REG_SZ | Path to a peer dotvault web-API Unix socket to borrow a token from |

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
| `Observability\Enabled` | REG_DWORD | Master switch for the OTLP exporters, both signals (0/1) |
| `Observability\Endpoint` | REG_SZ | **Deprecated** shared default (see below). OTLP collector endpoint |
| `Observability\Protocol` | REG_SZ | **Deprecated** shared default. `grpc` or `http/protobuf` |
| `Observability\Insecure` | REG_DWORD | **Deprecated** shared default. Disable transport TLS (0/1) |
| `Observability\ExportInterval` | REG_SZ | Export interval (e.g. `30s`, `1m`) |
| `Observability\Headers\<name>` | REG_SZ | **Deprecated** shared default. OTLP header value (see note) |
| `Observability\Metrics\Enabled` | REG_DWORD | Tri-state: absent = inherit, 0 = signal off, 1 = on |
| `Observability\Metrics\Endpoint` | REG_SZ | Metrics-only endpoint override (separate backend) |
| `Observability\Metrics\Protocol` | REG_SZ | Metrics-only protocol override |
| `Observability\Metrics\Insecure` | REG_DWORD | Tri-state: absent = inherit shared |
| `Observability\Metrics\Headers\<name>` | REG_SZ | Metrics-only headers; the subkey's presence replaces the shared map wholesale (present-but-empty = no headers) |
| `Observability\Metrics\Temporality` | REG_SZ | Metric temporality preference: `cumulative`, `delta`, or `lowmemory` (metrics subkey only — rejected under `Logs`) |
| `Observability\Logs\…` | — | Same values for the log signal; a `Temporality` value under `Logs` is rejected at config load (`reg-import` emits it empty there, which is inert) |

The top-level values are shared defaults driving both signals (metrics and logs) against one collector; the `Metrics\` / `Logs\` subkeys override them per signal so the two can go to separate backends or one can be switched off — same layering as the YAML `metrics:` / `logs:` blocks. The shared exporter values (`Endpoint`, `Protocol`, `Insecure`, `Headers` directly under `Observability`) are **deprecated** in favour of the per-signal subkeys, mirroring the YAML deprecation ([#140](https://github.com/goodtune/dotvault/issues/140)): the daemon warns at startup and meters each use on `dotvault.config.deprecated`, and a future release removes them — author new policy under the `Metrics\` / `Logs\` subkeys. Detection is presence-based, so an explicit `Insecure=0` DWORD (which loads as the default `false`) does not count as a use. On a GPO deployment running `dotvaultw.exe` (GUI subsystem, no console) the stderr warning is not visible — the `dotvault.config.deprecated` metric is the observable channel there, which is exactly what it exists for. Endpoint values follow the same contract as YAML: a full URL's scheme carries the TLS intent and an explicit path is used verbatim; a path-less URL gets the OTLP standard `/v1/metrics` / `/v1/logs` appended (http/protobuf); bare `host:port` is the canonical gRPC form with TLS governed by `Insecure`.

!!! warning "Observability headers carry credentials"
    OTLP `headers` typically hold bearer tokens (Datadog / Grafana Cloud / Honeycomb, etc.). Config conversion is lossless in every direction, so `reg-export` and `reg-import` **do** round-trip header values verbatim (each as a REG_SZ value under `Observability\Headers`) — which means a generated `.reg` artefact contains the live tokens. Treat it as a secret: store it at restricted permissions and don't check it in. If you would rather keep tokens out of the policy hive and out of any exported artefact, leave `headers` empty and set them via the per-user `EnvironmentFile` (`OTEL_EXPORTER_OTLP_HEADERS`) instead — the SDK falls through to those env vars.

### Remote configuration (`RemoteConfig\` subkey)

| Registry value | Type | Description |
|---------------|------|-------------|
| `RemoteConfig\URL` | REG_SZ | Remote configuration endpoint (`https` required except loopback hosts) |
| `RemoteConfig\RefreshInterval` | REG_SZ | Re-fetch cadence (e.g. `15m`; default: the sync interval; floor `1m`) |
| `RemoteConfig\CACert` | REG_SZ | Path to a CA bundle pinning the service's TLS certificate |
| `RemoteConfig\Headers\<name>` | REG_SZ | Extra dimension header sent with every fetch (e.g. `X-Dotvault-Env`) |

When `URL` is set, the registry-delivered policy becomes the *base* configuration and the daemon merges the remotely fetched dynamic sections (rules, enrolments, sync) on top — see [Remote Configuration](../configuration/remote-config.md). A GPO base may deliberately carry zero rules when the remote service supplies them all. Unlike observability headers, these values are non-secret dimension labels; like every section, they round-trip losslessly through `reg-export` / `reg-import`.

### Rules (`Rules\{RuleName}` subkeys)

Each rule is a subkey under `Rules\{RuleName}`:

```
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\VaultKey         (REG_SZ)    "gh"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetPath       (REG_SZ)    "~/.config/gh/hosts.yml"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetFormat     (REG_SZ)    "yaml"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetTemplate   (REG_SZ)    "github.com:\n  oauth_token: \"{{.oauth_token}}\""
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\Description      (REG_SZ)    "GitHub CLI credentials"
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetMerge      (REG_SZ)    ""
SOFTWARE\Policies\goodtune\dotvault\Rules\gh\TargetDeleteNulls (REG_DWORD) 0x00000001
```

`TargetDeleteNulls` is the one non-`REG_SZ` value in a rule subkey. It enables [field nullification](../configuration/sync-rules.md#removing-a-field): a `null` in the template removes that key from the target file instead of writing it. It is valid only for `json` and `yaml` rules — a `1` on any other format is rejected at startup like any other invalid policy. `reg-export` always emits the value, including `0x00000000`, so re-importing an export clears a flag a previous policy set.

Write it as a genuine `REG_DWORD`. dotvault refuses to start on a `TargetDeleteNulls` of the wrong type rather than reading it as disabled — silently treating a mistyped policy as "off" would leave retired credentials on disk while the policy said they were being removed.

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

To test with a YAML config file instead (bypassing the registry), the policy must first opt in by setting `BypassSystemConfig` to `1` under the policy root key. Once it is set:

```powershell
dotvault status --config C:\path\to\test-config.yaml
```

Without `BypassSystemConfig`, that command exits with an error explaining the override is not permitted.
