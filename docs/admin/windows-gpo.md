# Windows Group Policy

On Windows, dotvault can be fully configured via Group Policy using the Windows Registry. This allows centralised management of dotvault settings across a domain without deploying YAML config files.

## How it works

When HKLM registry keys exist at `SOFTWARE\Policies\dotvault`, dotvault loads **all** configuration from the registry and ignores the YAML config file entirely. Only machine-level policy (HKLM) is read — HKCU is intentionally skipped because it is user-writable and therefore cannot be trusted for enforced configuration.

!!! important "The `--config` flag always wins"
    If a user invokes dotvault with `--config path/to/config.yaml`, the specified file is used regardless of whether registry keys exist. This is useful for development and troubleshooting but means the user can bypass the managed configuration. In environments where strict enforcement is required, restrict access to the dotvault binary's command-line options.

## Installing the ADMX template

The ADMX administrative template is included in the dotvault distribution at `packaging/windows/dotvault.admx`.

### Local installation

Copy the files to the PolicyDefinitions folder:

```
%SystemRoot%\PolicyDefinitions\dotvault.admx
%SystemRoot%\PolicyDefinitions\en-US\dotvault.adml
```

### Central store (domain)

Copy to the SYSVOL central store:

```
\\domain\SYSVOL\domain\Policies\PolicyDefinitions\dotvault.admx
\\domain\SYSVOL\domain\Policies\PolicyDefinitions\en-US\dotvault.adml
```

After installation, the dotvault settings appear in the Group Policy Management Editor under **Computer Configuration > Administrative Templates > dotvault**.

## ADMX-managed settings

The ADMX template provides UI for these settings in the Group Policy editor:

### Vault settings

| Policy | Registry value | Type | Description |
|--------|---------------|------|-------------|
| Vault Address | `Vault\Address` | REG_SZ | Vault server URL (required) |
| CA Certificate | `Vault\CACert` | REG_SZ | Path to CA certificate |
| TLS Skip Verify | `Vault\TLSSkipVerify` | REG_DWORD | Skip TLS verification (0/1) |
| KV Mount | `Vault\KVMount` | REG_SZ | KVv2 mount path |
| User Prefix | `Vault\UserPrefix` | REG_SZ | Per-user path prefix |
| Auth Method | `Vault\AuthMethod` | REG_SZ | `oidc`, `ldap`, or `token` |
| Auth Role | `Vault\AuthRole` | REG_SZ | Vault auth role |
| Auth Mount | `Vault\AuthMount` | REG_SZ | Vault auth mount path |

### Sync settings

| Policy | Registry value | Type | Description |
|--------|---------------|------|-------------|
| Sync Interval | `Sync\Interval` | REG_SZ | Go duration string (e.g. `15m`) |

### Web UI settings

| Policy | Registry value | Type | Description |
|--------|---------------|------|-------------|
| Web Enabled | `Web\Enabled` | REG_DWORD | Enable web UI (0/1) |
| Web Listen | `Web\Listen` | REG_SZ | Listen address (loopback only) |

## Registry-only settings (Group Policy Preferences)

Sync rules and enrolments are complex multi-field objects that cannot be fully expressed as ADMX policies. Configure these using **Group Policy Preferences > Registry**, targeting keys under `SOFTWARE\Policies\dotvault`.

### Rules

Each rule is a subkey under `Rules\{RuleName}`:

```
SOFTWARE\Policies\dotvault\Rules\gh\VaultKey        (REG_SZ)    "gh"
SOFTWARE\Policies\dotvault\Rules\gh\TargetPath       (REG_SZ)    "~/.config/gh/hosts.yml"
SOFTWARE\Policies\dotvault\Rules\gh\TargetFormat     (REG_SZ)    "yaml"
SOFTWARE\Policies\dotvault\Rules\gh\TargetTemplate   (REG_SZ)    "github.com:\n  oauth_token: \"{{.oauth_token}}\""
SOFTWARE\Policies\dotvault\Rules\gh\Description      (REG_SZ)    "GitHub CLI credentials"
```

Optional OAuth subkey for rules with service onboarding:

```
SOFTWARE\Policies\dotvault\Rules\gh\OAuth\EnginePath (REG_SZ)
SOFTWARE\Policies\dotvault\Rules\gh\OAuth\Provider   (REG_SZ)
SOFTWARE\Policies\dotvault\Rules\gh\OAuth\Scopes     (REG_MULTI_SZ)
```

### Enrolments

Each enrolment is a subkey under `Enrolments\{Name}`:

```
SOFTWARE\Policies\dotvault\Enrolments\gh\Engine                  (REG_SZ)    "github"
SOFTWARE\Policies\dotvault\Enrolments\gh\Settings\client_id      (REG_SZ)    "178c6fc778ccc68e1d6a"
SOFTWARE\Policies\dotvault\Enrolments\gh\Settings\scopes         (REG_MULTI_SZ) "repo\0read:org\0gist"
```

## Example: deploying via GPO

A typical deployment workflow:

1. **Install the ADMX template** in the domain central store
2. **Create a new GPO** linked to the target OU (e.g. "Developer Workstations")
3. **Configure Vault settings** via the ADMX policies in the Group Policy editor:
    - Set Vault Address to `https://vault.example.com:8200`
    - Set Auth Method to OIDC
    - Enable Web UI and set Listen to `127.0.0.1:9000`
4. **Configure rules** via Group Policy Preferences > Registry:
    - Create the registry keys for each sync rule under `Rules\{name}`
5. **Deploy the binary** via SCCM, Intune, or a similar tool
6. **Create a scheduled task** (via GPO Preferences or a script) to run `dotvault.exe run` at user logon

## Verifying the configuration

On a managed machine, verify that dotvault is reading from the registry:

```powershell
dotvault status
```

To test with a YAML config file instead (bypassing the registry):

```powershell
dotvault status --config C:\path\to\test-config.yaml
```
