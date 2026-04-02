# Windows Registry Enrolment Loading

**Issue:** #21 — Windows Registry config loading missing enrolments

**Date:** 2026-04-02

## Problem

When dotvault is managed via Windows Group Policy (HKLM registry keys), `loadFromRegistry()` populates Vault, Sync, Web, and Rules config but never reads enrolments. The ADMX template also has no enrolment policies. Enrolments configured via GPO are silently ignored.

## Solution

Mirror the existing Rules registry pattern to load enrolments from named subkeys under `HKLM\SOFTWARE\Policies\dotvault\Enrolments\`.

## Registry Layout

```
HKLM\SOFTWARE\Policies\dotvault\Enrolments\
  <name>\                        one subkey per enrolment (keyed by KV path segment)
    Engine     (REG_SZ)          required, e.g. "github"
    Settings\                    optional subkey
      <key>    (REG_SZ)          string setting values
      <key>    (REG_MULTI_SZ)    list setting values (e.g. Scopes)
```

Example for a GitHub enrolment with custom scopes:

```
Enrolments\gh\Engine = "github"
Enrolments\gh\Settings\ClientID = "178c6fc778ccc68e1d6a"
Enrolments\gh\Settings\Scopes = ["repo", "read:org", "gist"]
Enrolments\gh\Settings\Host = "github.com"
```

## Go Code Changes

### `internal/config/registry_windows.go`

**`readRegistryEnrolments(root registry.Key) (map[string]Enrolment, error)`**

Opens `registryPolicyPath\Enrolments`, enumerates child subkey names (each is an enrolment name), and calls `readSingleEnrolment` for each. Returns `nil, nil` if the `Enrolments` key does not exist (ErrNotExist).

**`readSingleEnrolment(root registry.Key, name string) (Enrolment, error)`**

Opens the named subkey under `Enrolments\`. Reads `Engine` as REG_SZ. Then attempts to open an optional `Settings\` subkey. If present, enumerates all value names and reads each:
- Try REG_SZ first via `readRegString` — store as `string`
- If not found as string, try REG_MULTI_SZ via `readRegMultiString` — store as `[]any` (each element a `string`) to match YAML unmarshalling behaviour where lists deserialise as `[]any`

Returns the populated `Enrolment` struct.

**`loadFromRegistry()` update**

After the existing `readRegistryRules` call, add:

```go
enrolments, err := readRegistryEnrolments(registry.LOCAL_MACHINE)
if err != nil {
    return nil, true, fmt.Errorf("read registry enrolments: %w", err)
}
cfg.Enrolments = enrolments
```

## ADMX Changes

### `packaging/windows/dotvault.admx`

Add an `Enrolments` category under `Dotvault` in the `<categories>` block:

```xml
<category name="Enrolments" displayName="$(string.Cat_Enrolments)">
  <parentCategory ref="Dotvault" />
</category>
```

Add an XML comment block documenting the GP Preferences registry paths, following the same pattern as the existing Rules comment:

```
Enrolments are complex multi-field objects that cannot be fully expressed
as ADMX policies. Configure enrolments via Group Policy Preferences >
Registry, targeting:
  SOFTWARE\Policies\dotvault\Enrolments\<name>\Engine            (REG_SZ)
  SOFTWARE\Policies\dotvault\Enrolments\<name>\Settings\<key>    (REG_SZ)
  SOFTWARE\Policies\dotvault\Enrolments\<name>\Settings\<key>    (REG_MULTI_SZ)
```

## Tests

### `internal/config/registry_windows_test.go`

These tests can only run on Windows (build-tagged `windows`). They exercise the pure logic functions that don't require real registry access where possible, and use the real registry API where necessary.

- **`TestReadSingleEnrolment`** — verifies Engine and Settings (string + multi-string values) are correctly read into an `Enrolment` struct
- **`TestReadRegistryEnrolmentsNotExist`** — verifies that a missing `Enrolments` subkey returns `nil, nil` (no error)
- **`TestLoadFromRegistryIncludesEnrolments`** — integration-level test verifying `cfg.Enrolments` is populated when registry keys are present

## Out of Scope

- No changes to config validation — existing validation (`enrolments[key].engine is required`) already applies to registry-loaded enrolments
- No ADML file changes (no ADML file exists in the project)
- No changes to the enrolment manager, engine interface, or any other package
- Settings are flat only (no nested maps) — sufficient for all current engines
