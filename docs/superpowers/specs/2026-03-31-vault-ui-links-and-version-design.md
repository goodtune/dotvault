# Vault UI Links and Version Display

## Summary

Add Vault URL deep links and build version display to the dotvault web UI. All additions are in the SPA (post-auth only).

## Backend Changes

### Extend `Server` struct and `ServerConfig`

Add two new fields to `ServerConfig`:
- `Version string` — the build version injected via ldflags
- The Vault address is already available via `VaultCfg.Address`

Add two new fields to `Server`:
- `version string`
- `vaultAddress string`

Populated in `NewServer` from `sc.VaultCfg.Address` and `sc.Version`.

### Extend `handleStatus` response

Add these fields to the `/api/v1/status` JSON response:
- `"version"` — `s.version` (e.g. `"0.1.0"`, `"dev"`)
- `"vault_address"` — `s.vaultAddress` (e.g. `"http://127.0.0.1:8200"`)
- `"kv_mount"` — `s.kvMount` (e.g. `"kv"`)
- `"user_prefix"` — `s.userPrefix` (e.g. `"users/"`)
- `"username"` — `s.username` (e.g. `"gary"`)

These fields are static for the lifetime of the process. They are always included regardless of authentication state, since the SPA only shows post-auth anyway.

### Wire version through `main.go`

Pass the existing `version` variable from `cmd/dotvault/main.go` into `ServerConfig.Version` when constructing the web server.

## Frontend Changes

### StatusBar (top navigation)

Current layout: `[dotvault] [Connected] ... [Updated: HH:MM:SS] [Sync Now]`

New layout: `[dotvault v0.1.0] [Connected] [Vault ↗] ... [Updated: HH:MM:SS] [Sync Now]`

Specifics:
- **Version badge**: Render `status.version` as small muted text immediately after "dotvault" in the `.app-title` span (e.g. `dotvault v0.1.0`). Use a `<span class="app-version">` with reduced opacity and smaller font.
- **Vault link**: An anchor element after the status indicator pill. Text: "Vault" with an external link indicator. Links to `status.vault_address` with `target="_blank"` and `rel="noopener noreferrer"`. Styled as a subtle link that fits the dark header. Only rendered when `status.vault_address` is truthy.

### SecretPanel (secret detail view)

Current heading: `<h2>secretPath</h2>`

New heading row: `<h2>secretPath <a class="vault-link">View in Vault ↗</a></h2>`

The link opens the secret directly in the Vault web UI at:
```
{vault_address}/ui/vault/secrets/{kv_mount}/show/{user_prefix}{username}/{secretPath}
```

Implementation:
- `SecretPanel` receives `status` as a new prop (passed from `App`)
- A helper function `buildVaultSecretURL(status, secretPath)` constructs the URL
- The link uses `target="_blank"` and `rel="noopener noreferrer"`
- Only rendered when `status.vault_address` is truthy

### Deep Link URL Construction

Helper function in a shared location (inline in `secret-panel.jsx` or a small util):

```js
function buildVaultSecretURL(status, secretPath) {
  const base = status.vault_address.replace(/\/+$/, '');
  return `${base}/ui/vault/secrets/${status.kv_mount}/show/${status.user_prefix}${status.username}/${secretPath}`;
}
```

This produces URLs like:
```
http://127.0.0.1:8200/ui/vault/secrets/kv/show/users/gary/myapp/config
```

## CSS Changes

New classes in `style.css`:
- `.app-version` — small, muted version text in the header
- `.vault-link` — styled anchor for Vault links in both header and secret panel
- `.secret-heading` — flex container for secret path + vault link in SecretPanel

## Files Modified

| File | Change |
|---|---|
| `internal/web/server.go` | Add `version`, `vaultAddress` to `Server` struct and `ServerConfig`; populate in `NewServer` |
| `internal/web/api.go` | Add `version`, `vault_address`, `kv_mount`, `user_prefix`, `username` to `handleStatus` response |
| `cmd/dotvault/main.go` | Pass `version` into `ServerConfig.Version` |
| `internal/web/frontend/src/app.jsx` | Pass `status` prop to `SecretPanel` |
| `internal/web/frontend/src/components/status-bar.jsx` | Add version badge and Vault link |
| `internal/web/frontend/src/components/secret-panel.jsx` | Add `status` prop, "View in Vault" deep link |
| `internal/web/static/style.css` | Add `.app-version`, `.vault-link`, `.secret-heading` styles |

## Testing

- Verify `/api/v1/status` returns the new fields
- Verify StatusBar renders version and Vault link
- Verify SecretPanel deep link opens correct Vault UI URL
- Verify links use `target="_blank"` and `rel="noopener noreferrer"`
- Verify version shows "dev" during local development
- Rebuild frontend bundle (`npm run build` in `internal/web/frontend/`)
