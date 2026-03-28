# MFA Login Support for dotvault

## Problem

When Vault has MFA enabled (e.g., Duo push or TOTP), LDAP authentication fails because dotvault doesn't handle the `MFARequirement` in the login response. The initial `POST auth/<mount>/login/<username>` returns an empty `ClientToken` with an `MFARequirement` field instead, and the current code treats this as a failed login.

## Goals

- Support Vault MFA for LDAP auth (push and TOTP)
- Expose a web login page when running in web mode instead of prompting at the terminal
- CLI mode: prompt at TTY, fail gracefully when no TTY is available
- Unified async login model shared by CLI and web paths
- Route restructuring: scope all auth endpoints under their method (`/auth/oidc/*`, `/auth/ldap/*`, `/auth/token/*`)

## Non-Goals

- MFA for OIDC (handled at the identity provider level)
- MFA for token auth (already authenticated)
- Config schema changes (no new fields needed)

## Architecture

Two layers handle Vault login with MFA:

### 1. Vault Client — MFA Detection & Validation

**File:** `internal/vault/client.go`

New methods on `vault.Client`:

- `LoginLDAP(ctx, mount, username, password) (*LoginResult, error)` — POSTs LDAP credentials to `auth/<mount>/login/<username>`. Inspects the response:
  - If `ClientToken` is present: returns it directly (no MFA)
  - If `MFARequirement` is present with empty `ClientToken`: returns `LoginResult` with `MFARequired: true`, the `MFARequestID`, and the list of MFA method constraints (each has an ID and type)

- `ValidateMFA(ctx, mfaRequestID, methodID, passcode) (string, error)` — POSTs to `sys/mfa/validate` with the request ID and payload. For push (Duo), passcode is `""` (empty string triggers push notification). For TOTP, passcode is the user-provided code. Blocks until the push is approved or the context is cancelled. Returns the `ClientToken` on success.

New types:

```go
type LoginResult struct {
    Token        string
    MFARequired  bool
    MFARequestID string
    MFAMethods   []MFAMethod
}

type MFAMethod struct {
    ID   string
    Type string // "duo", "totp", etc.
}
```

### 2. LoginTracker — Async Login State Machine

**File:** `internal/auth/login.go`

Manages async login attempts so the web frontend can poll status. Also used by CLI mode.

**States:** `pending` → `mfa_required` → `authenticated` | `failed`

```go
type LoginStatus struct {
    State      string           `json:"state"`
    Token      string           `json:"-"`
    Error      string           `json:"error,omitempty"`
    MFAMethods []vault.MFAMethod `json:"mfa_methods,omitempty"`
}

// loginSession holds internal state for an in-progress login attempt.
// MFARequestID and MFAMethodID are stored here (not in LoginStatus)
// so SubmitTOTP can use them without the caller needing to provide them.
type loginSession struct {
    status       *LoginStatus
    mfaRequestID string
    mfaMethodID  string
    cancel       context.CancelFunc
}

type LoginTracker struct {
    mu       sync.Mutex
    sessions map[string]*loginSession
    vault    *vault.Client
}
```

**Methods:**

- `StartLogin(sessionID, mount, username, password)` — Spawns a goroutine with a 5-minute context timeout. Calls `vault.LoginLDAP()`. If MFA is required, stores `mfa_required` state with method info. If the only MFA method is push (Duo), immediately calls `vault.ValidateMFA()` which blocks until approved. If TOTP, waits for `SubmitTOTP()`.

- `SubmitTOTP(sessionID, passcode)` — Called when user submits a TOTP code. Calls `vault.ValidateMFA()` with the passcode.

- `GetStatus(sessionID) *LoginStatus` — Returns current state. The `Token` field is `json:"-"` so it is never serialized to the frontend. The server handler reads it internally to set the token on the Vault client and write the token file.

- `Clear(sessionID)` — Removes the session's result after the token is consumed.

**Session ID:** Generated server-side (random 32 bytes, hex-encoded) when `POST /auth/ldap/login` is called. Returned in the 202 response so the frontend can poll with it.

**Thread safety:** `sync.Mutex` on the results map.

**CLI usage:** Same `LoginTracker` is used in CLI mode. `StartLogin()`, then loop on `GetStatus()` with 500ms poll interval. For TOTP, prompt for the code via `term.ReadPassword` and call `SubmitTOTP()`.

## Web Auth Endpoints

### Route Restructuring

Existing routes move under `/auth/oidc/`:

| Old Route | New Route |
|---|---|
| `GET /auth/start` | `GET /auth/oidc/start` |
| `GET /auth/callback` | `GET /auth/oidc/callback` |

New LDAP routes:

| Route | Method | Description |
|---|---|---|
| `/auth/ldap/login` | POST | Accepts `{username, password}`, generates session ID, calls `LoginTracker.StartLogin()`, returns `202 {session_id}`. CSRF-protected. |
| `/auth/ldap/status` | GET | Query param `?session={id}`. Returns `{state, mfa_methods?, error?}`. Token is never included. |
| `/auth/ldap/totp` | POST | Accepts `{session_id, passcode}`, calls `LoginTracker.SubmitTOTP()`. CSRF-protected. |

New token routes:

| Route | Method | Description |
|---|---|---|
| `/auth/token/login` | POST | Accepts `{token}`, validates via `LookupSelf()`, sets token on client and writes token file if valid. Returns `200 {state: "authenticated"}` or `401`. CSRF-protected. |

### Auth Completion Signaling

When `/auth/ldap/status` handler detects `authenticated` state:

1. Reads the token from `LoginTracker` (internal, not serialized)
2. Sets it on the Vault client and writes the token file
3. Calls `LoginTracker.Clear(sessionID)`
4. Signals `s.authDone` channel (same channel used by OIDC today)

This means `WaitForAuth()` in `main.go` works identically regardless of auth method.

### Status Endpoint Enhancement

`GET /api/v1/status` adds `auth_method` field to its response (from config). The frontend uses this to determine which login form to render.

## Frontend — Login View

### Auth Gate in `app.jsx`

1. On mount, call `getStatus()`
2. If `status.authenticated === false`, render `LoginPage` with `status.auth_method`
3. Once authenticated, transition to the existing dashboard

### LoginPage Component

**File:** `internal/web/frontend/src/components/login-page.jsx`

Renders based on `auth_method`:

- **`oidc`**: "Login with OIDC" button that navigates to `/auth/oidc/start`
- **`ldap`**: Username + password form. On submit, POST to `/auth/ldap/login`, get session ID, start polling `/auth/ldap/status` at 2-second intervals. If state becomes `mfa_required`:
  - Push method (Duo): show "Waiting for MFA approval..." with a spinner
  - TOTP method: show passcode input field, submit via `POST /auth/ldap/totp`
- **`token`**: Single token input field. On submit, POST to `/auth/token/login`

### API Additions in `api.js`

- `loginLDAP(username, password)` — POST with CSRF
- `getLDAPStatus(sessionID)` — GET
- `submitTOTP(sessionID, passcode)` — POST with CSRF
- `loginToken(token)` — POST with CSRF

## CLI Mode — LDAP with MFA

### TTY Check

`authenticateLDAP` checks `term.IsTerminal(os.Stdin.Fd())` before prompting. If no TTY, returns error: `"LDAP auth requires a terminal or web mode (web.enabled: true)"`.

### Flow with MFA (TTY present)

1. Prompt for password (existing behavior)
2. Create a `LoginTracker`, call `StartLogin()`
3. Poll `GetStatus()` in a loop (500ms interval, respects context cancellation):
   - `pending` → continue waiting
   - `mfa_required` with push method → print `"Waiting for MFA approval (check your device)..."`, continue polling
   - `mfa_required` with TOTP method → prompt for passcode via `term.ReadPassword`, call `SubmitTOTP()`, continue polling
   - `authenticated` → read token from tracker, set on client, write token file, done
   - `failed` → return error

### No MFA Case

`LoginTracker` handles this transparently. If `LoginLDAP` returns a token directly, the state goes straight to `authenticated` and the first poll returns success.

## `main.go` Orchestration Changes

The `runDaemon` auth dispatch simplifies:

**When `webServer != nil` (web mode enabled):**
- All auth methods go through the web UI
- Open browser to the web UI root URL (the SPA's `LoginPage` handles method routing)
- Block on `webServer.WaitForAuth(ctx)` regardless of method

**When `webServer == nil` (CLI mode):**
- `oidc` → existing `authenticateOIDC` with ephemeral listener
- `ldap` → updated `authenticateLDAP` with TTY check and `LoginTracker`
- `token` → existing token resolution (unchanged)

`AuthStartURL()` is replaced by `URL()` which returns the web UI root.

**Re-authentication (lifecycle manager):**
- Web mode: lifecycle error handler opens browser to web UI root (same as initial auth)
- CLI mode for LDAP: log a warning telling the user to restart (no TTY interaction mid-daemon)

## Files Changed

| File | Change |
|---|---|
| `internal/vault/client.go` | Add `LoginLDAP()`, `ValidateMFA()`, `LoginResult`, `MFAMethod` types |
| `internal/auth/login.go` | New file: `LoginTracker` state machine |
| `internal/auth/ldap.go` | TTY check, use `LoginTracker`, MFA handling (push wait + TOTP prompt) |
| `internal/web/auth.go` | Move OIDC routes to `/auth/oidc/*`, add LDAP and token handlers |
| `internal/web/server.go` | Route registration updates, `LoginTracker` on `Server`, `AuthStartURL()` → `URL()` |
| `internal/web/api.go` | Add `auth_method` to status response |
| `internal/web/frontend/src/app.jsx` | Auth gate: login page vs dashboard |
| `internal/web/frontend/src/components/login-page.jsx` | New component: OIDC/LDAP/token forms, MFA states |
| `internal/web/frontend/src/api.js` | New auth API functions |
| `cmd/dotvault/main.go` | Simplified web-mode auth dispatch |

## What's Not Changing

- OIDC auth logic (just route rename)
- Token lifecycle manager (just URL change)
- Sync engine
- File handlers
- Config schema
