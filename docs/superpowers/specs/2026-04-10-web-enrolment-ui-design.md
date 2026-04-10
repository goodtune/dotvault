# Web-Based Enrolment UI Design

## Overview

Redesign the enrolment flow so the web UI drives enrolment interactively, replacing the current terminal-based sequential wizard. After authentication, users see a dedicated enrolment page listing all pending credentials. Each enrolment is started individually by the user, with engine-specific inline UI (device code display for GitHub, passphrase form for SSH). Users can skip individual enrolments and proceed to the dashboard.

## Motivation

The current flow authenticates in the browser, then silently runs the enrolment wizard in the daemon's terminal. The user never sees a wizard in the browser — engines open new browser tabs (e.g. GitHub device flow) without context, and the daemon proceeds without waiting for the user to interact. The web UI should own the entire post-auth setup experience.

## Auth Callback Change

All auth success handlers (`handleAuthCallback`, `handleLDAPStatus`, `handleTokenLogin`) currently respond with "Authentication successful! You can close this window." or redirect to `/`. Change these to redirect to `/` with an HTTP 302. The SPA at `/` will decide what to render based on the status API response.

## SPA Routing

The SPA adds a new top-level view: the enrolment page. View selection in `app.jsx`:

1. Not authenticated → login page (unchanged)
2. Authenticated, has pending enrolments → enrolment page
3. Authenticated, no pending enrolments → dashboard (unchanged)

"Pending" means any enrolment with status `pending`, `running`, or `failed`. Enrolments that are `complete` or `skipped` are considered addressed.

The "Continue to Dashboard" button on the enrolment page calls `POST /api/v1/enrol/complete` (which unblocks the daemon to proceed to sync) and then sets a component-level flag to switch the SPA view to the dashboard. The button is always visible, so the user can proceed even with pending enrolments — they don't need to individually skip each one.

## Header Indicator

When the user is on the dashboard and there are incomplete enrolments (pending or failed — not skipped), a small indicator appears in the SPA header. It shows the count (e.g. "2 pending") and links back to the enrolment page when clicked. It disappears when all enrolments are complete or skipped.

## API Changes

### Modified: `GET /api/v1/status`

Add an `enrolments` array to the existing response:

```json
{
  "authenticated": true,
  "enrolments": [
    {
      "key": "gh",
      "engine": "github",
      "name": "GitHub",
      "status": "pending",
      "fields": ["oauth_token"]
    },
    {
      "key": "ssh",
      "engine": "ssh",
      "name": "SSH",
      "status": "complete",
      "fields": ["public_key", "private_key"]
    }
  ]
}
```

Status values: `pending`, `running`, `complete`, `skipped`, `failed`.

The enrolments list is built by iterating the config's `enrolments` map, looking up each engine for its `Name()` and `Fields()`, and checking Vault for completeness (existing `findPending()` logic). Running/skipped/failed states come from the in-memory `EnrolmentRunner`.

### New: `POST /api/v1/enrol/{key}/start` (CSRF-protected)

Triggers the named enrolment engine. Returns 409 if already running, 404 if the key doesn't exist.

Response: `{"status": "running"}`

The engine runs in a background goroutine. The `IO` struct is wired with:
- `Out` → writes captured into an in-memory string slice
- `Browser` → no-op (frontend handles opening tabs)
- `PromptSecret` → blocks on channel, same as existing `EnrolPromptSecret`
- `Username` → from the authenticated Vault identity
- `Log` → the server's slog logger

On completion, the runner writes credentials to Vault KVv2 (same as the current manager) and updates the enrolment status to `complete`. On error, status becomes `failed` with the error message stored.

### New: `POST /api/v1/enrol/{key}/skip` (CSRF-protected)

Marks an enrolment as skipped for this session. Returns 404 if the key doesn't exist. Returns 409 if the enrolment is currently running.

Response: `{"status": "skipped"}`

Skipped state is in-memory only. A daemon restart resets it — the enrolment will appear as pending again based on the Vault check.

### New: `GET /api/v1/enrol/{key}/status`

Returns the current state of a specific enrolment, including captured output lines from the engine.

```json
{
  "status": "running",
  "output": [
    "Waiting for authentication...",
    "! First, copy your one-time code: A1B2-C3D4"
  ]
}
```

On completion:
```json
{
  "status": "complete"
}
```

On failure:
```json
{
  "status": "failed",
  "error": "device flow: context deadline exceeded"
}
```

The frontend polls this endpoint while an enrolment is running.

### New: `POST /api/v1/enrol/complete` (CSRF-protected)

Signals the daemon that the user has finished with enrolments. The daemon unblocks and proceeds to the sync engine. This replaces the automatic "wizard finished" trigger.

Response: `{"status": "ok"}`

### Existing: `GET /api/v1/enrol/prompt` and `POST /api/v1/enrol/secret`

Unchanged. Used by the SSH engine's passphrase flow. The frontend polls `/enrol/prompt` while an enrolment is running to detect when input is needed, then submits via `/enrol/secret`.

## Server-Side: `EnrolmentRunner`

New struct in `internal/web/` that manages per-enrolment lifecycle for web mode.

### State

```go
type enrolState struct {
    Key      string
    Engine   enrol.Engine
    Settings map[string]any
    Status   string        // pending, running, complete, skipped, failed
    Output   []string      // captured IO.Out lines
    Error    string        // set on failure
    cancel   context.CancelFunc
    mu       sync.Mutex
}

type EnrolmentRunner struct {
    states   map[string]*enrolState
    vault    *vault.Client
    username string
    done     chan struct{} // signalled by POST /enrol/complete
    mu       sync.RWMutex
}
```

### Initialization

After auth completes, the daemon calls `runner.Init(cfg.Enrolments, vaultClient, username)` which:
1. Iterates config enrolments
2. Looks up each engine via `enrol.GetEngine()`
3. Checks Vault for existing credentials (reuses `findPending()` logic)
4. Builds the `states` map with initial status (`complete` if Vault has all fields, `pending` otherwise)

### Engine Execution

`runner.Start(key)` called by the HTTP handler:
1. Validates state is `pending` or `failed` (retry case)
2. Creates a child context with cancel
3. Launches goroutine that:
   - Sets status to `running`
   - Calls `engine.Run(ctx, settings, io)` with web-wired IO
   - On success: writes to Vault KVv2, sets status to `complete`
   - On error: sets status to `failed`, stores error message

### IO Wiring

The `IO` struct for web mode:
- `Out` → `io.Writer` that appends lines to `enrolState.Output` (thread-safe via mutex)
- `In` → nil (not used in web mode)
- `Browser` → no-op function (frontend opens tabs itself)
- `Log` → server's slog logger
- `Username` → from Vault auth identity
- `PromptSecret` → `server.EnrolPromptSecret(ctx, label)` (existing implementation)

### Daemon Integration

In `cmd/dotvault/main.go`, when web is enabled:

```
WaitForAuth() → runner.Init() → runner.Wait() → proceed to sync
```

`runner.Wait()` blocks on the `done` channel until `POST /api/v1/enrol/complete` is called. If there are no pending enrolments after init, `Wait()` returns immediately.

When web is disabled, the existing `CheckAll()` → terminal wizard flow is unchanged.

## Frontend Components

### `enrol-page.jsx`

Top-level enrolment view. Fetches enrolment list from status API. Renders an `EnrolCard` for each enrolment. Shows "Continue to Dashboard" button when all enrolments are addressed (complete or skipped). Clicking "Continue" calls `POST /api/v1/enrol/complete` then switches to the dashboard view.

### `enrol-card.jsx`

Renders a single enrolment with state-dependent UI:

- **Pending** — engine name, description, "Start" and "Skip" buttons
- **Running** — engine name, status badge, engine-specific inline content (see below). Polls `GET /enrol/{key}/status` every 2 seconds.
- **Complete** — green checkmark, "Enrolled successfully"
- **Skipped** — dimmed card, "SKIPPED" label
- **Failed** — error message, "Retry" button

### Engine-Specific UI (within running state)

The card parses the `output` array from the status endpoint to render engine-appropriate UI:

- **GitHub** — detects the device code pattern (`! First, copy your one-time code: XXXX-XXXX`) from output. Displays the code prominently with a "Copy Code" button and an "Open GitHub" link (`https://github.com/login/device` or the configured host). Shows "Waiting for approval..." below.
- **SSH** — polls `/api/v1/enrol/prompt` to detect when the passphrase prompt appears. Renders a password input form. Submits via `/api/v1/enrol/secret`. For `recommended` mode, shows a hint that passphrase is optional.
- **Generic fallback** — for any future engine, displays the raw output lines as a log.

The device code detection uses a simple regex on the output lines. This keeps the engine unchanged — the GitHub engine writes its output to `IO.Out` as it does today, and the frontend interprets it.

**GitHub engine `In` caveat:** The GitHub engine currently calls `bufio.NewScanner(in).Scan()` to wait for Enter before opening the browser. In web mode, `IO.In` should be set to an `io.Reader` that returns immediately (e.g. `strings.NewReader("\n")`) so the engine proceeds without blocking. The `Browser` no-op means no browser is opened server-side — the frontend provides the "Open GitHub" link instead.

## Error Handling

- **Engine failure** — card shows "Failed" state with error text and a "Retry" button. Retry calls `POST /enrol/{key}/start` again.
- **Page reload** — `EnrolmentRunner` state is in-memory. Running engines continue; frontend picks up current state from poll endpoints. No work lost.
- **Daemon restart** — all in-memory state reset. `findPending()` re-checks Vault, so completed enrolments (already in Vault) show as complete. Skipped state is lost — user can skip again.
- **No enrolments configured** — status API returns empty list, SPA shows dashboard directly.
- **All already complete** — same as above. `findPending()` returns nothing.
- **Config adds new enrolments** — the daemon's existing periodic re-check detects new enrolments. The header indicator appears on the dashboard, prompting the user to visit the enrolment page.

## CLI Mode

No changes. When `web.enabled` is false, the daemon runs `enrolMgr.CheckAll()` with the terminal wizard exactly as today. The `EnrolmentRunner` is only instantiated when the web server is active.

## Files Changed

| File | Change |
|------|--------|
| `internal/web/enrol_runner.go` | New — `EnrolmentRunner` struct and methods |
| `internal/web/enrol_runner_test.go` | New — unit tests for runner state machine |
| `internal/web/server.go` | Register new `/api/v1/enrol/` routes, hold `EnrolmentRunner` reference |
| `internal/web/api.go` | Add enrolments to status response, new handler functions |
| `internal/web/api_test.go` | Tests for new endpoints |
| `internal/web/auth.go` | Change auth success responses to redirect to `/` |
| `internal/web/frontend/src/app.jsx` | Add enrolment page view selection logic |
| `internal/web/frontend/src/components/enrol-page.jsx` | New — enrolment page component |
| `internal/web/frontend/src/components/enrol-card.jsx` | New — per-enrolment card component |
| `internal/web/frontend/src/components/status-bar.jsx` | Add pending enrolments indicator |
| `internal/web/frontend/src/api.js` | Add enrolment API methods |
| `cmd/dotvault/main.go` | Wire `EnrolmentRunner` in web mode, keep terminal wizard for CLI mode |
