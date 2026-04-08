# SSH Enrolment Engine Design

## Overview

A new enrolment engine that generates Ed25519 SSH key pairs in OpenSSH format, storing the result as `public_key` and `private_key` fields in Vault KVv2. Key generation uses native Go libraries with no subprocess calls.

## Engine: `SSHEngine`

New file: `internal/enrol/ssh.go`

Zero-field struct implementing the `Engine` interface:

- **`Name()`** — returns `"SSH"`
- **`Fields()`** — returns `["public_key", "private_key"]` (both are completeness gates)
- **`Run(ctx, settings, io)`** — generates key pair and returns `map[string]string{"public_key": "...", "private_key": "..."}`

Registered as `"ssh"` in the engine map in `engine.go`.

## Key Generation

All native Go, no subprocess:

1. `crypto/ed25519.GenerateKey(crypto/rand.Reader)` produces the key pair.
2. Private key marshalled to OpenSSH PEM format:
   - Without passphrase: `ssh.MarshalPrivateKey(privateKey, "username@dotvault")`
   - With passphrase: `ssh.MarshalPrivateKeyWithPassphrase(privateKey, "username@dotvault", []byte(passphrase))`
   - `pem.EncodeToMemory(block)` produces the final PEM string.
3. Public key marshalled to authorized_keys format:
   - `ssh.NewPublicKey(publicKey)` wraps the raw key.
   - `ssh.MarshalAuthorizedKey(sshPub)` produces the `ssh-ed25519 AAAA...` line.
   - Trailing newline trimmed, ` username@dotvault` comment appended.

Dependencies: `crypto/ed25519`, `crypto/rand`, `encoding/pem`, `golang.org/x/crypto/ssh` (already an indirect dependency, becomes direct).

## Passphrase Modes

Configured via the `passphrase` setting in the enrolment config. Three tiers:

| Value | Behaviour |
|-------|-----------|
| `required` (default) | User must enter a non-empty passphrase, entered twice for verification |
| `recommended` | User is prompted but may leave both entries empty to skip |
| `unsafe` | No prompt at all, key always generated without passphrase |

An unrecognised value causes `Run()` to return an error.

### Passphrase Verification Flow

A helper function `promptPassphrase(io IO, mode string) (string, error)` in `ssh.go`:

1. If `mode == "unsafe"`: return `""` immediately.
2. Call `io.PromptSecret("Enter passphrase:")` — get first entry.
3. If `mode == "recommended"` and first entry is empty: return `""` (user opted out).
4. If `mode == "required"` and first entry is empty: return error `"passphrase is required"`.
5. Call `io.PromptSecret("Confirm passphrase:")` — get second entry.
6. If entries don't match: return error `"passphrases do not match"`.
7. Return the passphrase.

No retry loop on mismatch — the wizard logs the failure and continues. Re-run via config reload or daemon restart.

## IO Struct Changes

Two additions to the `IO` struct in `internal/enrol/engine.go`:

- **`Username string`** — the authenticated Vault username. Set by the manager when constructing `IO`. The SSH engine uses it for the key comment (`username@dotvault`).
- **`PromptSecret func(label string) (string, error)`** — requests masked input from the user. Returns the entered string, or error on cancellation/IO failure.

### CLI Implementation

Uses `golang.org/x/term.ReadPassword()` on the terminal file descriptor. The label is printed to `io.Out` before reading.

### Web Implementation

Blocks on a channel until a form submission arrives via HTTP:

1. Engine calls `PromptSecret("Enter passphrase:")`.
2. Implementation sets the pending prompt state (label + response channel).
3. Frontend polls `GET /api/v1/enrol/prompt`, sees a pending prompt, displays a masked input form.
4. User submits, frontend POSTs to `POST /api/v1/enrol/secret`.
5. Handler sends value through the channel, `PromptSecret` returns.

Context cancellation unblocks the channel with an error.

## Web Endpoints

Two new endpoints for passphrase collection:

- **`GET /api/v1/enrol/prompt`** — returns current prompt state: `{"pending": true, "label": "Enter passphrase:"}` or `{"pending": false}`.
- **`POST /api/v1/enrol/secret`** — accepts `{"value": "..."}`, CSRF-protected. Sends the value through the waiting channel.

## Public Key Comment

Hardcoded to `username@dotvault` where `username` is the Vault username from `IO.Username`. Not configurable.

## Configuration

No changes to the `Enrolment` struct. Example YAML:

```yaml
enrolments:
  ssh:
    engine: ssh
    settings:
      passphrase: required
```

The map key `ssh` becomes the Vault KV path segment: `{kv_mount}/data/{user_prefix}{username}/ssh`.

## Registration

Add `"ssh": &SSHEngine{}` to the `engines` map literal in `engine.go` alongside the existing `"github"` entry.

## Vault Storage

Two fields written to Vault KVv2:

| Field | Content |
|-------|---------|
| `private_key` | OpenSSH PEM format (possibly passphrase-encrypted) |
| `public_key` | OpenSSH authorized_keys format with `username@dotvault` comment |

Both fields are declared in `Fields()` and are completeness gates — if either is missing or empty, the enrolment is treated as pending.

## Testing

Unit tests in `internal/enrol/ssh_test.go`:

- **Key generation without passphrase** — `passphrase: "unsafe"`, verify both fields non-empty, parse private key PEM, parse public key authorized_keys line, verify comment is `username@dotvault`.
- **Key generation with passphrase** — `passphrase: "required"`, wire `PromptSecret` to return a fixed string, verify the private key requires the passphrase to decrypt via `ssh.ParseRawPrivateKeyWithPassphrase`.
- **Passphrase mismatch** — wire `PromptSecret` to return different values on successive calls, verify error.
- **Required mode rejects empty** — wire `PromptSecret` to return `""`, verify error.
- **Recommended mode allows empty** — wire `PromptSecret` to return `""`, verify success with unencrypted key.
- **Invalid passphrase setting** — pass `passphrase: "bogus"`, verify error.
- **`Fields()`** — returns exactly `["public_key", "private_key"]`.
- **`Name()`** — returns `"SSH"`.

`PromptSecret` as a function field on `IO` enables straightforward test injection — no mocks of terminal or HTTP needed.

## Files Changed

| File | Change |
|------|--------|
| `internal/enrol/ssh.go` | New — `SSHEngine` implementation |
| `internal/enrol/ssh_test.go` | New — unit tests |
| `internal/enrol/engine.go` | Add `Username` and `PromptSecret` to `IO`; register `"ssh"` engine |
| `internal/web/server.go` (or similar) | Add `/api/v1/enrol/prompt` and `/api/v1/enrol/secret` endpoints |
| `internal/enrol/manager.go` | Wire `IO.Username` and `IO.PromptSecret` at construction time |
| `go.mod` / `go.sum` | `golang.org/x/crypto/ssh` becomes a direct dependency |
