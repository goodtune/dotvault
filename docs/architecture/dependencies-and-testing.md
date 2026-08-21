# Dependencies, permissions, testing

> Carved from CLAUDE.md. The full file-permission matrix, the annotated dependency table, and the testing / dependency-update notes. The binding rules from these sections are summarised under "Invariants" and "Gotchas" in CLAUDE.md.

## File Permissions & Security

- Managed files (all sync rule targets): written at 0600
- Token file (`~/.dotvault-token`): written at 0600, warns if permissions differ
- Config file: warns if group or world writable
- Secret values are never logged, even at DEBUG level
- All file writes are atomic (temp file + rename)
- Local API socket (`api.enabled`): created 0600 inside a 0700 directory via `internal/uds`, refusing to clobber a socket a live instance owns
- Filesystem mount (`fuse.enabled`): owner-only (FUSE's default; `allow_other` is deliberately not offered), mountpoint created 0700, files 0400 / dirs 0500 read-only and 0600 / 0700 when `read_write`. Read-only unless `fuse.read_write`, enforced in `vaultfs.Tree` as well as via the kernel `ro` mount option so the guarantee does not rest on a mount flag
- Web UI: loopback only, CSRF on all mutating endpoints (documented exceptions: the peer-action endpoints `POST /api/v1/remote/browse`, `POST /api/v1/remote/notify`, and `POST /api/v1/remote/clipboard`, which use an Origin check instead — see Web UI routes for the rationale), strict CSP
- Windows: DACL-based permission checks via Security API (GetNamedSecurityInfo, GetAce)

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/hashicorp/vault/api` | Vault client SDK |
| `github.com/spf13/cobra` | CLI framework |
| `gopkg.in/yaml.v3` | YAML parsing (Node-level) |
| `gopkg.in/ini.v1` | INI parsing |
| `github.com/jdx/go-netrc` | Netrc parsing |
| `github.com/cli/oauth` | GitHub OAuth device flow |
| `github.com/pkg/browser` | Open browser |
| `github.com/gen2brain/beeep` | Cross-platform desktop notifications (pure Go, no cgo) |
| `git.sr.ht/~jackmordaunt/go-toast` | Windows clickable toast (protocol activation) for notify `--action-url`; Windows-only path |
| `nhooyr.io/websocket` | WebSocket client (Vault Events API) |
| `github.com/Microsoft/go-winio` | Windows named-pipe listener (SSH agent transport) |
| `github.com/coreos/go-systemd/v22` | systemd sd_listen_fds (socket activation; linux-tagged import) + sd_notify (READY/STOPPING/WATCHDOG; imported everywhere, inert outside systemd) |
| `github.com/hanwen/go-fuse/v2` | FUSE filesystem (pure Go, no cgo; linux/darwin/freebsd-tagged import) |
| `golang.org/x/crypto/ssh/agent` | SSH agent protocol server (read-only backend) |
| `golang.org/x/term` | Secure terminal input |
| `golang.org/x/sys` | OS-specific syscalls (Windows registry, etc.) |

All pure Go. No CGO dependencies.

## Testing

- **Unit tests** per package with fixture files and table-driven tests
- **Integration tests** in `test/integration/` against a real Vault dev server (via docker-compose)
- Engine interface allows mock injection for enrolment tests without real OAuth providers
- `go test ./...` runs all unit tests; integration tests require the docker-compose environment

**A green `go test ./...` is not evidence the Vault-backed tests ran.** They are guarded by skip-if-the-stack-is-down checks, so with `docker compose up -d` absent they skip silently rather than fail. This has masked a real regression before: five packages each carried a hardcoded `dev-root-token` that was never valid (vault-init runs `vault operator init`, which mints a random root token to a volume), so those tests skipped when the stack was down and 403'd when it was up — an entire tier never ran. `internal/vaulttest` centralises the token lookup so that cannot be reintroduced one package at a time; **new Vault-backed tests must go through it** rather than hardcoding credentials. Bring the stack up before trusting a test run on anything touching auth, sync, enrolment, or the vault client.

The FUSE mount tests likewise skip when FUSE is unusable (`mount_fuse_test.go`); CI installs `fuse3` explicitly. On macOS they need macFUSE, and the platform-neutral `internal/vaultfs` core is tested everywhere regardless.

## Dependency Updates

Dependabot is configured in `.github/dependabot.yml` and currently covers:

- `gomod` at repo root
- `github-actions` at repo root

When introducing a new package ecosystem (e.g. a second npm workspace, a Dockerfile, a Python tool directory), extend `.github/dependabot.yml` with a matching `updates:` entry so the new manifests are kept up to date. Use the same weekly schedule and grouped-updates pattern as the existing entries unless there is a reason to diverge.

