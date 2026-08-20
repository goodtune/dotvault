# CLI internals

> Carved from CLAUDE.md. Per-command behaviour, exit-code contracts, and the reasoning behind the peer-action commands. User-facing equivalent: `docs/cli.md`.

## CLI

```
dotvault             Print help (no implicit daemon start)
dotvault run         Run the long-lived daemon
dotvault sync        One-shot sync cycle, then exit
dotvault login       Force a fresh login via the configured auth method
dotvault login-check Validate/renew cached token on interactive login (tty-aware)
dotvault enrol       Interactive enrolment picker (`dotvault enrol <name>` to run one directly)
dotvault browse      Open a URL in a browser, preferring the peer over vault.token_socket
dotvault notify      Raise a desktop notification, preferring the peer over vault.token_socket
dotvault clipboard   Put text on the clipboard, preferring the peer over vault.token_socket
dotvault ssh         Manage daemon-maintained SSH remote forwards (add/edit/list/remove)
dotvault status      Display auth state, token TTL, per-rule sync state, filesystem mount state
dotvault version     Print build version (--json for machine-readable resource metadata)
dotvault reg-export  Convert a Windows .reg file to YAML (or canonical .reg)
dotvault reg-import  Convert a YAML config to a Windows .reg file
```

Running `dotvault` with no subcommand prints help — the daemon is no
longer the default. Use `dotvault run` to start it explicitly.

`dotvault login` always runs the configured fresh-auth flow (OIDC, LDAP),
ignoring any cached token. It is the dotvault-config-driven analogue of
`vault login -address … -method …` and is the natural entry point when a
running daemon needs a new token after expiry.

`dotvault login-check` is intended for interactive-shell login profiles
wired in via a thin wrapper that gates on interactivity, TTY, and the
daemon being active (`systemctl --user is-active dotvault.service`).
The binary trusts those preconditions and never re-checks them, so the
wrapper stays trivial and signal handling works correctly during shell
startup.

- A suppression marker at
  `${XDG_STATE_HOME:-$HOME/.local/state}/dotvault/login-check-suppress`
  is checked first. While its mtime is within `DOTVAULT_SUPPRESS_HOURS`
  (positive integer, default `6`) the command exits silently with no
  vault calls. A future mtime is treated as stale so clock skew, VM
  snapshot rollback, or restored backups cannot lock suppression on.
  The path can be overridden via `DOTVAULT_SUPPRESS_MARKER` (used by
  tests). The path matches the previous shell-managed location, so
  existing suppression state survives the rollout without migration.
  Logic lives in `internal/loginsuppress/`.
- `--no-passwd` exits 0 immediately when the current user has an entry
  in `/etc/passwd` — in directory-service fleets a passwd entry means a
  local machine account with no Vault credentials, so a fleet-wide
  profile.d script can pass the flag unconditionally. The file is
  parsed directly (`internal/passwd/`), never via getent/NSS, because
  merged-source lookups cannot say which source an entry came from.
  NIS/compat `+`/`-` splice lines are skipped (they reference directory
  sources, not local accounts). Ignored with a WARN log on Windows. A
  passwd read failure warns and falls through to the normal check (fail
  open; exit 1 stays reserved for genuine internal errors). The check
  runs after the suppression-marker freshness check and refreshes the
  marker on early exit, so subsequent shells in the window stop at the
  marker without re-reading the file. The heuristic is Linux-targeted:
  macOS keeps local accounts in Open Directory, so the lookup never
  matches a human there and the flag degrades to a no-op (falls through
  to the normal check — it cannot wrongly skip auth). Test override:
  `DOTVAULT_PASSWD_FILE`.
- If a cached token is valid and still within the first half of its
  creation TTL, exit clean.
- If the cached token is valid but past the halfway mark, attempt renewal.
  On renewal failure where the token is still valid, warn with the
  absolute expiry time and exit 0.
- If the cached token is missing or invalid, print a one-line
  explanation of why an authentication prompt is about to appear
  ("no cached Vault token was found", "the cached Vault token has
  expired", "the cached Vault token is no longer valid") and then
  run the configured login flow. The line is yellow on a colour-capable
  TTY (ANSI SGR 33; honours `NO_COLOR`; ANSI is gated on the writer
  being `os.Stderr` so test buffers / piped output stay plain) and
  plain text otherwise. Without it, a profile-script invocation would
  drop the user straight into a context-free password prompt. Pass
  `--quiet` to suppress just the notice (the prompt still appears) for
  wrappers that surface their own context. Ctrl-C exits immediately
  without requiring an extra Enter: a dedicated signal handler restores
  the terminal state captured before the password prompt, refreshes the
  marker, and `os.Exit(0)`s (`term.ReadPassword` does not observe
  context cancellation, so going through a goroutine + `os.Exit` is the
  only reliable way to honour the contract).
- The marker is refreshed on every exit past the freshness check
  (success, decline, failure, Ctrl+C, internal errors) so concurrent
  shells across tmux/IDE/SSH-multiplex fanout only ever prompt once
  per window. Concurrent marker updates are intentionally
  unsynchronised — duplicate prompts in a tight race are acceptable;
  blocking shell startup on a `flock` is not.
- Exits `0` for suppressed, success, decline, cancellation, or
  expected authentication failure. Exits `1` only on invalid
  `DOTVAULT_SUPPRESS_HOURS` or genuine internal errors. The shell
  wrapper does not branch on exit code.

`dotvault enrol` is the CLI counterpart to the web UI's enrolment page,
intended for terminal-only users (servers, headless setups, devs who
don't run the local web UI). With no argument it draws a small raw-mode
picker listing every configured enrolment alongside its current state
(`enrolled` / `not enrolled` / `error: …` for unknown engines or Vault
read failures); arrow keys navigate, Enter runs the highlighted entry,
`q` or Esc exits. With a single positional argument it skips the picker
and runs that enrolment directly, looking the name up against the
configured `enrolments:` map. An unknown name prints the configured
keys and exits non-zero.

Both forms require a valid cached Vault token and refuse to initiate
fresh *interactive* authentication — the user is pointed at `dotvault login`
instead. The exception is `mtls+os`, which keeps no token at rest: there an
absent token is the normal state rather than "not authenticated", so enrol
derives one from the certificate via `CertLoginFromStore`. That needs no human,
so it does not breach the rule the refusal exists to enforce, and refusing would
otherwise point the user at a `dotvault login` that is neither necessary nor
meaningful for that method.

The picker also refuses to run without a TTY on both stdin and stderr,
because a headless caller has no way to drive the selection; pass an
explicit name to enrol non-interactively. The underlying engine runs
through `enrol.Manager.RunOne`, which is deliberately a re-run-on-demand
entry point: unlike `CheckAll`, it executes the engine even if the
target is already populated, so the command doubles as a way to refresh
expiring credentials without first wiping the Vault secret.

`dotvault browse <url>` is a `$BROWSER`-shaped wrapper over the web
API's remote-browse endpoint. When `vault.token_socket` names a
reachable peer dotvault (the same SSH-forwarded socket the token
borrow uses, so an already-wired headless host needs no new config),
the URL is form-posted to the peer's `POST /api/v1/remote/browse` and
the browser opens on the workstation; otherwise the URL opens in the
local default browser. Only http/https URLs with a host are accepted —
validated locally (`web.ValidateBrowseURL`, shared with the endpoint)
before any socket or opener is touched. Config load is local-only
(interactive latency budget, and the vault section is local-only
anyway); a config-load failure warns and degrades to the local
browser rather than failing, so the command works on hosts with no
dotvault config. Silent on success, per `$BROWSER` convention. The
socket client lives in `cmd/dotvault/browse.go`
(`postBrowseToSocket`); the transport (expand ~, stat-before-dial,
unix `http.Transport`) is the shared `auth.PeerSocketClient` that
`auth.FetchTokenFromSocket` also uses — only the error policy
differs (browse returns failures for its fallback decision; the
borrow swallows them). The local fallback opener is the injectable
`openLocalBrowser` var (tests fake it, mirroring `internal/auth`'s
`openBrowser`). Note the `$BROWSER` caveat: Python-based tools exec
a multi-word value as one program name — docs point those at a
wrapper script.

`dotvault notify <level> <title> [description]` is the notification
sibling of `browse`, same peer-preferring shape over the same
`vault.token_socket`. It form-posts to the peer's `POST
/api/v1/remote/notify` so a native desktop notification (Windows
toast, macOS Notification Center, Linux D-Bus) appears on the
workstation where a human is looking; otherwise it raises the
notification locally. An optional `--action-url` attaches an
http/https link the notification takes the user to when clicked: it is
genuinely clickable on Windows (the toast is protocol-activated via
go-toast directly, since beeep exposes no activation API — fire-and-forget,
the shell handles the click), and degrades on macOS/Linux (a one-shot
delivery cannot register a click handler there) by appending the URL to
the body so it stays visible. The URL is validated with the same
http/https allowlist as browse — the rule lives in one place
(`internal/urlallow.Validate`, shared by `web.ValidateBrowseURL` and
`notify.validateActionURL`) so the invariant can't drift. Delivery lives in `internal/notify` (a thin
level vocabulary — `info`/`warning`/`error`/`attention` — over
`github.com/gen2brain/beeep`, pure-Go with build-tagged platform
backends, preserving CGO_ENABLED=0). `notify.NewMessage` validates
the level and an optional http/https `action_url`, and sanitizes
title/body — strips control characters and neutralizes the
metacharacters that would break out of beeep's Windows toast backends
(the XML CDATA terminator `]]>`, and the PowerShell here-string
metacharacters `$`/backtick that the COM-unavailable fallback would
otherwise evaluate as a subexpression, i.e. RCE). It is shared by the
CLI and the endpoint so both reject or neutralize input identically.
Level drives urgency (error/attention → `beeep.Alert`,
audible; info/warning → `beeep.Notify`) and, on Linux/BSD where the
D-Bus `app_icon` accepts freedesktop stock names, the icon
(`dialog-error` etc.); on macOS/Windows a stock name isn't a real
file path so `iconArg` returns `""` there and the level shows via
urgency. Delivery is split by build tag: `send_windows.go` raises a
protocol-activated clickable toast via `git.sr.ht/~jackmordaunt/go-toast`
directly when an `action_url` is set (beeep has no activation API), with
`safeToastArgs` XML-escaping `& " < >` and percent-encoding `$`/backtick
for the launch attribute's XML + PowerShell-here-string sinks;
`send_other.go` appends the URL to the body via `actionBody`. Both route
their non-clickable path through the shared `beeepDeliver`. The go-toast
clickable path is not exercised in the (Linux) CI, like the TPM backend —
but its pure encoder `safeToastArgs` is unit-tested everywhere. The local fallback notifier is the injectable
`sendLocalNotification` var.

`dotvault clipboard [text]` is the third peer action, same
peer-preferring shape over the same `vault.token_socket`. It
form-posts to the peer's `POST /api/v1/remote/clipboard` so the value
lands on the clipboard of the workstation the user is actually pasting
on; otherwise it writes this host's clipboard. Together with `browse`
and `notify` it closes the headless-auth loop: open the login page in
the workstation's browser, then stage the one-time token or device
code right where the user's Ctrl+V is. With no positional argument
(or `-`) the text is read from stdin — the documented-preferred path
for secrets, since argv is visible in process listings — and exactly
one trailing newline is stripped (`clipboardText`,
`cmd/dotvault/clipboard.go`); a positional argument is taken verbatim.
Delivery lives in `internal/clipboard`: exec-based writers on the Unix
platforms (`pbcopy`; `wl-copy` → `xclip` → `xsel` in candidate order,
Wayland-first with X11 fallthrough) and direct Win32 syscalls on
Windows (`CF_UNICODETEXT` via `golang.org/x/sys/windows` — not
clip.exe, whose console-code-page stdin mangles non-ASCII text;
preserving CGO_ENABLED=0, hardware-untested in the Linux CI like the
go-toast path, with the shared exec/candidate logic unit-tested
everywhere). The Win32 writer runs the Open→Set→Close sequence under
`runtime.LockOSThread` (the clipboard is thread-affine) and registers
the `CanIncludeInClipboardHistory`/`CanUploadToCloudClipboard`/
`ExcludeClipboardContentFromMonitorProcessing` exclusion formats
alongside the text (best-effort), so the credential stays out of
Win+V history and cross-device Cloud Clipboard sync. `clipboard.ValidateText` (shared by CLI and endpoint) is
deliberately *not* a sanitizer: clipboard content is data, never
interpolated into an evaluated context, and the typical payload is a
credential that must arrive byte-for-byte intact — it only rejects
what no clipboard can carry faithfully (interior NUL, invalid UTF-8)
or what signals a caller bug (empty, >64 KiB), and its error messages
are content-free by contract. The exec writers take text on stdin
(never argv) and deliberately capture no output pipes (wl-copy/xclip
fork a selection-owning child that inherits the descriptors — a pipe
would block until the clipboard is next replaced). The enrolment
wizard's best-effort device-code copy reuses the same writers. The
local fallback writer is the injectable `setLocalClipboard` var. All
three peer-action CLIs (`browse`/`notify`/`clipboard`) share the peer
form-POST transport (`auth.PostFormToPeer`,
`internal/auth/peerpost.go`) and, on the server, the single-flight +
bounded-wait + panic-recovery launcher (`internal/web/launcher.go`,
`guardedLaunch`).

`dotvault ssh add|edit|list|remove` manages the SSH remote forwards the daemon maintains for itself (see "Managed SSH forwards" below). `add`, `edit` (PATCH with only the flags passed — the CLI counterpart of the web UI's per-remote form), and `remove` are thin clients of the daemon's own web API (`cmd/dotvault/ssh.go`, `ssh_add.go`, `ssh_edit.go`, `ssh_remove.go`) — the CLI never writes `ssh.yaml` directly, because the verifying login `add` performs needs the daemon's agent identity, and routing every mutation through the one `sshfwd.Registry` the web UI also uses removes the CLI-versus-daemon write race outright. The daemon is reached over the local API socket (`api.enabled`) when configured, else the loopback web listener (`web.enabled`) — on Windows only the latter exists today, since the API socket is Unix-only, so `dotvault ssh` there requires `web.enabled`. `ssh add <host>` performs a live SSH dial, credential check, and host-key verification before persisting anything (`--force` skips the dial for a host known to be offline right now); an unpinned host's key surfaces as a printed fingerprint requiring confirmation (`--accept-host-key` on a non-interactive shell, after verifying the fingerprint out of band — there is no silent-accept path). `ssh list` degrades to reading `ssh.yaml` directly (reporting `unavailable` status) when the daemon can't be reached, since reading is safe without a daemon but writing is not; `ssh remove` is idempotent on an unconfigured host (prints and exits 0).

The naming follows regedit's `/e` (export) and `/s` (import) directional
convention: `reg-export` pulls policy out of the registry world into a
user-facing form, `reg-import` casts a YAML config into the .reg form a
Windows admin would push back into the registry.

`reg-export` parses a `.reg` file (positional path or stdin when
omitted/`-`) under `HKLM\SOFTWARE\Policies\goodtune\dotvault` and emits the
equivalent dotvault YAML configuration to stdout (or `--output <path>`,
0600). Both UTF-16LE-with-BOM and plain ASCII inputs are accepted — the
encoding is detected from the leading BOM. The reconstructed YAML is
run through `config.Load` validation before being printed, so malformed
inputs surface as clear errors rather than producing partial YAML. Pass
`--regedit` to re-emit the canonicalised .reg form instead of YAML;
combine with `--ascii` for the plain-text variant of the v5 format.

`reg-import` is the inverse: it reads and validates a YAML config, then
emits a `Windows Registry Editor Version 5.00` file targeting
`HKLM\SOFTWARE\Policies\goodtune\dotvault` to stdout (or `--output <path>`,
written with 0600 permissions). Default encoding is UTF-16LE with BOM,
matching the canonical format produced by regedit.exe; `--ascii`
produces an unencoded plain-text variant of the same v5 format.
Multi-line values such as Go templates round-trip via `hex(1):`
(UTF-16LE bytes). Optional string fields are emitted as `""` even when
empty so re-importing clears stale registry values. Rendering lives in
`internal/regfile/regfile.go`, parsing in `internal/regfile/parse.go`,
and the canonical YAML emitter in `internal/regfile/yaml.go`.

The web UI's Effective Configuration screen exposes the same conversion
in-browser via download buttons backed by `GET
/api/v1/config/download?format=yaml|reg`. The endpoint reassembles the
in-memory `*config.Config` and routes through the same regfile renderers,
so a daemon that loaded its config from a Windows GPO can be exported
back as YAML (or vice versa) without restart.

Flags: `--config <path>`, `--log-level debug|info|warn|error`, `--log-format auto|text|json` (forces the slog handler; default `auto` picks text on TTY, JSON otherwise), `--dry-run`. Subcommand-scoped: `--once` on `dotvault run` redirects to the sync path; `--json` on `dotvault version` emits a structured `{version, service, go_version, os, arch}` envelope.

Logging uses `log/slog` — text format when stderr is a TTY, JSON otherwise. Always writes to stderr; no file-based logging directly from dotvault (a configured OTel collector can fan the mirrored log stream out to a file, syslog, or the Windows Event Log — see Config Sections → `observability`).

