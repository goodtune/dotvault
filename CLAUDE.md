# dotvault

Cross-platform daemon (Go) that runs in user context, authenticates to HashiCorp Vault, and synchronises KVv2 secrets into local configuration files via surgical, field-level merges.

**How to read this file.** It is a router, not a specification. Items under **Invariant** break something when violated — treat them as binding. Items under **Current design** record a choice that made sense at the time; if a task calls for revisiting one, propose it and say what changes. Depth lives in `docs/architecture/` and in package doc comments — follow the pointer rather than assuming this file is complete.

## Agent workflow: review before pushing

Every Claude agent on this repo runs a five-persona pre-push review of the unpushed changes BEFORE executing `git push`. The personas are security, architecture, cross-platform, test & correctness, and docs & DX. This replaces a PR-time CI review that generated a comment loop the author always had to babysit one commit behind.

1. **Invoke `/precommit-review`.** The skill at `.claude/skills/precommit-review/` inspects the unpushed diff, fires five `Agent` calls in one message, and waits. Each persona reports under 250 words with `file:line` references and a severity tag (`blocker` / `major` / `minor` / `nit`).
2. **Address the findings in the same commit series** — fix in place, don't push and then fix in a follow-up. `blocker`/`major`: fix, or commit a message naming the persona and the deliberate trade-off. `minor`/`nit`: fix when cheap, else mention in the commit message.
3. **Push once.** A clean series with the review baked in is the deliverable.

Skip only when the user explicitly says so, or when the push is purely administrative (rebase pointer update, tag). Doc-only changes can use judgement. This is non-negotiable for code-changing pushes.

## PR descriptions and commit messages

Write PR bodies and long-form commit messages in **flowing prose** — one long line per paragraph or bullet, no manual wrapping inside a paragraph. GitHub re-wraps to the viewer's width; hard-wrapped source renders ragged, churns multiple lines per single-sentence edit, and breaks copy-paste. Hard breaks are still right between bullets, numbered steps, paragraphs, and code-block boundaries. Commit *subject* lines stay ~50 chars; this rule is for the body.

Do **not** mention the pre-push review in PR descriptions — it is the default workflow here, so saying so every time is noise. The audit trail is the commit series itself.

## Commands

```sh
make test          # go test ./...
make python-test   # build the cgo bridge, then the Python binding tests
make build         # current platform
make build-all     # linux/darwin (amd64/arm64) + windows (amd64)

docker compose up -d                                  # Vault + Dex, for local dev
go run ./cmd/dotvault run --config config.dev.yaml     # daemon against the dev stack
```

The web UI is server-rendered Go templates with **no build step** — `internal/web/uitmpl/*.tmpl` plus static assets in `internal/web/uiassets/`, embedded via `embed.FS`. There is no npm, no bundler, and no committed build artefact.

Local dev needs `127.0.0.1 dex` in `/etc/hosts`. Dev Vault is on `127.0.0.1:8200`, the dotvault web UI on `9000`. JFrog enrolment testing is opt-in: `docker compose --profile jfrog up -d` (~3 min cold start). `vault-init` seeds sample secrets and writes the root token to `/vault/data/root-token`. `.claude/launch.json` defines both services as Claude Code Desktop preview configurations.

## Map

```
cmd/dotvault/main.go     CLI entry point (Cobra)
client/                  Public, importable Go API — the only supported import boundary
python/                  Python bindings: cgo c-shared bridge over client/ + ctypes wrapper
internal/
  config/                YAML + Windows Registry (GPO) + per-user preference overlay (user.go)
  regfile/               .reg <-> YAML conversion
  paths/                 OS-specific path resolution
  vault/                 Vault client wrapper, KVv2, Events API (WebSocket)
  remoteconfig/          Remote config overlay: ETag fetcher, last-known-good cache, fail-open
  auth/                  Auth orchestration (OIDC, LDAP+MFA, token, mtls/+tpm/+os)
  securestore/           Key store for cert auth: file + build-tagged TPM + Windows OS cert store
  loginsuppress/         login-check suppression marker
  passwd/                /etc/passwd parsing for login-check --no-passwd
  observability/         OTel metrics + logs SDK wiring, slog->OTel bridge
  tokenwatch/            Watches ~/.dotvault-token for replacement (inotify on Linux)
  httpproxy/             Per-request proxy resolver (ieproxy/PAC on Windows, env elsewhere)
  notify/                Cross-platform desktop notifications via beeep
  clipboard/             Cross-platform clipboard writer + content-free validation
  urlallow/              Shared http/https allowlist for OS-opener/notification sinks
  uds/                   Per-user Unix-socket listener, 0600-in-0700 owner-only invariant
  sync/                  Hybrid event+poll sync engine, state store
  handlers/              File format handlers (yaml, json, ini, toml, text, netrc, ssh_config)
  tmpl/                  Go template rendering (named tmpl to avoid shadowing text/template)
  enrol/                 Credential acquisition (GitHub, JFrog, Databricks, ghp, SSH, Copy)
  web/                   Web UI server (server-rendered pages + REST API), auth endpoints
  perms/                 File permission checks (Unix mode bits, Windows DACL)
  tray/                  Windows system-tray icon (no-op elsewhere)
  agent/                 SSH agent: read-only ExtendedAgent backend + socket/pipe listeners
  sshfwd/                Daemon-managed SSH remote forwards
  vaultfs/               FUSE filesystem: platform-neutral core + build-tagged go-fuse binding
  vaulttest/             Shared plumbing for tests against the docker-compose dev Vault
test/integration/        Integration tests against real Vault
packaging/windows/       NSIS installer script + build helper
packaging/linux/         systemd units
```

## Invariants

**Build.** All binaries are `CGO_ENABLED=0` static builds; the Python bridge is the single exception. `main.version` is the **v-stripped** semantic version (`0.19.0`) even though release tags are v-prefixed — consumers must not add or assume a leading `v`. Windows ships two binaries from one source because the PE subsystem flag is immutable post-link: `dotvault.exe` (console, the CLI) and `dotvaultw.exe` (GUI, `-H=windowsgui`, for double-click and the tray). CLI subcommands run through `dotvaultw.exe` appear to do nothing — cmd.exe does not wait for GUI-subsystem binaries.

**Config surfaces move in lockstep.** A new config field must be extended across `internal/config/registry_windows.go` (live loader), `internal/regfile/regfile.go` (render), `internal/regfile/parse.go` (parse), **and** a round-trip test. Coverage is total today — every YAML field has a registry equivalent and round-trips losslessly — and that property is worth keeping. On Windows, HKLM policy at `SOFTWARE\Policies\goodtune\dotvault` replaces the file config entirely; **HKCU is never read**, because it is user-writable and so cannot be policy. Add a matching `config.dev.yaml` entry when adding an enrolment engine, so the dev config exercises every engine.

**Static vs dynamic config sections.** Dynamic (`rules`, `enrolments`, `sync.interval`, `remote_config`) apply in place on SIGHUP or the refresh tick. Static (`vault`, `web`, `api`, `agent`, `fuse`, `observability`, `bypass_system_config`) configure subsystems built once at startup; a reload that finds them changed logs a WARN naming them rather than half-applying. A remote document may carry dynamic sections only — static sections in one are a hard error, and `remote_config` itself is local-only.

**The per-user overlay is a narrow exception, not a reversal.** `paths.UserConfigPath()` may carry **only** the `fuse` section, and each field ratchets rather than overwrites: `enabled` ORs (user may turn it on), `read_write` ANDs (user may turn writes off, never on). Before making any other section user-overridable, answer the question that licensed this one: could a user turning it on reach anything their own Vault token could not?

**Auth.** `VAULT_TOKEN` is deliberately ignored everywhere, including the SDK's automatic pickup, so a concurrent `vault` CLI session never leaks in. Downscoping (`vault.policies`) **fails closed** — a failed child-token mint is a login error, never a fallback to the broad token. A `+tpm` method has **no silent plaintext fallback**. Under `mtls+os` no token is written at rest, and that guarantee is gated **at the wiring** (`cmd/dotvault`) rather than in each reader, so a future reader inherits it. Borrowed peer tokens are held **in memory only** and never written to `~/.dotvault-token` — the peer stays the single owner.

**Denied-token suppression.** A token Vault has rejected is not presented again — `auth.TokenDenylist` suppresses it, and `cmd/dotvault` builds **one** instance before the first Vault call and shares it across the startup reuse check, the peer borrow, `waitForHeadlessToken`, and `LifecycleManager`. Sharing is the point: the bug was each stage independently re-asking about a token an earlier stage had watched Vault refuse. Three properties are load-bearing. **Only Vault's verdict counts** — `auth.IsTokenRejected` is narrow by design (a 403 or the expired sentinel); a 5xx, a sealed Vault, or a connection failure is a fault of the moment and must leave the token retryable. **Suppression is keyed on the token's value**, so a new token is never affected. And it is a **long re-probe window** (`DenyProbeInterval`, 15m), not a permanent verdict — a 403 can also mean a policy missing `auth/token/lookup-self`, or a Vault mid-failover, which clear server-side with nothing happening on this host.

**Web.** Loopback binding is a hard invariant; the daemon refuses to start if `web.listen` resolves elsewhere. The browser sees three surfaces and `GET /` (`handleRoot`) alone decides which: the login view at `/` when the daemon holds no token, the first-run wizard at `/setup/` when authenticated with nothing enrolled, and the main site under `/ui/` otherwise.

**All browser POSTs — `/ui/`, `/setup/` and the login forms alike — require a present, same-origin `Origin`** (`requireSameOrigin`); that is the CSRF control for this surface, and an absent Origin is rejected because these endpoints have no curl consumer. The JSON API keeps token-based CSRF, with three documented exceptions — `POST /api/v1/remote/{browse,notify,clipboard}` — which use an Origin check instead because their consumer is a bare curl over a forwarded socket where an issue-then-spend handshake is impractical.

Secrets never ride in page HTML: reveal and clipboard are separate server-side fragments, and the clipboard copy happens server-side so the value never reaches the browser. **The login view loads no JavaScript at all** — its waiting states advance via `<meta http-equiv="refresh">`. Inline scripts stay forbidden; do not use datastar's `ExecuteScript`/`Redirect` SSE helpers, which the CSP blocks — use 303 redirects. The only safe interpolation into **any** datastar attribute is a strictly URL-encoded value.

**The `client/` facade is the only supported import boundary.** External modules import `client`, never `internal/*`. Identity is the **OS user**, not the token — changing that default derivation is a path-layout migration, not a facade tweak. Keep the `client.Config` projection in lockstep when the connectivity/auth shape of the system config changes. The Python bridge imports **only** `client`; when extending its surface, change the error category codes on both sides together and add a matching exception class.

**SSH agent is read-only.** `Add`/`Remove`/`RemoveAll`/`Lock`/`Unlock`/`Signers` return `ErrReadOnly` — dotvault is one-way, so the agent is too. Endpoint permissions are a hard invariant: 0600-in-0700 via `internal/uds` on Unix, protected-DACL SDDL on Windows.

**Managed SSH forwards.** `ssh.yaml` is user-level and must never be resolved from a system location, put in the registry, or carried by the remote-config overlay — it is user-writable and so cannot act as policy. `sshfwd.Registry` is the single writer; the CLI is a thin client of the daemon's API and never writes the file itself. Host-key trust has exactly three outcomes — CA-signed, pinned-and-matching, or rejected — with **no runtime trust-on-first-use**; a changed key is a hard error, never a confirmable prompt.

**Filesystem (FUSE).** Only `mount_fuse.go` imports go-fuse (tagged `linux || darwin || freebsd`); `mount_other.go` returns `ErrUnsupported` so the windows target keeps building — keep new logic in the platform-neutral core. `NewStore` is the only place the mount and user prefix are joined, which is what makes "a mount cannot address another user's secrets" structural. `cleanPath` must not use `path.Clean` — Vault does not collapse `..`. Read-only is enforced in `Tree.readWrite` **and** via the kernel `ro` option, both. Package cache TTL and kernel entry/attr timeouts must stay equal. `Read` copies into the caller's buffer; returning a slice of the handle's panicked the daemon. Mount failure is never fatal and never retried.

**Security posture.** Secret values are never logged, even at DEBUG. All file writes are atomic (temp file + rename). Managed files and the token file are 0600. The peer-action endpoints log lengths and scheme+hostname, never content — URLs, notification text, and clipboard payloads are all capability- or credential-bearing.

## Current design

Deliberate choices, recorded so they are not re-litigated by accident — and so they can be revisited on purpose. None of these are invariants.

- **No ADMX administrative template**, and none planned. Admins author registry values directly (e.g. `reg-import` from YAML); the registry surface is the supported Group Policy integration.
- **FUSE:** `allow_other` is not offered; there is no Windows/WinFsp backend (cgo DLL, against the `CGO_ENABLED=0` contract); `.json` is the extension that collapses the folder/secret name collision.
- **Managed SSH forwards:** no local forwards, no per-remote SSH usernames, no `known_hosts` file interop, no non-`streamlocal` forward types.
- **Python bindings** cover the read-only + cached-auth subset plus peer actions. Interactive `Login`/`Authenticate` are excluded — driving a browser or TTY flow across FFI is not what a library caller wants.
- **macOS proxy detection** falls back to env vars; native CFNetwork would require cgo. **macOS Secure Enclave** is a stub returning `ErrUnsupported` until the binary is code-signed.
- **Staged deprecations:** the shared OTel exporter fields are being retired in favour of per-signal config (#140); `vault.no_default_policy` defaults false today, staged to true, mandatory at 1.0.
- **The `merge` field** exists in rule config but is not dispatched on — each handler uses its native strategy, the only sensible one for that format.

## Gotchas

- **Adding a scripted page means updating `uiScriptedPath`.** The relaxed CSP that lets datastar evaluate attribute expressions is keyed on that list. A page missed there renders fine and then silently refuses to evaluate *any* datastar expression — which is how the wizard's card poll was first found broken.
- **A green `go test ./...` is not evidence the Vault-backed tests ran.** They skip silently when the docker-compose stack is down. This has masked a real regression: five packages each hardcoded a `dev-root-token` that was never valid, so those tests skipped when down and 403'd when up — a whole tier never ran. `internal/vaulttest` centralises the lookup; **new Vault-backed tests must go through it**. Bring the stack up before trusting a run touching auth, sync, enrolment, or the vault client.
- **Seven `internal/web` socket tests fail on macOS and pass in CI.** `t.TempDir()` there yields a ~112-byte path against the OS's 103-byte `sun_path` limit for Unix sockets, so `TestSocketOnly*`, `TestLosingServerDoesNotUnlinkWinnersSocket`, `TestPartialBindCleansUpBoundListeners`, `TestTokenEndpointDeclinesDuringReauth`, and `TestSocketActivatedAPIServesAndSurvivesShutdown` fail with a path-length error. CI is Linux (`/tmp/...`, short) and green. Confirm against a clean checkout before assuming you broke something.
- **FUSE tests skip when FUSE is unusable.** CI installs `fuse3`; macOS needs macFUSE. The platform-neutral `internal/vaultfs` core is tested everywhere regardless.
- **A new browser-driven enrolment engine needs a matching web card.** The web runner deliberately builds `enrol.IO` with a nil `Browser` (the daemon must not pop a browser on a headless host), so the engine writes its login URL to `io.Out`. Emit it in a form the card (`internal/web/ui_enrol.go` + `uitmpl/enrol_card.tmpl`) already recognises — an `https://` URL, plus the one-time-code line only if there is a user code — or add a branch. Otherwise it lands in the raw-output fallback and the user sees a bare URL with nothing to click. **Verify the web path, not just the CLI**, which opens a real browser and masks this.
- **A rule's render-affecting definition is fingerprinted into state.** Without `ruleRenderHash`, editing only `target.template` would skip forever — neither the secret version nor the file moved.
- **New package ecosystem → add a `.github/dependabot.yml` entry** (currently gomod, github-actions, and pip at `python/`).
- **`target.delete_nulls` is json/yaml only**, and tombstones reach **mapping keys only** — neither handler descends into arrays, which the merge replaces wholesale. It exists because the merge is otherwise additive by construction: without it a rule can add and update keys but never retire one.
- **Unattended engines are invisible to the first-run wizard** (`enrol.EngineUnattended`, today only Copy) — excluded from the decision to show it *and* from the page. A copy enrolment often finishes before the user sees anything, so counting it would satisfy `NeedsWizard` on its own.

## Where the depth lives

Carved verbatim out of this file; each is the full prior text, not a summary.

| Topic | Internal detail | User-facing |
|---|---|---|
| Authentication, tokens, sockets | `docs/architecture/authentication.md` | `docs/authentication/` |
| Config sections, validation, registry | `docs/architecture/configuration.md` | `docs/configuration/config-reference.md` |
| CLI command behaviour | `docs/architecture/cli-internals.md` | `docs/cli.md` |
| Daemon startup and reload | `docs/architecture/daemon-lifecycle.md` | `docs/admin/deployment.md` |
| Enrolment engines | `docs/architecture/enrolment.md` | `docs/services/` |
| Sync engine, handlers, templates | `docs/architecture/sync-engine.md` | `docs/configuration/sync-rules.md` |
| Web UI, `/ui/`, routes | `docs/architecture/web.md` | `docs/web-ui.md` |
| SSH agent and forwards | `docs/architecture/ssh.md` | `docs/guide/ssh-agent.md`, `ssh-forwards.md` |
| FUSE and the per-user overlay | `docs/architecture/filesystem.md` | `docs/guide/filesystem.md` |
| `client/` facade, Python bindings | `docs/architecture/public-api.md` | `client/README.md`, `python/README.md` |
| Version injection, Windows binaries | `docs/architecture/build-and-packaging.md` | `docs/getting-started/installation.md` |
| Dependency table, permission matrix | `docs/architecture/dependencies-and-testing.md` | — |
| Dependency table, permission matrix | `docs/architecture/dependencies-and-testing.md` | — |

Package doc comments carry the rationale nearest the code — `internal/vaulttest`, `internal/uds`, `internal/vaultfs`, and `internal/securestore` are the models. Prefer adding new rationale there over growing this file.
