# Peer socket pool: per-workstation forwards, glob borrowing, and the pre-1.0 migration

Status: design, approved 2026-09-24. Branch `feat/peer-socket-pool`.

## Problem

`vault.token_socket` names one Unix socket, and every workstation that forwards its dotvault web API to a remote binds the same default path there, `~/.ssh/dotvault.sock`. With one workstation that is fine. With two it is a race: the last forward to connect wins the path and the other is silently unbound.

The observed case is a laptop and a desktop both managing a forward to the same headless host. The desktop is the primary and is always connected. The laptop wakes sporadically; dotvault dutifully reconnects its forward and takes over `~/.ssh/dotvault.sock`, and the desktop's forward is gone without the desktop knowing. The lid closes, the laptop's socket dies, and when the remote's borrowed token ages out it has nowhere to borrow from — even though the desktop is up and would happily serve it.

Forcing every forwarder to periodically recreate its session would paper over this at the cost of churn nobody without the race needs. The fix is to stop sharing the path.

## Design summary

1. Each workstation binds a socket named for itself. The managed-forward default becomes `~/.ssh/dotvault.{{HOSTNAME}}.sock`, stored literally in `ssh.yaml` and expanded on the forwarder at connect time.
2. The borrower accepts a **list** of socket patterns, globs included. The default list is `[~/.ssh/dotvault.sock, ~/.ssh/dotvault.*.sock]`, so the old path keeps working during the transition.
3. Borrowers hold a **pool** of matched sockets. Token borrows go to the most recently seen socket first; the peer actions (`browse`, `notify`, `clipboard`) fan out to every active socket. A socket that cannot be reached within a short bound is evicted and readmitted when it is recreated (inotify on Linux, inode change or a probe window elsewhere).
4. A daemon that borrows through the **old default path** inspects the workstation's managed-forward list, finds the entry naming itself, and PATCHes its `remote_socket` to the new template — the equivalent of `dotvault ssh edit` — so mixed-release fleets converge without a human. This migration, the scalar `token_socket` form, the registry REG_SZ fallback, and the old default path in the list are all removed before 1.0.

## Section 1 — Config shape and round-trips

### `vault.token_socket` becomes a list

The YAML key is unchanged. A new `config.SocketList` type (`[]string`) carries a custom `UnmarshalYAML` that accepts either a scalar or a sequence, so both of these load:

```yaml
vault:
  token_socket: ~/.ssh/dotvault.sock
```

```yaml
vault:
  token_socket:
    - ~/.ssh/dotvault.sock
    - ~/.ssh/dotvault.*.sock
```

The struct field is renamed `Vault.TokenSockets SocketList` (yaml tag `token_socket`). A scalar `""` maps to the empty list. Each entry is validated at load: non-empty, no NUL byte, absolute or `~/`-relative (the `api.unix.path` rule), and glob metacharacters (`*`, `?`, `[`) are permitted **only in the final path segment**. That restriction is what gives every pattern exactly one parent directory to watch, and it keeps a pattern from sweeping the filesystem.

**Legacy scalar rule.** A scalar decodes through `config.ExpandLegacyScalar` (`internal/config/socketlist.go`), not straight into a one-element list. A value of exactly `config.LegacyPeerSocket` (`~/.ssh/dotvault.sock` — the value every pre-list config guide showed, and the path an un-upgraded workstation's managed forward still binds) expands to the explicit pair `[~/.ssh/dotvault.sock, ~/.ssh/dotvault.*.sock]` (`config.PerHostPeerSocketGlob`); any other scalar stays the one pattern the operator wrote. This is deliberate: a host that spells the pre-list default explicitly, read literally as a one-element list, would borrow once, trigger the old-default migration (Section 5) on the workstation, and then match no socket at all once the forward renamed itself — with nothing left to recover it. Reading the scalar as "the default, as it was then written" rather than as a considered one-element list is what preserves the operator's actual intent, and it is also why an *explicit* one-element sequence (not a scalar) is left alone — that spelling can only have been written after the list form existed, so it is taken as deliberate.

### Default and disabling

When the key is absent, `config.TokenBorrowSockets()` and the new `config.PeerActionSockets()` supply the default `[~/.ssh/dotvault.sock, ~/.ssh/dotvault.*.sock]` at resolve time, mirroring `apiSocketCandidate`: the struct keeps the operator's literal value so an exported config round-trips "absent" as absent instead of baking in the default. An explicit empty list (`token_socket: []`, or the scalar `""`) disables peer borrowing and the peer actions, which is what an empty string does today.

This is a deliberate behaviour change: a host that never set `token_socket` will now try the two default patterns on every login and lifecycle recovery. The cost is a glob over one directory and, when nothing matches, no dial at all; the borrow has always been best-effort and never fatal, so the change is additive.

`TokenBorrowSockets()` keeps its shape — `[api socket, ...token sockets...]`, local-first — but the entries are now patterns. **Correction during implementation:** "local-first" and "most-recently-seen-first" turned out to be two different rules that cannot both be expressed as one `Pool`'s sort key — a `Pool` orders by last-seen, and a forwarded peer socket is recreated on every reconnect, so it always looks fresher than the locally-bound API socket and a single pool over both would rank them backwards. The borrow order is instead a `peer.Chain` (`internal/peer/chain.go`): tier 0 wraps the local API socket in its own one-member pool, tier 1 wraps `config.PeerActionSockets()`, and `Chain.Borrow` tries tier 0 before tier 1, falling through only when it holds no token. The daemon and `dotvault login` never reach this ambiguity in the first place — both exclude their own local socket from `TokenBorrowSockets()` outright, so what remains is peers-only and a single `peer.Pool` is already correct for them. `PeerActionSockets()` returns the peer list alone, without the local API socket, preserving the rule that `browse`/`notify`/`clipboard` must reach the workstation and never the local daemon.

### Registry and `.reg`

`Vault\TokenSocket` (REG_SZ) is replaced by `Vault\TokenSockets` (REG_MULTI_SZ), the `Vault\Policies` pattern. The Windows loader (`registry_windows.go`) and the `.reg` parser (`regfile/parse.go`) read the old `TokenSocket` REG_SZ as a one-element list when `TokenSockets` is absent, so an existing GPO keeps working; `reg-import` and the web config download emit only the new value. An explicit empty REG_MULTI_SZ is the empty list (disabled), distinct from absent (default), the same present-versus-absent distinction the per-signal observability `Headers` subkeys already draw. The `TokenSocket` REG_SZ fallback applies the same `ExpandLegacyScalar` rule as the YAML scalar: a value of exactly `~/.ssh/dotvault.sock` reads as the explicit pair, not a one-element list, for the identical reason — a GPO that has not been updated to the list form must not lose its only token source the first time a managed forward renames itself.

### `client/` facade

`client.VaultConfig.TokenSocket string` becomes `TokenSockets []string`. `borrowSockets()` and the peer actions consume the list. This breaks the public Go surface; the facade is pre-1.0, and keeping a deprecated scalar alongside would be two fields for one concept — the shape the observability shared-fields deprecation is still paying for. The Python bridge is unaffected: it passes a config path and reads error categories.

## Section 2 — `internal/peer` and the `Pool`

### Package move

The peer transport is promoted out of `internal/auth`, as the note on `PostFormToPeer` said a further surface should trigger: `PeerSocketClient` → `peer.Client`, `FetchTokenFromSocket` → `peer.FetchToken`, `PostFormToPeer` → `peer.PostForm`, with `ErrPeerUnreachable` and `PeerStatusError` (→ `peer.StatusError`) moving too. `internal/peer` imports only `internal/paths`, `internal/tokenwatch`, and `internal/observability`; `internal/auth`, `cmd/dotvault`, and `client/` import it. Callers are updated; no re-exports are left in `auth`.

### `Pool`

`peer.NewPool(patterns []string, opts ...Option)` expands a leading `~` in each pattern once (an unexpandable pattern is skipped with a debug log) and keeps the patterns in order.

**Resolve.** Every `Borrow` and `Broadcast` begins by re-resolving: one `filepath.Glob` per pattern (a literal is a pattern without metacharacters) and a `stat` per match. This is cheap and is what keeps the pool correct on platforms without inotify. Each member records:

- `path` — the matched socket path;
- `identity` — device and inode from the stat, used to tell "recreated" from "still the same socket";
- `lastSeen` — seeded from the socket's mtime on first sight, bumped to `now` on an inotify create or write event;
- `evictedAt` — zero unless evicted.

A member whose file has vanished is dropped from the pool outright; there is nothing to evict.

**Priority.** Members are ordered by `lastSeen` descending, ties broken by pattern order and then path. A freshly reconnected laptop therefore sits ahead of the desktop for a borrow, which is correct while it is alive and is undone by eviction the moment it is not.

**`Borrow(ctx) (token, source string)`.** Walk the ordered active members and `FetchToken` each under the existing 3-second bound; the first token wins and `source` is the member path it came from. A **transport** failure — dial error, timeout, connection reset, EOF, anything `http.Client.Do` returns — **evicts** the member. An HTTP non-200 does not: the peer is alive and merely holds no token (a 401 from a peer that is itself waiting to authenticate is the common case), and the walk continues.

**`Broadcast(ctx, apiPath, form) error`.** Post to every active member concurrently (a pool holds a handful of sockets, so no bound beyond the member count) under the existing 10-second bound. Outcomes, evaluated once every post has returned:

- any member answered 200 → `nil`;
- any member answered a 4xx → that `*StatusError` is returned, even if another member accepted, because a 4xx means the input is bad everywhere and the caller must hear it;
- no active members → `ErrNoPeers`, which wraps `ErrPeerUnreachable`;
- everything failed → a joined error wrapping `ErrPeerUnreachable`.

Transport failures evict exactly as in `Borrow`. Because both "nothing to talk to" and "everything failed" wrap `ErrPeerUnreachable`, the CLIs' local fallback and the facade's `ErrPeerUnavailable` mapping are unchanged.

**A refusal inside `ReadinessGrace` (2s of the member being seen) does not evict.** inotify reports a forward's `bind()`, the `listen()` that follows leaves no event, and a borrow woken by the create can dial in between and be refused by a healthy peer; evicting on that would take the socket dark for the whole probe window with nothing left to bring it back. The next attempt after the grace applies the normal rule.

**Eviction is a re-probe window, not a verdict**, for the same reason the token denylist's `DenyProbeInterval` is. An evicted member is readmitted when any of the following holds:

1. inotify reports the path created or written (Linux, daemon only);
2. a re-resolve finds a different `identity` at the path — the socket was recreated, which is how a forward reconnecting looks on a platform with no inotify;
3. `EvictProbeInterval` (5 minutes, wall clock) has elapsed since eviction — a forward whose TCP side stalled and then recovered keeps its inode and would otherwise stay dark until the process restarted.

**`Watch(ctx)`** (daemon only). One `tokenwatch` per distinct parent directory across the patterns. `tokenwatch` gains `NewMatch(dir string, match func(name string) bool, onChange func(name string))` beside the single-name `New`; Linux inotify, a no-op elsewhere. On an event whose name matches a pattern the pool bumps that member's `lastSeen`, clears its eviction, and fires the pool's `OnChange` hook. That hook is where the two hand-rolled per-socket `tokenwatch` loops in `cmd/dotvault/main.go` — the `NeedsReauth`-gated `lm.Reload()` nudge in the running daemon and the wake in `waitForHeadlessToken` — plug in; both loops are deleted.

**Auth seam.** `auth.Manager.TokenSockets []string` and `LifecycleManager.SetTokenSockets` become a `peer.Borrower` interface (`Borrow(ctx) (token, source string)`), so `internal/auth` never sees paths or globs and its tests fake the borrower rather than standing up sockets. The exclusion helpers in `cmd/dotvault/apisocket.go` (`daemonBorrowSockets`, `freshLoginBorrowSockets`) keep filtering the pattern list before the pool is built; the local API socket is a literal, so their comparison on expanded paths is unchanged.

**Properties.** Every method is nil-receiver safe (a call site with no pool wired needs no branch). A mutex guards the member table, since the lifecycle goroutine and the watcher goroutine both touch it. One counter, `dotvault.peer.pool` with attribute `event` ∈ `admitted | evicted | readmitted`, makes a flapping forward visible fleet-wide.

## Section 3 — Wiring

### Daemon

`cmd/dotvault` builds one `peer.Pool` from `daemonBorrowSockets(cfg, ownSocket)` before the first Vault call — where the shared `TokenDenylist` is built — and hands it to every borrower: the startup socket borrow, `waitForHeadlessToken`, `auth.Manager.Borrower`, and `lm.SetBorrower`. `pool.Watch(ctx)` starts once. Its `OnChange` hook fans out to the headless idle's wake channel while the daemon is still waiting for a token, and to the `NeedsReauth`-gated `lm.Reload()` afterwards. `vault` is a static section, so the pattern set is fixed for the process lifetime and the config-refresh loop needs no new plumbing.

### One-shot commands

`dotvault login` builds a single transient peers-only pool via `freshLoginBorrowSockets` (it excludes the local API socket, same rationale as the daemon: the command exists to ignore cached tokens, and the local socket is exactly a cache). `login-check`, `status`, `sync`, and `enrol` — the commands that may legitimately reach through this host's own daemon — instead build a transient `peer.Chain` (`newBorrowChain`, `cmd/dotvault/apisocket.go`): tier 0 a one-member pool over the local API socket, tier 1 a pool over `config.PeerActionSockets()`. `dotvault status` reports `source: borrowed from peer socket <path>` with the member path that answered, not the pattern, and additionally prints the chain's per-tier `Status()` for diagnostics. `browse`, `notify`, and `clipboard` build their pool from `config.PeerActionSockets()` alone and call `Broadcast`; any error still degrades to the local action exactly as today, logged at debug.

### `client/` facade

`VaultConfig.borrower()` builds the same two-tier `peer.Chain` as `newBorrowChain` (tier 0 `APISocket`, tier 1 `TokenSockets`) for `Authenticate` and `AuthenticateCached`; `peerAction` builds a peers-only pool over `TokenSockets` (`peerPool()`, deliberately excluding `APISocket`) and calls `Broadcast`. The error mapping is unchanged: `ErrNoPeers` and transport failure → `ErrPeerUnavailable`; a 4xx → a plain error carrying the peer's message. The Python bridge needs no change.

### Visibility

`GET /api/v1/status` gains a `peer_sockets` block: the configured patterns and, per member, `path`, `last_seen`, and `evicted` (with `evicted_at` when set). It is unauthenticated like the sibling `ssh` and `fuse` blocks — it names files in the user's own home and nothing from behind them. `dotvault status` prints the same. This is the block that would have shown "two sockets, one evicted" in the laptop/desktop case instead of "nowhere to borrow from".

## Section 4 — Forwarder side: `{{HOSTNAME}}` and the new default

- `sshfwd.DefaultRemoteSocket` becomes `~/.ssh/dotvault.{{HOSTNAME}}.sock`. `Registry.Add` fills it in literally, as it fills the default today, and `ExpandRemotePath` expands the token at connect time next to the `~/` expansion. A renamed workstation follows on its next reconnect, and the verifying dry run in `ssh add` binds the same path the steady-state forward will.
- The substituted value is the forwarder's `os.Hostname()`: first label only, lowercased, restricted to `[a-z0-9-]` with any other byte replaced by `-`. Case-folding matters because the borrower's glob is a filename match and macOS hostnames are routinely mixed-case. An empty result is a connect error naming the cause, never a silent `dotvault..sock`.
- `ValidateRemoteSocket` accepts `{{HOSTNAME}}` as an exact token only. Any other occurrence of `{{` or `}}` is rejected, so a typo such as `{{HOST}}` fails at `ssh add` or `PATCH` rather than binding a literal-braced socket that would happen to glob-match.
- The `remote_socket` in the status block and in `dotvault ssh list` keeps reporting the expanded path, as it already does for `~/` — now via `ManagedRemote.resolvedSocket` (`internal/sshfwd/remote.go`), retained after a successful `ExpandRemotePath` and reported by `status()`; a remote that has never connected falls back to the configured literal, template and all. The web edit form and `ssh.yaml` show the template regardless.
- `ssh add` and `ssh edit` help text and `docs/guide/ssh-forwards.md` are updated. The one caveat is a **new workstation adding a not-yet-upgraded remote**: pass `--socket ~/.ssh/dotvault.sock`, because the old remote only knows that path.

`ensureRemoteSocketDir` still operates on `~/.ssh` for the default, and the stale-socket eviction in `forward.go` is unaffected.

## Section 5 — Migration (daemon-only, removed before 1.0)

### Trigger

Only in `dotvault run`; one-shot commands never migrate (they sit on a latency budget, and the daemon will get to it). It fires after a **successful** borrow from a pool member whose path is exactly the expanded old default, `$HOME/.ssh/dotvault.sock`, and at most once per socket identity per process: a recreated socket earns one more attempt, and a failed attempt is not retried before then. It lives in `cmd/dotvault/peermigrate.go` and is wired from the pool's borrow result; `internal/peer` knows nothing about it.

### Steps, over that same socket

1. `GET /api/v1/status` → `version` and `hostname_label`. Skip, at debug, unless the version parses as a semantic version at or above the release that introduces `{{HOSTNAME}}` expansion (a named constant, `remoteSocketTemplateSince`); an empty or unparseable value (a dev build) is treated as new. This is the guard that keeps an old workstation from being handed a template it cannot expand and binding a literal-braced socket. `hostname_label` is the value that workstation expands `{{HOSTNAME}}` to — `sshfwd.LocalHostnameLabel()`, served unauthenticated alongside `version` because it is already the visible half of every socket name the forward binds — and it is what makes step 2 an exact check rather than a shape check.
2. **Migration guard:** `canFindRenamedSocket(label)` checks that at least one of *this* host's own borrow patterns matches the **exact** path the workstation's forward will move to, `dotvault.<hostname_label>.sock` in the old default's directory. An earlier version probed a stand-in label, `x`, on the reasoning that the workstation's future hostname was unknowable from here and the question was only whether a glob covered the shape. That is wrong: `dotvault.?.sock` and `dotvault.[a-z].sock` both match the stand-in and neither matches a real hostname, so the stand-in would pass a host whose only token source the migration was about to move out of reach. A peer that reports no label at all is refused for the same reason — the rename cannot be verified, and refusing costs one deferred migration where guessing costs the borrow. The label is **validated before any use** (`sshfwd.ValidateHostnameLabel`, the producer's own rule: non-empty, ≤63 bytes, `[a-z0-9-]`, no leading or trailing `-`): it arrives in an unauthenticated JSON body and is about to become a filesystem path, so an unchecked value would let a hostile peer steer the confirmation probe — a stat and an HTTP request — at any path this user can reach. The raw value is never logged, only its length and the validator's positional complaint. Checked here, after the version gate and before fetching the remotes list, because it costs no network and refusing early keeps the WARN about this host's own `vault.token_socket` misconfiguration separate from anything the peer reports. Without it, a host whose config spells the pre-list default as an explicit one-element list (not a scalar, so `ExpandLegacyScalar` does not rescue it) would trigger the rename and then have no pattern left that matches the renamed socket — losing its only token source in the same step that was meant to fix the sharing problem.
3. `GET /api/v1/ssh/remotes` → the literal `ssh.yaml` entries. Candidates are entries whose stored `remote_socket` is **exactly** `~/.ssh/dotvault.sock`. An explicit absolute spelling of the same path is left alone: that is an operator's choice, not the untouched default.
4. Self-identification of each candidate's `host`: case-insensitive equality with `os.Hostname()` or its first label; failing that, `net.LookupHost(host)` under a 2-second bound yields an address present in `net.InterfaceAddrs()`. Loopback addresses never match. Every matching candidate is migrated; aliases for the same box are distinct entries and each gets its own PATCH.
5. `GET /api/v1/csrf`, then `PATCH /api/v1/ssh/remotes/<host>` with body `{"remote_socket": "~/.ssh/dotvault.{{HOSTNAME}}.sock", "reconcile_delay": "10s"}` and the `X-CSRF-Token` header. The extra field is what makes the exchange answerable. Without it the workstation's `Registry.Patch` saves and reconciles in one breath, rebinding the forward — and so tearing down the connection carrying its own response — and this end sees a dropped connection whether the patch was applied or the peer died. With it, the workstation validates, saves `ssh.yaml` durably, answers 200 over the still-live forward, and only then, after the delay, reconciles once from the **latest** saved configuration (a mutation landing inside the window wins; the deferred pass re-reads the file rather than replaying the entry it committed). `sshfwd.MaxReconcileDelay` (60s) bounds what a caller may ask for, and the web layer 400s anything unparseable or out of range.
6. **Confirmation, on the remote.** A 200 is not the end of it: what this host actually needs to know is that it can still borrow. It polls the expected path — `dotvault.<hostname_label>.sock`, the path step 2 already proved a pattern matches — every 500ms for up to 45s, requiring a socket node, a `GET /api/v1/status` that answers over it, **and** a `hostname_label` in that answer equal to the one the migration was planned against, and logs "peer forward migration confirmed" at INFO. The label match is what makes this evidence about the migration rather than about the neighbourhood: a second workstation's forward can perfectly well sit at a name this host's glob also matches, and treating that as confirmation would report a rename that never happened. The confirmation also runs for hosts already patched when a *later* host's PATCH fails, so a rename that landed is still confirmed and reported rather than stranded behind the once-per-identity latch. A lost PATCH response takes the same path, so it is no longer ambiguous: the renamed socket answering is the evidence, whether or not the reply got home. If the wait expires the migration is reported **uncertain** at WARN, naming the expected path, rather than successful or failed — the workstation may well have applied it. Any error the peer articulated is a single WARN naming the host.

**Retry semantics.** An uncertain migration is retried safely rather than repeated blindly. The once-per-identity latch is keyed on the old-default socket's device/inode pair, so the next time that socket is re-created — the forward reconnecting, which is also the event that follows a workstation that never applied the patch — the whole exchange runs again against the workstation's *current* configuration. The candidate filter is exact-default-only, so a re-run against an entry that did migrate finds nothing to do and patches nothing.

### Why it is safe to do from the remote

Anyone who can reach the forwarded socket can already run `dotvault ssh edit` against it: the PATCH endpoint and its CSRF flow exist today. The migration adds no capability; it automates a mutation the user could already make, narrowed to entries that name this host and still carry the untouched default.

### Sunset

[Issue #172](https://github.com/goodtune/dotvault/issues/172), "Remove pre-1.0 token_socket compatibility", tracks the removal of: the migration itself, the scalar `token_socket` form, the `Vault\TokenSocket` REG_SZ fallback, and `~/.ssh/dotvault.sock` in the default pattern list. Each code site carries a `TODO(pre-1.0, #172)` comment naming it.

## Section 6 — Documentation and tests

### Docs

- `docs/configuration/config-reference.md`: the `token_socket` reference (list form, globs, default, disabling), the `RemoteForward` wiring example, and the ASCII diagram.
- `docs/guide/ssh-forwards.md`: the new default, `{{HOSTNAME}}`, the not-yet-upgraded-remote caveat, and the migration.
- `client/README.md`: `TokenSockets`.
- `CLAUDE.md`: the `vault` config-section entry, the peer-socket borrow and local-API-socket paragraphs, the `sshfwd` default, and a new `peer/` line in the architecture tree.

### Tests

- `internal/config`: `SocketList` scalar, sequence, empty-scalar, and empty-sequence decode; validation (relative path, glob outside the final segment); `TokenBorrowSockets` and `PeerActionSockets` defaults and ordering.
- `internal/regfile`: round-trips of the list form and of the legacy REG_SZ fallback; the `//go:build windows` loader test for both values.
- `internal/peer`: real Unix sockets in a temp dir — ordering by `lastSeen`; eviction on a listener that accepts and never answers; no eviction on a 401; readmission by inode change, by probe window, and by watch event; `Broadcast` any-success, 4xx-wins, and no-peers outcomes; nil-receiver safety.
- `internal/tokenwatch`: `NewMatch` on Linux.
- `internal/sshfwd`: `ExpandRemotePath` hostname substitution and sanitisation; `ValidateRemoteSocket` accepting the exact token and rejecting other braces.
- `cmd/dotvault`: migration against an `httptest` server on a Unix socket — version gate, exact-default match, self-match (hostname and address), PATCH body and CSRF header, once-per-identity, and the mid-response drop; `apisocket_test.go`, `browse_test.go`, `notify`/`clipboard` tests updated for the list.
- `client/`: `TokenSockets` projection and `peerAction` over multiple sockets.
