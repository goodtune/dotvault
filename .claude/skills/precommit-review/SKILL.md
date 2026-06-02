---
name: precommit-review
description: Dispatch a five-persona pre-push code review (security, architecture, cross-platform, test & correctness, docs & DX) against the current branch's unpushed changes. Use BEFORE every `git push` of new commits on a feature branch so findings drive a single clean commit series instead of a noisy round-trip with CI reviewers. Skip only when the user explicitly opts out for the current push, or when the push is purely administrative (rebase pointer update, tag, etc.) and touches no code.
---

# precommit-review

This skill is the project-local replacement for the previous
`.github/workflows/claude-code-review.yml` "council of reviewers"
that ran on every PR open/synchronize. The CI workflow generated
a noisy comment loop and arrived after the push — by the time
findings landed, the author had already moved on, so the fix
cycle was always one commit behind. Running the same five
personas locally before the push collapses that loop: findings
are addressed in-place and the resulting commit series tells a
clear story.

## When to invoke

Invoke before every `git push` of new commits on a feature
branch. Skip only when:

- The user has explicitly said to skip review for this push, or
- The push is purely administrative (an existing commit being
  re-pushed after a rebase that doesn't change the diff, a tag,
  a branch pointer update).

If you are unsure, run it. The cost is bounded (five short
agent calls) and missing a finding has a real cost (a
public-PR comment loop the author has to babysit).

## How

### 1. Determine what's about to be pushed

```sh
# Unpushed commit summaries on the current branch:
git log --oneline @{upstream}..HEAD 2>/dev/null || git log --oneline origin/HEAD..HEAD

# Full diff to brief the personas with:
git diff @{upstream}..HEAD 2>/dev/null || git diff origin/main...HEAD
```

If the branch has no upstream and `origin/main` doesn't exist
either, fall back to `git status` and `git diff HEAD` so the
personas see at least the uncommitted changes.

### 2. Dispatch the five personas in parallel

Issue **one** message containing five `Agent` tool calls. Each
uses `subagent_type=general-purpose` (or `Explore` if the
persona only needs read-only file inspection — security and
architecture often benefit from `Explore`'s read-window-aware
approach when the change is small).

Brief each persona with:

- Branch name and unpushed-commit summary
- The full diff (paste inline; do not re-derive)
- The persona's lens (see below)
- The relevant `CLAUDE.md` sections to keep the bar consistent
- An instruction: **report in under 250 words** with concrete
  `file:line` references and a severity tag
  (`blocker` / `major` / `minor` / `nit`). Suppress
  "no findings" filler — return a single line saying so if
  there is nothing to report.

### 3. Triage findings

| Severity | Action |
|----------|--------|
| `blocker` | Address before pushing. No exceptions. |
| `major`   | Address before pushing, or push a commit message that explains the deliberate decision to defer. |
| `minor`   | Fix if cheap. Otherwise mention in the commit message. |
| `nit`     | Fix only if trivially co-located with other changes. |

When you decline a `major` finding, the commit message that
declines it should reference the specific persona / finding so a
future reader knows the trade-off was deliberate.

### 4. Push

`git push -u origin <branch>`.

## Persona briefs

Each persona reviews the same diff but applies a different
review lens. The set mirrors the original council workflow.

### Security

> Review the diff with a security lens. Cover: credential
> handling (`token`, `password`, `headers` map, Vault tokens,
> OAuth flows); file permissions (0600 invariant on managed
> files, 0600 on `~/.dotvault-token`); CSRF / CSP on the web UI;
> the loopback-only invariant for the web listener; secrets
> appearing in slog output even at Debug level; registry /
> DACL handling on Windows; template injection in
> `internal/tmpl/`; HTTP header injection
> (CR/LF/NUL) in any OTLP/HTTP path; YAML round-trip leaks
> (`MarshalYAML` strip discipline); time-of-check / time-of-use
> on token-file reads.

### Architecture

> Review the diff with an architectural lens. Cover: package
> boundaries (`internal/auth`, `sync`, `enrol`, `handlers`,
> `web`, `vault`, `observability`); interface contracts
> (`FileHandler`, `Engine`, `Refresher`, `Watcher`,
> `SettingsFielder`); the daemon's lifecycle ordering
> (auth → initial sync → READY → loop); error handling vs.
> CLAUDE.md's conventions ("Don't add error handling for
> scenarios that can't happen", per-rule isolation,
> trust-but-verify); mutex coverage; goroutine leak / context
> propagation; observability hot path discipline (no labels
> with unbounded cardinality); duplicated logic that should
> live in one package.

### Cross-platform / portability

> Review the diff for Linux / macOS / Windows behaviour.
> Cover: `CGO_ENABLED=0` invariant; path resolution
> (XDG_CONFIG_DIRS vs `%ProgramData%` vs Application Support);
> Windows subsystem (`dotvault.exe` console vs
> `dotvaultw.exe` GUI); registry-vs-YAML config parity; atomic
> writes (temp file + rename across platforms); signal
> handling (`SIGHUP` on Windows, abstract socket prefix);
> build tags (`//go:build linux`); systemd vs launchd vs
> Windows-service expectations; goreleaser nfpms paths across
> RPM / DEB / APK.

### Test & correctness

> Review the diff for test coverage and behavioural
> correctness. Cover: tests for the changed code; table-driven
> idioms; integration-vs-unit balance (`skipIfNoVault`
> coverage gaps); flake risk (sleeps, time-of-day, scheduling
> dependencies); missing edge cases the diff implies; data-race
> hazards under `go test -race`; whether the assertions are
> load-bearing (don't pass vacuously) or whether removing the
> production change would still let them pass; metric / log
> assertions that promise behaviour the production code
> doesn't deliver.

### Docs & DX

> Review the diff for docs and developer-experience drift.
> Cover: `CLAUDE.md` / `README.md` / `docs/` alignment with
> the change; CLI help text; config validation error
> messages; comments that describe code that no longer
> exists; phantom outcomes in metric / instrument godocs;
> upgrade-notice call-outs for behavioural breaking changes;
> `.github/dependabot.yml` entries when a new package
> ecosystem appears; `make test` / `make build` behaviour;
> goreleaser / packaging contents drift.

## Anti-patterns this skill exists to avoid

- **Push-then-review.** The CI council workflow ran on PR
  open/sync. Findings arrived as comments after the push, so
  the author either rebased (rewriting history other reviewers
  had already commented on) or layered fix commits (noisy PR).
  Pre-push review fixes once, pushes once.
- **Repeated dispatch in a tight loop.** If your last push
  was less than ~5 minutes ago and you're pushing a one-line
  fix that an earlier review explicitly flagged, the personas
  will not have new context. Skip review and reference the
  earlier finding in the commit message instead.
- **Asking the personas to fix things.** Personas review and
  report. The fix is the author's; the personas don't run
  with write access.
