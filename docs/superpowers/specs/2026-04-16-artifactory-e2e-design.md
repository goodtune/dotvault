# Local Artifactory + JFrog Enrolment E2E Verification

**Status:** Design
**Date:** 2026-04-16

## Goal

Stand up a local JFrog Artifactory container in the dev compose stack so the newly-added `JFrogEngine` (see `internal/enrol/jfrog.go`) can be exercised end-to-end against a real Access service, then verify the full enrolment flow once via Playwright to prove the engine is correct before the work merges.

One-shot verification only. No committed E2E test, no CI wiring.

## Non-Goals

- Changes to the `JFrogEngine` Go code, its unit tests, or the `CLAUDE.md` engine documentation.
- A committed Playwright test script or `make test-e2e` target.
- CI integration — Artifactory's 4 GB RAM and ~2 min cold boot make it unsuitable for per-PR test runs.
- License-gated JFrog features (Xray, Distribution, SAML/OAuth federation).

## Architecture

Three new services in `docker-compose.yaml`, all tagged `profiles: ["jfrog"]` so they are skipped by default and activated only by `docker compose --profile jfrog up -d`.

### `artifactory`

- Image: `releases-docker.jfrog.io/jfrog/artifactory-jcr:7.98.9`
- Rationale for JCR over OSS: JCR ships the full JFrog Platform UI chrome, including the `jfClientSession` confirmation screen that the web-login flow routes through. The Access service is bundled in both, but the OSS UI is thinner and has shown inconsistencies in the `/ui/login?jfClientSession=...` handoff. Multi-arch (`linux/amd64` + `linux/arm64`), so Apple Silicon runs native.
- Port: `8082:8082` (JFrog router entrypoint — serves both `/ui/...` and `/access/api/...`).
- Memory limit: 4 GB (`mem_limit: 4g`).
- Volume: named volume `artifactory-data` mounted at `/var/opt/jfrog/artifactory`.
- Healthcheck: `GET /artifactory/api/system/ping` every 5 s, `start_period: 120s`, `retries: 30`.

### `artifactory-init`

Mirrors the `vault-init` pattern. Runs once, exits 0.

Depends on `artifactory` with `condition: service_healthy`.

Responsibilities:

1. Resolve `admin/password` (default) into a known dev password `dotvault-dev` by `POST /artifactory/api/security/users/admin` with `Authorization: Basic YWRtaW46cGFzc3dvcmQ=`.
2. Idempotency: if the initial basic-auth login returns 401, treat as "already initialised" and exit 0. If the reset itself returns 200, exit 0. Any other status is a hard failure with the response body logged.
3. No secrets are logged. The new password is inline in the script because it is a dev-only fixture.

Why REST rather than the file-based `bootstrap.creds` approach: `bootstrap.creds` only takes effect on a **pristine** volume. A REST-based init container survives `docker compose down && up` without needing the volume wiped, matching the ergonomic of `vault-init`.

### Shared profile tag

All three existing services (`vault`, `dex`, `vault-init`) remain profile-less and are brought up by a plain `docker compose up -d`. Only the new `artifactory` + `artifactory-init` carry the `jfrog` profile. Existing devs see zero change in the default workflow.

## dotvault Configuration

`config.dev.yaml` — a single URL change:

```diff
   jfrog:
     engine: jfrog
     settings:
-      # Point at your JFrog Platform. Required — no sensible default exists.
-      url: "https://mycompany.jfrog.io"
+      # Local Artifactory JCR from docker-compose --profile jfrog.
+      url: "http://127.0.0.1:8082"
```

No changes to sync rules, handlers, or engine code — the engine already accepts any URL via the `url` setting.

`CLAUDE.md` — one sentence added to the **Local Development** section:

> JFrog enrolment testing is opt-in: `docker compose --profile jfrog up -d` additionally starts a local Artifactory JCR on port 8082 (admin password `dotvault-dev`). The default `docker compose up -d` does not include it.

## Playwright Verification Flow

Run once, interactively from this session. Not committed.

### Preconditions

- `docker compose --profile jfrog up -d` — all five services (vault, dex, vault-init, artifactory, artifactory-init) healthy.
- `go run ./cmd/dotvault run --config config.dev.yaml` — daemon running on `127.0.0.1:9000`.
- `/etc/hosts` entry for `dex` already exists (prerequisite of the existing dev setup).

### Steps

1. **Dotvault login.** Playwright MCP navigates to `http://127.0.0.1:9000`, clicks "Sign in with OIDC", which redirects to Dex. Dex's mockCallback connector auto-approves. Returns to dotvault, lands on the enrolment page.
2. **Start JFrog enrolment.** Playwright clicks `Start` on the JFrog card. The web UI displays the last-4-chars confirmation code and the Artifactory login URL `http://127.0.0.1:8082/ui/login?jfClientSession=<uuid>&jfClientName=JFrog-CLI&jfClientCode=1`. Both captured from the DOM.
3. **Artifactory login** (same browser context). Playwright navigates to the captured URL, signs in as `admin` / `dotvault-dev`. The Artifactory UI surfaces the "Confirm you're authorizing JFrog-CLI" screen showing the expected last-4 chars. Playwright clicks `Accept`.
4. **Token poll.** dotvault's background poll against `GET /access/api/v2/authentication/jfrog_client_login/token/<uuid>` flips from 400 to 200. The enrolment page transitions to `complete`.
5. **Verify.** Three independent checks:
   - `docker exec dotvault-vault vault kv get kv/users/gary/jfrog` — contains `access_token`, `refresh_token`, `token_type=Bearer`, `expires_in`, `url=http://127.0.0.1:8082`, `server_id=default-server`, `user=admin`.
   - `cat ~/tmp/.jfrog/jfrog-cli.conf.v6` — valid JSON matching the template, with the real access token embedded.
   - `curl -H "Authorization: Bearer <token>" http://127.0.0.1:8082/artifactory/api/system/ping` — returns `OK`, proving the minted token is genuinely accepted by the live Artifactory.

## Error Handling

- **Artifactory fails to boot within 180 s:** abort, surface `docker compose logs artifactory`, do not proceed.
- **`artifactory-init` fails the admin-reset:** hard failure (any status other than 200 or initial 401). Log the response body.
- **Playwright selector drift** (Artifactory UI version differences on the confirmation screen): screenshot the DOM, report, and ask the user rather than guessing. Do not auto-retry with different selectors.
- **Token poll timeout (5 min default in the engine):** the engine already returns a timeout error with the elapsed duration; the web UI shows the failure and the enrolment stays `pending`.

## File Changes

| File | Change |
|------|--------|
| `docker-compose.yaml` | Add `artifactory` + `artifactory-init` services under `profiles: ["jfrog"]`; add `artifactory-data` named volume |
| `config.dev.yaml` | Point `enrolments.jfrog.settings.url` at `http://127.0.0.1:8082` |
| `CLAUDE.md` | One-sentence note in Local Development about the `--profile jfrog` variant |

No Go code changes. No test changes.

## Out of Scope / Follow-Ups

- A committed `test/e2e/` Playwright harness — can be added later if the engine's behaviour becomes load-bearing enough to need regression protection.
- Wiring Artifactory into `.claude/launch.json` for Claude Code Desktop — the profile already lets you opt in by hand; adding it to the launch config would make the Preview integration always pay the 4 GB cost.
- A Makefile helper (`make up-jfrog`, etc.). The compose profile invocation is short enough that an additional alias is noise.
