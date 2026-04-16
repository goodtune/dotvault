# Local Artifactory E2E Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Status (2026-04-17):** Historical planning artifact — preserved for
> audit trail. **What actually shipped differs from this plan**:
>
> - The `artifactory-init` sidecar was dropped mid-execution because
>   rotating the admin password via REST was unreliable across Artifactory
>   UI versions. The default `admin` / `password` credentials are kept
>   as-is; Artifactory forces a first-login change that happens naturally
>   during the Playwright verification flow.
> - A `artifactory-db` Postgres sidecar was added (not in the original
>   plan) because Artifactory 7.78+ dropped the embedded Derby database
>   and fails to start without an external database.
> - `JF_SHARED_SECURITY_MASTERKEY` and `JF_SHARED_SECURITY_JOINKEY` are
>   pinned to deterministic hex fixtures; auto-generation is unreliable
>   on Docker Desktop volumes.
> - The `8082:8082` port mapping was tightened to `127.0.0.1:8082:8082`
>   after a Copilot review noted the dev-only credentials + fixed keys
>   would otherwise be reachable from the LAN.
>
> Refer to the current `docker-compose.yaml` and the companion spec
> (`docs/superpowers/specs/2026-04-16-artifactory-e2e-design.md`, which
> has been updated to match what shipped) for the authoritative setup.
> The step-by-step below is left intact so the decision history is not
> lost.

**Goal:** Add an opt-in local Artifactory JCR to `docker-compose.yaml` so the `JFrogEngine` can be exercised end-to-end, then verify the full browser-based enrolment flow once via the Playwright MCP.

**Architecture:** Two new services (`artifactory`, `artifactory-init`) gated by `profiles: ["jfrog"]` so plain `docker compose up -d` stays lean. `artifactory-init` mirrors the existing `vault-init` pattern: waits for the healthcheck, then uses the default `admin/password` credentials to reset the admin password to `dotvault-dev` via REST, idempotently. No Go code changes.

**Tech Stack:** Docker Compose v2 profiles, `releases-docker.jfrog.io/jfrog/artifactory-jcr:7.98.9` (multi-arch, arm64 native on Apple Silicon), the existing dotvault Go daemon + Preact web UI, and the Playwright MCP for one-shot verification.

**Spec:** `docs/superpowers/specs/2026-04-16-artifactory-e2e-design.md`

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `docker-compose.yaml` | Dev stack orchestration | Add `artifactory` + `artifactory-init` services under `profiles: ["jfrog"]`; add `artifactory-data` named volume |
| `config.dev.yaml` | dotvault dev config | Point `enrolments.jfrog.settings.url` at `http://127.0.0.1:8082` |
| `CLAUDE.md` | Contributor reference | One-sentence Local Development note about `docker compose --profile jfrog up -d` |

No Go source, no tests, no docs under `docs/services/` change. The Playwright verification in Task 4 produces no committed artefact.

---

## Task 1: Add Artifactory services to docker-compose

**Files:**
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Read the current docker-compose.yaml**

Check existing structure, confirm the `volumes:` block at the bottom and the `vault-init` service pattern you're mirroring.

- [ ] **Step 2: Add the `artifactory` service**

Insert after the existing `vault-init` service block, before the `volumes:` block at the bottom of the file. The service must be tagged with the `jfrog` profile.

```yaml
  artifactory:
    image: releases-docker.jfrog.io/jfrog/artifactory-jcr:7.98.9
    container_name: dotvault-artifactory
    profiles: ["jfrog"]
    ports:
      - "8082:8082"
    volumes:
      - artifactory-data:/var/opt/jfrog/artifactory
    mem_limit: 4g
    ulimits:
      nproc: 65535
      nofile:
        soft: 32000
        hard: 40000
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:8082/artifactory/api/system/ping >/dev/null"]
      interval: 5s
      timeout: 3s
      retries: 30
      start_period: 120s
```

- [ ] **Step 3: Add the `artifactory-init` service**

Insert immediately after the `artifactory` service block.

```yaml
  artifactory-init:
    image: alpine:3.20
    container_name: dotvault-artifactory-init
    profiles: ["jfrog"]
    depends_on:
      artifactory:
        condition: service_healthy
    entrypoint: /bin/sh
    command:
      - -c
      - |
        set -eu
        apk add --no-cache curl >/dev/null

        echo "==> Checking if admin/password still works..."
        code=$$(curl -s -o /dev/null -w '%{http_code}' \
          -u admin:password \
          http://artifactory:8082/artifactory/api/system/ping || true)

        if [ "$$code" = "401" ] || [ "$$code" = "403" ]; then
          echo "==> Admin already rotated (got HTTP $$code), nothing to do."
          exit 0
        fi

        if [ "$$code" != "200" ]; then
          echo "==> Unexpected ping status $$code with default creds; aborting." >&2
          exit 1
        fi

        echo "==> Rotating admin password to dev fixture..."
        status=$$(curl -s -o /tmp/resp -w '%{http_code}' \
          -u admin:password \
          -H 'Content-Type: application/json' \
          -X POST \
          -d '{"userName":"admin","oldPassword":"password","newPassword1":"dotvault-dev","newPassword2":"dotvault-dev"}' \
          http://artifactory:8082/artifactory/api/security/users/authorization/changePassword)

        if [ "$$status" != "200" ] && [ "$$status" != "204" ]; then
          echo "==> changePassword failed (HTTP $$status):" >&2
          cat /tmp/resp >&2 || true
          exit 1
        fi

        echo "==> admin password set to 'dotvault-dev'."
```

- [ ] **Step 4: Add the `artifactory-data` volume**

Extend the existing `volumes:` block at the bottom of the file.

```yaml
volumes:
  vault-data:
  dex-data:
  artifactory-data:
```

- [ ] **Step 5: Validate docker-compose syntax**

Run: `docker compose config --profile jfrog >/dev/null`
Expected: exits 0, no warnings about unknown keys.

- [ ] **Step 6: Verify the profile gate**

Run: `docker compose config --services | sort`
Expected output (plain `up` does NOT surface the jfrog services):
```
dex
vault
vault-init
```

Run: `docker compose --profile jfrog config --services | sort`
Expected:
```
artifactory
artifactory-init
dex
vault
vault-init
```

- [ ] **Step 7: Bring the stack up**

Run: `docker compose --profile jfrog up -d`

- [ ] **Step 8: Wait for Artifactory to be healthy**

Run: `docker compose --profile jfrog ps artifactory`
Expected: `STATUS` column eventually shows `healthy` (allow up to 3 minutes on first boot — the image is ~2 GB and JFrog seeds its internal Derby DB on first start). Use `watch -n 5 'docker compose --profile jfrog ps artifactory'` or re-run until healthy.

- [ ] **Step 9: Confirm `artifactory-init` exited cleanly**

Run: `docker compose --profile jfrog logs artifactory-init`
Expected: ends with `==> admin password set to 'dotvault-dev'.`

Run: `docker inspect --format='{{.State.ExitCode}}' dotvault-artifactory-init`
Expected: `0`

- [ ] **Step 10: Sanity-check the new admin password**

Run:
```bash
curl -sS -u admin:dotvault-dev http://127.0.0.1:8082/artifactory/api/system/ping
```
Expected: `OK`

Run (negative check — old creds must be rejected):
```bash
curl -s -o /dev/null -w '%{http_code}\n' -u admin:password \
  http://127.0.0.1:8082/artifactory/api/system/ping
```
Expected: `401` or `403`.

- [ ] **Step 11: Confirm the web-login endpoint is live**

Run:
```bash
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"session":"00000000-0000-4000-8000-000000000000"}' \
  -w '\nHTTP %{http_code}\n' \
  http://127.0.0.1:8082/access/api/v2/authentication/jfrog_client_login/request
```
Expected: `HTTP 200` in the trailing line. Any 404 means the Access service version is too old or the image mismatches the spec — stop and report.

- [ ] **Step 12: Test idempotency**

Run:
```bash
docker compose --profile jfrog rm -fsv artifactory-init
docker compose --profile jfrog up -d artifactory-init
docker compose --profile jfrog logs artifactory-init --tail=10
```
Expected: logs contain `==> Admin already rotated (got HTTP 401), nothing to do.` and exit code `0`.

- [ ] **Step 13: Commit**

```bash
git add docker-compose.yaml
git commit -m "$(cat <<'EOF'
Add opt-in Artifactory JCR to dev compose stack

Two new services under profiles: [jfrog] so plain `docker compose up -d`
is unaffected. artifactory-init mirrors vault-init: waits for the
healthcheck, then rotates the default admin password to dotvault-dev
via REST, idempotently.

Used to exercise the JFrogEngine end-to-end against a real Access
service. See docs/superpowers/specs/2026-04-16-artifactory-e2e-design.md.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Point dev dotvault at the local Artifactory

**Files:**
- Modify: `config.dev.yaml`

- [ ] **Step 1: Edit `config.dev.yaml`**

Replace the `url:` line under `enrolments.jfrog.settings` with the local URL. The full `enrolments` block should read:

```yaml
enrolments:
  gh:
    engine: github
  ssh:
    engine: ssh
    settings:
      passphrase: "recommended"
  jfrog:
    engine: jfrog
    settings:
      # Local Artifactory JCR from `docker compose --profile jfrog`.
      url: "http://127.0.0.1:8082"
```

- [ ] **Step 2: Validate config loads cleanly**

Run: `go run ./cmd/dotvault run --config config.dev.yaml --dry-run --once 2>&1 | head -40`
Expected: the daemon starts up, logs enrolment engines (including `jfrog`), exits after the one-shot sync without config-validation errors. (The sync itself may succeed or warn depending on Vault state — we're only checking config parse, so ignore errors about missing secrets.)

- [ ] **Step 3: Commit**

```bash
git add config.dev.yaml
git commit -m "$(cat <<'EOF'
Point dev JFrog enrolment at local Artifactory

Matches the new docker-compose profile: [jfrog] service on port 8082.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Document the opt-in profile in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md` (Local Development section)

- [ ] **Step 1: Locate the Local Development section**

Run: `grep -n '^## Local Development' CLAUDE.md`
Note the line number.

- [ ] **Step 2: Add a one-sentence note**

Insert the following paragraph immediately after the existing paragraph that ends with `…web UI is configured on port 9000 (\`127.0.0.1:9000\`) in \`config.dev.yaml\` to avoid conflict.` (i.e. right before the `The vault-init container seeds…` paragraph):

```markdown
JFrog enrolment testing is opt-in: `docker compose --profile jfrog up -d` additionally starts a local Artifactory JCR on port 8082 (admin password `dotvault-dev`, credentials rotated on first boot by the `artifactory-init` sidecar). Plain `docker compose up -d` does not include it. Allow ~2 minutes on the first cold start for JFrog to seed its internal database.
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
Document opt-in JFrog profile in Local Development

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Playwright E2E verification (one-shot, not committed)

**Files:** none modified; this task produces evidence, not artefacts.

**Prerequisites:**
- Tasks 1–3 committed.
- `docker compose --profile jfrog up -d` running, all services healthy (re-check `docker compose --profile jfrog ps`).
- No existing dotvault daemon on `:9000` (check `lsof -iTCP:9000 -sTCP:LISTEN` — kill any stray `dotvault` process).
- `~/tmp/.jfrog/` does not exist yet, so the sync definitively writes a fresh file (run `rm -rf ~/tmp/.jfrog`).
- `/etc/hosts` has the existing `127.0.0.1 dex` entry.

- [ ] **Step 1: Wipe any stale jfrog secret in Vault**

Run:
```bash
ROOT_TOKEN=$(docker exec dotvault-vault cat /vault/data/root-token)
docker exec -e VAULT_TOKEN="$ROOT_TOKEN" dotvault-vault \
  vault kv delete kv/users/gary/jfrog 2>/dev/null || true
docker exec -e VAULT_TOKEN="$ROOT_TOKEN" dotvault-vault \
  vault kv metadata delete kv/users/gary/jfrog 2>/dev/null || true
```
Expected: either `Success!` or a "secret not found" message — both are fine.

- [ ] **Step 2: Start the daemon in the background**

Run:
```bash
go run ./cmd/dotvault run --config config.dev.yaml --log-level debug \
  > /tmp/dotvault.log 2>&1 &
echo $! > /tmp/dotvault.pid
```

Then: `sleep 3 && curl -fsS http://127.0.0.1:9000/api/v1/status >/dev/null && echo "daemon up"`
Expected: `daemon up`.

- [ ] **Step 3: Navigate to the dotvault UI via Playwright MCP**

Use `mcp__plugin_playwright_playwright__browser_navigate` with `url: http://127.0.0.1:9000`.

Then `mcp__plugin_playwright_playwright__browser_snapshot` to capture the DOM — expect the dotvault sign-in page.

- [ ] **Step 4: Complete OIDC sign-in via Dex**

Click the "Sign in with OIDC" button (use `browser_click` with the ref from the snapshot).

Dex's mockCallback connector auto-approves; the browser will redirect through `http://dex:5556/...` and land back on dotvault at the enrolment page. Re-snapshot to confirm the enrolment cards (`gh`, `ssh`, `jfrog`) are visible.

- [ ] **Step 5: Start the JFrog enrolment**

Click the `Start` button on the JFrog card.

Snapshot the page and capture two values from the DOM:
- The displayed confirmation code (last 4 chars of the UUID).
- The Artifactory login URL (should match `http://127.0.0.1:8082/ui/login?jfClientSession=<uuid>&jfClientName=JFrog-CLI&jfClientCode=1`).

Record both — you will need them in Step 7.

- [ ] **Step 6: Navigate the same browser context to Artifactory login**

Use `browser_navigate` with the captured URL from Step 5. Artifactory's sign-in form appears.

Fill in `admin` / `dotvault-dev` and submit. On first real login Artifactory may prompt to change the password again; if so, accept the current one as the new one (or dismiss if the UI allows). Expect to land on the "Confirm authorization for JFrog-CLI" screen showing the same last-4 chars captured in Step 5.

- [ ] **Step 7: Verify the confirmation code matches and accept**

Compare the last-4 chars displayed by Artifactory against the value captured in Step 5. They MUST match. If they don't, stop — something is wrong with session plumbing.

Click `Accept` (or the button labeled to authorise the client).

- [ ] **Step 8: Wait for dotvault to finish polling**

Navigate back to `http://127.0.0.1:9000`, snapshot. The JFrog card should transition to `complete`. If still `pending`, wait 5 seconds and re-snapshot (the engine polls every 3 s; max 5 min).

- [ ] **Step 9: Verify the Vault secret**

Run:
```bash
ROOT_TOKEN=$(docker exec dotvault-vault cat /vault/data/root-token)
docker exec -e VAULT_TOKEN="$ROOT_TOKEN" dotvault-vault \
  vault kv get -format=json kv/users/gary/jfrog | \
  python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["data"]; print(json.dumps({k: (v[:20]+"..." if k in ("access_token","refresh_token") else v) for k,v in d.items()}, indent=2))'
```

Expected — every one of these fields present:
- `access_token` (JWT-looking string)
- `refresh_token` (non-empty)
- `token_type`: `Bearer`
- `expires_in` (a numeric string like `"31536000"`)
- `url`: `http://127.0.0.1:8082`
- `server_id`: `default-server` (because the hostname is an IP)
- `user`: `admin`

- [ ] **Step 10: Verify the rendered config file**

Run: `cat ~/tmp/.jfrog/jfrog-cli.conf.v6 | python3 -m json.tool`
Expected: valid JSON, `servers[0].serverId == "default-server"`, `servers[0].url == "http://127.0.0.1:8082/"`, `servers[0].user == "admin"`, `servers[0].accessToken` is a non-empty string matching the Vault `access_token`.

- [ ] **Step 11: Prove the minted token actually works**

Run:
```bash
TOKEN=$(python3 -c 'import json; print(json.load(open("/Users/gary/tmp/.jfrog/jfrog-cli.conf.v6"))["servers"][0]["accessToken"])')
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8082/artifactory/api/system/ping
```
Expected: `OK`.

- [ ] **Step 12: Tear down**

Run:
```bash
kill "$(cat /tmp/dotvault.pid)" && rm -f /tmp/dotvault.pid
```

Leave the docker compose stack up — the user may want to inspect it. Do NOT `docker compose down` unless the user asks.

- [ ] **Step 13: Report evidence**

Summarise to the user:
- The Vault fields captured in Step 9 (with tokens truncated).
- The rendered `jfrog-cli.conf.v6` `user` / `url` / `serverId`.
- The Step 11 `curl` result proving the token is live.

This is the terminal state. No commit — Task 4 is verification, not code.

---

## Self-Review Notes

- **Spec coverage:** Architecture (Task 1), dotvault config (Task 2), CLAUDE.md (Task 3), Playwright flow (Task 4). All spec sections covered.
- **Placeholders:** none — every command, env var, expected output, and DOM interaction is spelled out.
- **Type/name consistency:** service names (`artifactory`, `artifactory-init`), container names (`dotvault-artifactory`, `dotvault-artifactory-init`), volume (`artifactory-data`), admin password (`dotvault-dev`), image tag (`7.98.9`), port (`8082`) all consistent across tasks.
- **Risk flagged:** Step 1.11 (`jfrog_client_login/request` live check) and Step 4.7 (confirmation-code match) are explicit fail-early gates for the two assumptions most likely to break: image version supports the endpoint, and the session plumbing round-trips correctly.
