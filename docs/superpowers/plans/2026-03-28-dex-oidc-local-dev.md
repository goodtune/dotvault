# Dex OIDC Local Dev Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Dex as a local OIDC identity provider so the web-based OIDC auth flow can be tested end-to-end via `docker compose up`.

**Architecture:** Dex runs alongside Vault in docker-compose with a mockCallback connector. vault-init configures Vault's OIDC auth method to use Dex. The dotvault web UI handles the browser-based login flow unchanged.

**Tech Stack:** Dex (dexidp/dex Docker image), HashiCorp Vault OIDC auth method, docker-compose

**Networking note:** Dex's issuer is `http://dex:5556/dex`. Docker DNS resolves `dex` inside containers. The host machine needs `127.0.0.1 dex` in `/etc/hosts` so the browser can reach Dex's login page (Dex port 5556 is mapped to the host).

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `dex.yaml` | Create | Dex config: issuer, static client, static password connector |
| `docker-compose.yaml` | Modify | Add Dex service, update vault-init to configure OIDC auth |
| `/Library/Application Support/dotvault/config.yaml` | Modify | Enable web UI on port 8250 |

No application code changes.

---

### Task 1: Create Dex configuration

**Files:**
- Create: `dex.yaml`

- [ ] **Step 1: Create `dex.yaml`**

```yaml
issuer: http://dex:5556/dex

storage:
  type: sqlite3
  config:
    file: /var/dex/dex.db

web:
  http: 0.0.0.0:5556

staticClients:
  - id: dotvault
    secret: dotvault-dev-secret
    name: dotvault
    redirectURIs:
      - http://127.0.0.1:8250/auth/callback

connectors:
  - type: mockCallback
    id: mock
    name: Login
```

Note: `mockCallback` connector auto-approves login with a test email, no credentials needed. This is the fastest path for dev iteration.

- [ ] **Step 2: Commit**

```bash
git add dex.yaml
git commit -m "Add Dex configuration for local OIDC dev testing"
```

---

### Task 2: Add Dex service to docker-compose

**Files:**
- Modify: `docker-compose.yaml`

- [ ] **Step 1: Add Dex service**

Add after the `vault` service block (before `vault-init`):

```yaml
  dex:
    image: dexidp/dex:v2.41.1
    container_name: dotvault-dex
    ports:
      - "5556:5556"
    volumes:
      - ./dex.yaml:/etc/dex/config.yaml:ro
      - dex-data:/var/dex
    command: ["dex", "serve", "/etc/dex/config.yaml"]
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:5556/dex/.well-known/openid-configuration"]
      interval: 2s
      timeout: 3s
      retries: 10
      start_period: 5s
```

- [ ] **Step 2: Add `dex-data` volume**

Add to the `volumes:` section at the bottom:

```yaml
  dex-data:
```

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yaml
git commit -m "Add Dex service to docker-compose"
```

---

### Task 3: Update vault-init to configure OIDC auth

**Files:**
- Modify: `docker-compose.yaml` (vault-init service)

- [ ] **Step 1: Add Dex to vault-init depends_on**

Update vault-init's `depends_on` to wait for both Vault and Dex:

```yaml
    depends_on:
      vault:
        condition: service_started
      dex:
        condition: service_healthy
```

- [ ] **Step 2: Add OIDC auth configuration to vault-init command**

Append after the `echo "==> Writing sample secrets..."` block and the sample `vault kv put` commands (before the root token write):

```shell
        echo "==> Enabling OIDC auth method..."
        vault auth enable oidc 2>/dev/null || true

        echo "==> Configuring OIDC auth with Dex..."
        vault write auth/oidc/config \
          oidc_discovery_url="http://dex:5556/dex" \
          oidc_client_id="dotvault" \
          oidc_client_secret="dotvault-dev-secret" \
          default_role="default"

        echo "==> Creating OIDC default role..."
        vault write auth/oidc/role/default \
          bound_audiences="dotvault" \
          allowed_redirect_uris="http://127.0.0.1:8250/auth/callback" \
          user_claim="email" \
          token_policies="dotvault"
```

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yaml
git commit -m "Configure Vault OIDC auth method with Dex in vault-init"
```

---

### Task 4: Update local system config

**Files:**
- Modify: `/Library/Application Support/dotvault/config.yaml`

- [ ] **Step 1: Add web UI config**

Add `web` section to the config:

```yaml
web:
  enabled: true
  listen: "127.0.0.1:8250"
```

The full file should be:

```yaml
vault:
  address: "http://localhost:8200"
  auth_method: "oidc"

web:
  enabled: true
  listen: "127.0.0.1:8250"

sync:
  interval: "15m"

rules:
  - name: gh
    vault_key: "gh"
    target:
      path: "~/.config/gh/hosts.yml"
      format: yaml
      template: |
        github.com:
          oauth_token: "{{.token}}"
```

- [ ] **Step 2: No commit** (system config is outside the repo)

---

### Task 5: Verify end-to-end flow

- [ ] **Step 1: Add `/etc/hosts` entry (one-time)**

Verify `dex` resolves on the host:

```bash
grep -q 'dex' /etc/hosts || echo "Add '127.0.0.1 dex' to /etc/hosts (requires sudo)"
```

- [ ] **Step 2: Start services**

```bash
docker compose down -v && docker compose up -d
```

Wait for vault-init to complete:

```bash
docker compose logs -f vault-init
```

Expected: logs ending with `==> Vault ready` after OIDC configuration messages.

- [ ] **Step 3: Run dotvault**

```bash
go run ./cmd/dotvault
```

Expected:
1. Browser opens to `http://127.0.0.1:8250/auth/start`
2. Redirected to Dex at `http://dex:5556/dex/auth/...`
3. Dex mock callback auto-approves (or shows Grant Access button)
4. Redirected to `http://127.0.0.1:8250/auth/callback`
5. "Authentication successful" page shown
6. Terminal shows `OIDC authentication successful via web UI` followed by `starting dotvault daemon`
