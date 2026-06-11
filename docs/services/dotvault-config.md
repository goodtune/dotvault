# dotvault-config Service

`dotvault-config` is the server side of [remote configuration](../configuration/remote-config.md): a small HTTP service that composes **layered partial configuration documents** and serves them to dotvault daemons. A global organisation runs one instance and delivers per-region rules and enrolments — a user in the Sydney office sees Sydney's enrolments, a user in two offices sees the union — without touching the locally managed base config on any machine.

The service ships as its own binary (`dotvault-config`, linux and darwin) in every release alongside the dotvault client.

## How composition works

Configuration layers are [partial config documents](../configuration/remote-config.md#what-the-service-can-and-cannot-deliver) — `rules`, `enrolments`, and `sync` only — stored under canonical keys and folded in a fixed order:

```
global  →  os/<os>  →  group/<g> (each, sorted)  →  user/<user>
```

Later layers win: a same-named rule replaces the earlier one wholesale (keeping its position), an enrolment entry replaces by map key, and a non-empty `sync.interval` overrides. This is the *same merge* the client applies onto its local base — the service and the client share one merge implementation, so what you compose is exactly what merges.

Missing layers are skipped silently: an unknown user composes to `global` + `os/<os>`, which is valid. A present-but-invalid layer is **never** silently dropped — the request fails with a `500` naming the layer key, because serving a silently wrong composition would be worse than failing.

Group order is sorted for determinism: the composed bytes are stable, so the document's `ETag` (a sha256 of the bytes) is stable, and unchanged configs cost a single `304` round-trip.

## HTTP API

| Route | Behaviour |
|-------|-----------|
| `GET /v1/config` | Requires the `X-Dotvault-OS` and `X-Dotvault-User` headers (`400` otherwise). Composes the document for that identity; honours `If-None-Match` with a `304`; otherwise `200` with `Content-Type: application/yaml`, `ETag`, and `Cache-Control: no-cache`. |
| `GET /healthz` | Liveness — `200` while the process serves. |
| `GET /readyz` | Readiness — `200` once the storage backend answers a ping, `503` otherwise. |

There is **no client authentication**: configuration is not secret, and the dimension headers are client-asserted and spoofable by design — anyone may fetch anyone's document, so **layers must never contain secret values**. TLS provides integrity, not confidentiality: terminate it at your ingress, or configure the service's own listener (`tls.cert_file` / `tls.key_file`). Unlike the daemon's web UI there is no loopback-binding restriction — this is a deployable network service.

## Configuration

The service takes a single YAML file via `--config`:

```yaml
listen: "0.0.0.0:9100"

# Optional: terminate TLS on the service's own listener. Omit when an
# ingress terminates in front of the service.
# tls:
#   cert_file: /etc/dotvault-config/tls.crt
#   key_file: /etc/dotvault-config/tls.key

store:
  driver: vault            # vault | sqlite
  vault:
    address: https://vault.example.com
    mount: kv              # KVv2 mount (default "kv")
    path: dotvault-config  # base path under the mount (default "dotvault-config")
    auth: kubernetes       # token | kubernetes
    kubernetes:
      mount: kubernetes    # auth mount (default "kubernetes")
      role: dotvault-config
      # jwt_path defaults to the projected service-account token path

groups:
  source: ldap             # static | ldap
  ttl: "5m"                # resolver cache TTL (default 1m; "0" disables)
  ldap:
    url: ldaps://ldap.example.com
    bind_dn: cn=svc-dotvault,ou=services,dc=example,dc=com
    bind_password_file: /run/secrets/ldap-password
    base_dn: ou=groups,dc=example,dc=com
    filter: "(&(objectClass=groupOfNames)(member=uid=%s,ou=people,dc=example,dc=com))"
    attribute: cn
```

Unknown keys in the file are a hard error, so a typo'd key fails the start instead of silently doing nothing.

### Storage backends

- **Vault KVv2** (production) — layer documents live at `<mount>/data/<path>/layers/<key>` (single `doc` field) and static group membership at `<mount>/data/<path>/groups/<user>`. Auth is `token` (dev; falls back to the `VAULT_TOKEN` environment variable) or `kubernetes` — the service-account JWT is **re-read from disk on every login**, so projected-token rotation needs no restart, and the service re-logs-in on a `403`.
- **SQLite** (development and tests) — a single file (or `:memory:`), pure Go, no infrastructure.

The service authenticates only to its storage backend; it never holds user credentials.

### Group resolution

- **`static`** — membership maps stored in the backend (published from a `groups.yaml`, see seeding below). Right for dev, tests, and small fleets.
- **`ldap`** — the directory-driven case. Each lookup binds (optionally) and searches `base_dn` with `filter`, substituting the **escaped** username for `%s`; each matching entry contributes its `attribute` value (default `cn`) as a group name. Use `bind_password_file` rather than `bind_password` so the secret stays out of the config file; the file is re-read on every lookup.

Both resolvers sit behind a TTL cache (`groups.ttl`) so a burst of requests for one user costs one directory lookup. An unknown user resolves to *no groups*, not an error.

## Seeding: layers as code

`dotvault-config seed` publishes a directory of layer YAMLs into the configured backend:

```
layers/
├── global.yaml
├── groups.yaml          # optional static membership: user → [groups]
├── os/
│   ├── linux.yaml
│   └── windows.yaml
├── group/
│   ├── sydney.yaml
│   └── newyork.yaml
└── user/
    └── alice.yaml
```

```sh
dotvault-config seed --config configsvc.yaml --dir layers/
```

Every document is validated **before any write** — the same parse and validation the daemon applies, including the rejection of static sections (`vault`, `web`, `agent`, `observability`, …) that must never be delivered remotely. An invalid layer aborts the whole publish with nothing written; writes are idempotent puts, so re-running a publish interrupted by a backend failure converges. Stray files and unrecognised subdirectories are errors, catching the typo'd `os.yaml` that would otherwise silently not be served.

This gives you config-as-code: keep the layer tree in a git repository, review changes as pull requests, and have CI run `seed` against the production backend on merge.

## Administration

With `admin.enabled: true` the service exposes a management API under `/v1/admin/` and a web UI at `/admin/`, covering every axis: layers (all four kinds), static group membership, and service accounts. The UI is a thin shell over the API — anything it can do, an automation client (e.g. a Terraform provider) can do against the same routes.

```yaml
admin:
  enabled: true
  group: dotvault-admins       # admins must hold this group (via the groups resolver)
  session_ttl: "12h"
  ldap:                        # human username/password login
    url: ldaps://ldap.example.com
    user_dn_template: "uid=%s,ou=people,dc=example,dc=com"
    # or search-then-bind:
    # bind_dn: cn=svc,ou=services,dc=example,dc=com
    # bind_password_file: /run/secrets/ldap-password
    # user_search_base_dn: ou=people,dc=example,dc=com
    # user_search_filter: "(uid=%s)"
  mtls:                        # service-account listener (mTLS only)
    listen: "0.0.0.0:9101"
    ca_cert: /etc/dotvault-config/svc-ca.pem
    cert_file: /etc/dotvault-config/tls.crt
    key_file: /etc/dotvault-config/tls.key
```

### Human admins

`POST /v1/admin/auth/login` binds against the directory **as the user** (DN template or search-then-bind) and then requires membership of `admin.group`, resolved through the same groups resolver that drives layer composition — admins are declared in the same membership source as everything else. Sessions are cookies (HttpOnly, SameSite=Strict, Secure over TLS); mutating requests need a one-time CSRF token from `GET /v1/admin/csrf` in the `X-CSRF-Token` header.

### Service accounts

Service accounts are local identities defined in the storage layer — not directory users — for automation such as CI publishing or a Terraform provider. They have **no password**: the only way to authenticate as one is a mutual-TLS client certificate on the dedicated `admin.mtls.listen` listener, and the expectation is that **Vault mints the certificates** via a dedicated PKI secrets engine.

What makes "only authorized certificates" hold:

- the listener trusts **only** `admin.mtls.ca_cert` — point it at a PKI intermediate dedicated to dotvault-config service accounts, never a general corporate CA, so the Vault role's issuance policy *is* the access policy (and Vault's audit log is the issuance trail);
- the certificate's CN must name a **registered, enabled** service account — disabling or deleting the account in the admin API revokes access immediately, regardless of certificate lifetime;
- keep certificates **short-lived** (Vault role `max_ttl` ≤ 72h) instead of running CRL/OCSP infrastructure;
- the `clientAuth` EKU is enforced during the handshake, so a server certificate from the same CA cannot be replayed as a client credential.

A suitable Vault role looks like:

```sh
vault secrets enable -path=dotvault-config-pki pki
vault write dotvault-config-pki/roles/service-account \
  allow_any_name=false allow_bare_domains=true allow_subdomains=false \
  enforce_hostnames=false allowed_domains="terraform,ci-publisher" \
  client_flag=true server_flag=false max_ttl=72h ttl=24h
```

and a client authenticates with `curl --cert sa.pem --key sa-key.pem --cacert service-ca.pem https://config.example.com:9101/v1/admin/...`.

### Management API

| Route | Behaviour |
|-------|-----------|
| `POST /v1/admin/auth/login`, `POST /v1/admin/auth/logout`, `GET /v1/admin/csrf`, `GET /v1/admin/whoami` | session lifecycle and caller identity |
| `GET /v1/admin/layers?prefix=` · `GET/PUT/DELETE /v1/admin/layers/{key}` | layer CRUD; PUT validates with the daemon's own parser and returns the validation error as the 400 body |
| `GET /v1/admin/groups` · `GET/PUT/DELETE /v1/admin/groups/{user}` | static membership CRUD (`{"groups": [...]}`) |
| `GET /v1/admin/service-accounts` · `GET/PUT/DELETE /v1/admin/service-accounts/{name}` | service-account CRUD; PUT is an upsert preserving `created_at` |
| `GET /v1/admin/preview?os=&user=&groups=` | the composed document an identity would receive (`groups` overrides the resolver) |

Every `PUT` is an idempotent upsert and every mutation is audit-logged with the acting identity — the contract a configuration-as-code Terraform provider builds on directly.

### Dev loop

`docker compose --profile ldap up -d` starts a tiny glauth directory (sign in to `http://127.0.0.1:9100/admin/` as `admin`/`password`; `bob`/`password` exercises the not-an-admin 403). `dev/mint-svc-cert.sh` provisions the service-account PKI from the dev Vault into `dev/pki/` — enable the `admin.mtls` block in `configsvc.dev.yaml` afterwards to exercise the certificate path end to end.

## Debugging a composition

`compose` renders what a given identity would receive, offline:

```sh
dotvault-config compose --config configsvc.yaml --os linux --user alice
dotvault-config compose --config configsvc.yaml --os linux --user alice --groups sydney,newyork
```

The document goes to stdout; the layer order and ETag go to stderr. `--groups` overrides the resolver, which is useful for answering "what *would* she get if she were in this group" without touching the directory.

## Local development

The repository wires a complete dev loop (see `configsvc.dev.yaml` and the fixtures under `dev/remote-layers/`):

```sh
go run ./cmd/dotvault-config serve --config configsvc.dev.yaml --seed dev/remote-layers
```

`--seed` is a dev convenience that publishes the layer directory on startup. `config.dev.yaml` points the daemon at `http://127.0.0.1:9100/v1/config` (loopback, so plain HTTP is allowed); add your OS username to `dev/remote-layers/groups.yaml` to see group layers in your own composed document, and inspect the result with:

```sh
curl -H 'X-Dotvault-OS: linux' -H "X-Dotvault-User: $USER" http://127.0.0.1:9100/v1/config
```
