# dotvault-config Administration Design

## Overview

The remote-configuration design (2026-06-10) shipped the dotvault-config service with exactly two write paths: `dotvault-config seed` (config-as-code from a layer directory) and direct store access. This design adds the **administration surface**: a JSON management API under `/v1/admin/` and an embedded web UI at `/admin/`, so every dimension of the configuration — layers across all four axes, static group membership, and the new service accounts — is constructible interactively and programmatically.

Following the ghp prior art: a single Go binary, an embedded dashboard, and an **API-first contract** — the UI is a thin shell over the same routes an automation client uses, so a configuration-as-code Terraform provider can be built directly on the API with no UI-only capabilities to chase.

## Authentication model

Two principal kinds, deliberately asymmetric:

| Principal | Authentication | Authorisation |
|-----------|----------------|---------------|
| Human admin | LDAP username/password bind (`POST /v1/admin/auth/login` → session cookie) | membership of `admin.group`, resolved through the service's **configured groups resolver** |
| Service account | mTLS client certificate on a dedicated listener — no passwords, ever | certificate CN must name a **registered, enabled** service account in the store |

### Human admins: LDAP + admin group

The login handler binds *as the user* against the directory in `admin.ldap` — either a `user_dn_template` (`uid=%s,ou=people,…`, username DN-escaped) or a search-then-bind (`bind_dn` service credential, `user_search_base_dn` + `user_search_filter`, exactly one entry required). An empty username or password is rejected before any network I/O: an LDAP bind with a DN and no password is an *anonymous* bind that many servers accept — the classic login bypass.

Group membership for the admin check goes through the **configured groups resolver** (static or LDAP), not a separate lookup: admins are declared in the same membership source that drives layer composition. All authentication failures collapse into one "invalid username or password" sentinel so the endpoint cannot be used to enumerate users; a directory outage is a distinguishable 502. Login attempts are rate-limited per client address (a fixed window, deliberately primitive — it bounds the online guessing rate against the directory; it is not a lockout policy).

Sessions are random 32-byte IDs in an in-memory store (TTL `admin.session_ttl`, default 12h, capacity-bounded) — a restart logs admins out, which is acceptable for an operator tool. The cookie is HttpOnly + SameSite=Strict, Secure over TLS. Mutating session-authenticated requests require a one-time CSRF token (`GET /v1/admin/csrf`, `X-CSRF-Token` header), mirroring the daemon's web UI.

### Service accounts: local identities, mTLS only

A service account is an account **defined in the storage layer itself** — not a directory user — for automation (CI seeding, the Terraform provider). The record is `{name, description, disabled, created_at, updated_at}`; there is no password field by design. The only way to authenticate as one is a mutual-TLS client certificate, with Vault expected to mint the identity (PKI secrets engine).

The properties that make "only authorized certificates are accepted" hold:

1. **Dedicated trust anchor.** `admin.mtls.ca_cert` is the *only* CA the listener trusts — a Vault PKI intermediate dedicated to dotvault-config service accounts, never a general corporate CA. Since every certificate from that CA was minted through the Vault role, the role's issuance policy (who can hit `pki/issue/service-account`, which CNs it allows, `client_flag=true`, capped `max_ttl`) **is** the access policy, and Vault's audit log is the issuance audit trail.
2. **Identity binding, not bearer certificates.** A verified chain is necessary but not sufficient: the leaf CN must equal the name of a registered service account, and the account must not be disabled. Deleting or disabling the account therefore revokes access **immediately**, independent of certificate lifetime.
3. **Short TTLs instead of revocation infrastructure.** The recommended Vault role caps `max_ttl` at 72h (24h default). With short-lived certs, "stop issuing + disable the account" replaces CRL/OCSP distribution, which the service deliberately does not implement.
4. **EKU enforcement.** Go's server-side chain verification requires the `clientAuth` extended key usage, so a server certificate or generic TLS cert from the same CA cannot be replayed as a client credential.

The mTLS endpoint is a **separate listener** (`admin.mtls.listen`, `RequireAndVerifyClientCert`) rather than optional client certs on the main one: browsers talking to the UI are never prompted for a certificate, the human and automation trust domains stay separate, and the main listener's TLS posture is unchanged. Certificate-authenticated requests are CSRF-exempt — there is no ambient browser credential to forge.

## Management API

All admin routes exist only when `admin.enabled`. JSON unless noted; every mutation is audit-logged with the acting identity.

| Route | Behaviour |
|-------|-----------|
| `POST /v1/admin/auth/login` | LDAP bind + admin-group check → session cookie |
| `POST /v1/admin/auth/logout` | invalidate session |
| `GET /v1/admin/csrf` | one-time CSRF token |
| `GET /v1/admin/whoami` | `{name, kind, groups}` of the caller |
| `GET /v1/admin/layers?prefix=` | list layer keys |
| `GET /v1/admin/layers/{key}` | layer document (`application/yaml`), 404 when absent |
| `PUT /v1/admin/layers/{key}` | validate (`ValidLayerKey` + `ParsePartial` + `Validate`) then store; validation errors come back as the 400 body |
| `DELETE /v1/admin/layers/{key}` | remove layer |
| `GET /v1/admin/groups` | list users with membership entries |
| `GET/PUT/DELETE /v1/admin/groups/{user}` | membership CRUD (`{"groups": […]}`) |
| `GET /v1/admin/service-accounts` | list account names |
| `GET/PUT/DELETE /v1/admin/service-accounts/{name}` | account CRUD; PUT is an upsert that preserves `created_at` |
| `GET /v1/admin/preview?os=&user=&groups=` | the composed document for an identity (`groups` overrides the resolver) — the `compose` CLI as an API |

Layer writes pass exactly the validation gate the seed path uses, so an invalid document is refused at write time with the daemon's own error text rather than surfacing later as a composition 500. `PUT` everywhere is idempotent upsert — the shape a Terraform provider wants (`Create`/`Update` collapse onto `PUT`, `Read` onto `GET`, `Delete` onto `DELETE`, drift detection onto byte comparison of the YAML).

## Store extensions

The `Store` interface gains `DeleteGroups`, `ListGroupUsers`, and the service-account CRUD (`Get/Put/Delete/ListServiceAccounts`); both drivers implement them (sqlite: a `service_accounts(name, doc)` table; Vault: a JSON `doc` field at `<path>/service-accounts/<name>`) and the conformance suite covers the new contract.

## Web UI

A dependency-free static page (HTML + vanilla JS, `embed.FS`, served at `/admin/` with the daemon's CSP posture) — no npm workspace, no build step, matching ghp's minimal-frontend approach. Screens: sign-in, layer editor (list/create/edit/delete with server-side validation errors inline), group membership table, service-account table (create/disable/delete), and compose preview. Every action is a plain fetch against the API above. If the UI outgrows this, promote it to a Preact + esbuild workspace like `internal/web/frontend` and extend dependabot.

## Dev loop

`docker compose --profile ldap up -d` adds a glauth directory (`dev/glauth.cfg`: `admin`/`password` in the admin group via the static resolver, `bob`/`password` not). `dev/mint-svc-cert.sh` provisions the service-account PKI from the dev Vault — dedicated mount, client role pinning CN/EKU/TTL, listener certificate — into `dev/pki/`, exercising the production "Vault mints the identity" flow locally.

## Future work

Layer-write optimistic concurrency (If-Match on a content ETag); per-identity authorisation scopes (read-only admins, per-axis writers); account-lockout policy beyond the per-address login rate limit; the Terraform provider itself (separate repository, consuming this API); SPIFFE-style URI SANs as an alternative identity binding.
