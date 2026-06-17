# TPM-Backed Vault Authentication Design

## Overview

dotvault authenticates to Vault today with a human credential every session — LDAP+MFA or OIDC (`internal/auth/auth.go`, `Manager.Login` switching on `oidc`/`ldap`/`token`). This design adds two new auth methods, **`mtls`** and **`mtls+tpm`**, where a TLS client certificate does the authenticating instead of a human. The LDAP/OIDC flow is demoted to a one-time **bootstrap**: it is used once to mint a certificate via Vault's PKI engine, and from then on the certificate logs in against Vault's `cert` auth method. A human credential is needed again only when the certificate expires unrotated, the sealed key is lost, or the user re-provisions.

The change is strictly **additive**. All four methods stay valid and selectable per `vault.auth_method`:

| Method | Human interaction | Long-lived | Hardware-bound |
|--------|-------------------|------------|----------------|
| `ldap` | every session | no | no |
| `oidc` | every session | no | no |
| `mtls` | bootstrap only (or BYO) | yes | no |
| `mtls+tpm` | bootstrap only (or BYO) | yes | yes |

The whole feature is pure Go with `CGO_ENABLED=0` preserved: the TPM backends (Linux `/dev/tpmrm0`, Windows TBS) are pure-Go through `go-tpm`/`go-tpm-tools`, and macOS Secure Enclave support is a compile-time-selected backend that degrades to plain `mtls` until the binary carries Apple entitlements (it is scaffolded by this design, not delivered).

## Goals and non-goals

In scope: the two new auth methods; both certificate-acquisition paths (Vault-minted bootstrap and BYO); a platform-agnostic secure-storage seam with Linux/Windows TPM backends and a non-hardware file backend; automatic certificate re-issuance before expiry; explicit failure surfacing with a bootstrap fallback; full config-surface parity (YAML, Windows registry/GPO, `.reg`).

Out of scope for v1: a working macOS Secure Enclave backend (interface and build-tag slot only — it returns `ErrUnsupported` until signed); PCR-policy *configuration* surface beyond a simple on/off seal-to-current-PCRs toggle; certificate *renewal* (Vault PKI certs cannot be renewed — re-issuance mints a fresh keypair); revocation orchestration beyond deleting the local credential.

## Certificate sources ("seeding")

Before the cert flow can run there must be a certificate. Two paths produce one; once a certificate is in hand the rest of the flow is identical.

**Option A — Vault-minted (bootstrap).** The user authenticates with the configured bootstrap method (LDAP+MFA or OIDC) and, while that token is live, dotvault calls the Vault PKI engine — `POST <pki_mount>/issue/<pki_role>` — to issue a certificate. For plain `mtls` the keypair is generated locally and the private key is sent to Vault only as a CSR-less `issue` call returns the key, or (preferred, and required for `mtls+tpm`) dotvault generates the key in the secure store, builds a CSR, and calls `POST <pki_mount>/sign/<pki_role>` so the private key never leaves the host. The sign-CSR path is the default for both methods because it keeps the private key generation co-located with where it will live; `issue` is supported only as a fallback for PKI roles that disallow `sign`. This is the normal first-run flow.

**Option B — BYO certificate.** If the user already holds a certificate and key signed by the CA registered in Vault's cert auth method, they supply it directly (`vault.mtls.byo.cert` / `byo.key` paths, or a one-shot `dotvault login --byo-cert … --byo-key …`). dotvault skips LDAP/OIDC entirely, validates the cert locally (see below), seals/stores it, and proceeds straight to cert auth. Useful for pre-provisioning, migrating from another system, or re-seeding a machine where the user still has a copy from elsewhere. For `mtls+tpm`, BYO requires an importable software key — the key is sealed into the TPM at import time; a key that is already non-exportable in foreign hardware cannot be BYO'd into our TPM and the user must bootstrap instead (surfaced as a clear error).

## The four paths — decision flow

```
needs a Vault token
        │
   auth_method?
        │
  ┌─────┴─────────────┐
ldap/oidc          mtls / mtls+tpm
  │                    │
  │            valid local credential?
  │            (cert on disk / sealed blob, not expired)
  │              │
  │          yes─┤─no
  │              │   │
  │              │   BYO cert supplied?
  │              │     │
  │              │  yes┤no
  │              │     │  │
  │              │     │  bootstrap: LDAP/OIDC → PKI issue/sign → cert
  │              │     │  │
  │              │   import/validate cert
  │              │     │  │
  │              │   mtls+tpm? ── yes → seal key into TPM, write blob+cert
  │              │     │     └──── no  → store cert+key on disk (0600)
  │              │     │
  │            (credential in hand)
  │                    │
  ▼                    ▼
Vault token     present cert in TLS handshake → auth/<cert_mount>/login → Vault token
```

## What `mtls+tpm` means in practice

With `mtls+tpm`, the certificate's private key never exists in plaintext at rest — on disk there is only the TPM-sealed blob plus the public certificate. Unsealing is bound to the same physical machine (the TPM's Storage Root Key is unique to the chip) and, optionally, to an unchanged boot state via PCR binding. The Vault token is obtained by presenting the certificate during the TLS handshake to Vault's cert auth endpoint; the private key never leaves the hardware — the TPM performs the signing internally. On every subsequent run the flow is just: load sealed blob → TPM unseal/load → sign handshake → Vault token, with **no user interaction**.

The load-bearing crypto insight that makes this clean: `tls.Certificate.PrivateKey` only needs to satisfy `crypto.Signer`, never to hold key bytes. `go-tpm-tools/client.GetSigner()` returns exactly such a signer backed by the hardware, so the same `crypto/tls` assembly code serves all three storage modes — TPM, Secure Enclave, and a software key parsed from disk are interchangeable behind `crypto.Signer`.

## Config: the `vault.mtls` section

`auth_method` gains two new values; a new nested `vault.mtls` block carries everything the cert flow needs. The block is ignored unless `auth_method` is `mtls` or `mtls+tpm`.

```yaml
vault:
  address: https://vault.example.com:8200
  auth_method: mtls+tpm          # or: mtls
  mtls:
    bootstrap_method: oidc       # ldap | oidc — used only to mint the first cert
    bootstrap_mount: ""          # optional auth_mount override for the bootstrap login
    cert_mount: cert             # Vault cert auth mount (default "cert")
    cert_role: dotvault          # cert auth role name (login param)
    pki_mount: pki               # PKI secrets engine mount used to issue/sign
    pki_role: dotvault-client    # PKI role
    key_type: ec                 # ec (P-256) | rsa (2048) — default per platform
    common_name: ""              # optional; default "{{.user}}" rendered to OS username
    ttl: ""                      # optional client-side hint; PKI role TTL is authoritative
    reissue_before: 168h         # rotate this long before expiry (default 7d)
    seal_to_pcrs: false          # mtls+tpm only: bind unseal to current PCR state
    storage_dir: ""              # default: {cache_dir}/mtls
    byo:
      cert: ""                   # PEM cert path for BYO seeding
      key: ""                    # PEM key path for BYO seeding (mtls+tpm: must be importable)
```

| Field | Type | Default | Validation |
|-------|------|---------|------------|
| `bootstrap_method` | string | `oidc` | one of `ldap`, `oidc` |
| `bootstrap_mount` | string | `vault.auth_mount` | — |
| `cert_mount` | string | `cert` | non-empty |
| `cert_role` | string | — | required (Vault rejects an empty login role) |
| `pki_mount` | string | `pki` | non-empty when no BYO and no valid cert (issuance needed) |
| `pki_role` | string | — | required when issuance is possible |
| `key_type` | string | `ec` (Linux/Windows: `rsa` also allowed; macOS: `ec` only) | one of `ec`, `rsa` |
| `common_name` | template string | `{{.user}}` | renders via `internal/tmpl` |
| `reissue_before` | duration (`Nd` ok) | `168h` | positive; must be `< role TTL` (warn if not) |
| `seal_to_pcrs` | bool | `false` | only meaningful for `mtls+tpm` |
| `storage_dir` | path | `{cache_dir}/mtls` | parent must be creatable |
| `byo.cert` / `byo.key` | path | — | both-or-neither; files must exist and parse at use |

Validation lives in the existing `Config.Validate()` (`internal/config/config.go:457`), extended with a `validateMTLS` helper gated on `auth_method ∈ {mtls, mtls+tpm}`. `key_type: rsa` with `auth_method: mtls+tpm` on macOS is rejected at load (the Secure Enclave is EC-only) so the error is explicit rather than a runtime degrade surprise.

## The `SecureStorage` interface

One platform-agnostic interface, selected at compile time via build tags, is the heart of the design. The calling code (auth orchestration) never branches on platform.

```go
// internal/securestore/securestore.go (platform-neutral)
type SecureStorage interface {
    // Capabilities reports whether this backend hardware-binds the key.
    Capabilities() Capabilities
    // GenerateKey creates a new key (in hardware where supported) and
    // returns a crypto.Signer plus an opaque Handle that can later reload it.
    GenerateKey(opts KeyOpts) (crypto.Signer, Handle, error)
    // ImportKey seals an existing software private key (BYO path).
    ImportKey(key crypto.PrivateKey, opts KeyOpts) (crypto.Signer, Handle, error)
    // Load reconstructs a crypto.Signer from a previously stored Handle.
    Load(h Handle) (crypto.Signer, error)
    // Destroy removes any hardware-resident material for the handle.
    Destroy(h Handle) error
}

type Capabilities struct {
    HardwareBound bool   // true for TPM / Enclave, false for file backend
    KeyTypes      []string
    Name          string // "tpm", "secure-enclave", "file"
}
```

`Handle` is an opaque, serialisable value (a byte slice — the marshalled `go-tpm-tools` `SealedBytes` proto for TPM, the keychain reference for Enclave, or the PEM for the file backend). It is persisted inside the credential envelope, never interpreted by the caller.

Backend selection is a single constructor `securestore.Open(mode string) (SecureStorage, error)` where `mode` is derived from `auth_method`: `mtls+tpm` → the hardware backend, `mtls` → the `file` backend. If `mtls+tpm` is requested but the platform build has no hardware backend (macOS unsigned, or a Linux box with no TPM), `Open` returns `ErrUnsupported`, which the orchestration surfaces as a clear "TPM unavailable — falling back to mtls requires re-running with `auth_method: mtls`" message rather than silently writing a plaintext key.

### Backends and build tags

| File | Build constraint | Backing |
|------|------------------|---------|
| `securestore_tpm.go` | `//go:build linux \|\| windows` | `go-tpm-tools/client`: `StorageRootKeyRSA`, `NewKey`, `LoadCachedKey`, `GetSigner`; transport via `go-tpm/legacy/tpm2` (`/dev/tpmrm0` on Linux, TBS on Windows — same import, build-tag-internal) |
| `securestore_darwin.go` | `//go:build darwin` | Secure Enclave via `ebitengine/purego` + Security.framework (reference: `lstoll/keychain`); returns `ErrUnsupported` until the binary is code-signed with `keychain-access-groups` entitlements |
| `securestore_file.go` | always built | software key on disk, 0600, used for plain `mtls` and as the explicit non-hardware mode |

The TPM backend seals the generated private key under the SRK. When `seal_to_pcrs` is set, the seal policy binds to the current PCR values (firmware + Secure Boot measurements) so an unseal fails after a firmware/boot change — surfaced as a recoverable error, never a silent fallback. The `SealedBytes` proto is marshalled with `google.golang.org/protobuf` (already transitive via go-tpm-tools) for storage in the envelope.

## On-disk credential envelope

A single JSON file at `{storage_dir}/credential.json`, written 0600 via temp-file+rename (same atomic pattern as `state.json`). The private key is **never** in this file — for `mtls+tpm` it is inside the sealed `Handle`; for `mtls` the `Handle` *is* the PEM key (so the file backend is the only mode where key bytes touch disk, by definition).

```go
type SealedCredential struct {
    Schema      int       `json:"schema"`       // 1
    Method      string    `json:"method"`       // "mtls" | "mtls+tpm"
    Backend     string    `json:"backend"`      // "tpm" | "secure-enclave" | "file"
    CertPEM     string    `json:"cert_pem"`     // leaf + chain
    Handle      []byte    `json:"handle"`        // opaque secure-store handle (sealed blob OR PEM key)
    Serial      string    `json:"serial"`        // cert serial, for revocation/audit
    NotAfter    time.Time `json:"not_after"`     // expiry — drives the re-issuance window
    Identity    string    `json:"identity"`      // OS username at issue time, binds the blob
    IssuedAt    time.Time `json:"issued_at"`
}
```

`NotAfter` is read from the certificate itself (not trusted from any side channel) and drives re-issuance. `Identity` binds the envelope to the OS user the way the remote-config cache does, so a credential written under one account is never loaded for another.

## Auth orchestration changes

`auth.Manager` (`internal/auth/auth.go`) gains the two methods in its `Login` switch, delegating to a new `internal/certauth` package so the Manager stays a thin dispatcher:

```go
case "mtls", "mtls+tpm":
    return m.authenticateMTLS(ctx)   // → certauth.Flow
```

`certauth.Flow` owns the decision tree:

1. **Load existing.** Read the envelope; if present, `securestore.Load(handle)` → `crypto.Signer`, assemble `tls.Certificate`, and if `time.Now() < NotAfter` attempt cert-auth login immediately. A successful login with an in-window cert is the steady state — zero user interaction, zero Vault PKI calls.
2. **Seed if needed.** No valid credential → if BYO paths are set, import+validate; else bootstrap: construct a *temporary* `auth.Manager` with `AuthMethod = bootstrap_method` and run its existing OIDC/LDAP flow to obtain a short-lived bootstrap token, then call PKI issue/sign with the secure-store-generated key.
3. **Persist.** Write the envelope; for `mtls+tpm` the sealed handle, for `mtls` the PEM.
4. **Cert-auth login.** Present the cert, get the operational Vault token, discard the bootstrap token.

`Authenticate` (the token-reuse fast path) is unchanged: an existing `~/.dotvault-token` that still `LookupSelf`s is reused before any of this runs, exactly as today — the cert flow is the *fresh-auth* path, so a warm daemon restart still costs nothing.

## Cert-auth login mechanics

Vault's cert auth method authenticates by the client certificate presented during the TLS handshake; the login call itself is `POST auth/<cert_mount>/login` with `{"name": "<cert_role>"}`. The Vault SDK does not expose a per-call client cert, so `internal/vault.NewClient` gains an option to inject one:

```go
// internal/vault/client.go
type Config struct {
    // …existing fields…
    ClientCert *tls.Certificate // optional; presented during TLS handshake
}
```

When set, `NewClient` installs a `tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cfg.ClientCert, nil }}` on the api client's `HttpClient` transport — `GetClientCertificate` (rather than `Certificates`) so the hardware signer is invoked lazily per handshake and the `crypto.Signer` abstraction holds end to end. The existing CA-cert / skip-verify TLS wiring is preserved; the client cert is layered on top. A new `Client.LoginCert(ctx, mount, role)` posts the login and adopts the returned token, mirroring the existing OIDC/LDAP token-adoption code.

Because the operational token returned by cert-auth login is an ordinary Vault token, **everything downstream is unchanged** — `LifecycleManager` renews it at 75% TTL, the sync engine, enrolment, and SSH agent all consume it identically. The cert is only re-presented when the token itself can no longer be renewed and a fresh login is required, at which point `certauth.Flow` runs again from step 1.

## PKI issuance: bootstrap and re-issuance

`internal/vault` gains `IssueCertificate` / `SignCSR` wrapping `pki/issue/<role>` and `pki/sign/<role>`. The default path generates the key in the secure store, builds a CSR (`x509.CreateCertificateRequest` over the `crypto.Signer`), and calls `sign` — so even at bootstrap the `mtls+tpm` private key is born in hardware and never transits Vault. `issue` is used only when the role forbids `sign`.

**Re-issuance** is driven off `NotAfter`. The daemon's existing periodic loop (the config-refresh tick already runs in every daemon mode) gains a cheap check: when `now >= NotAfter - reissue_before`, run re-issuance — authenticate with the *current still-valid* cert to get a token, call PKI sign with a freshly generated key, write a new envelope (new sealed handle), and atomically swap. This needs no human because the live cert authorises it. The bootstrap (human) path is therefore only ever hit on: first run on a new machine; a cert that expired *outside* the window unrotated; a lost/cleared sealed blob; or explicit re-provision. Re-issuance failures are transient-retried with backoff and surfaced in status; they do not tear down the working token.

`LifecycleManager` interplay: the lifecycle manager already fires `OnReauth` when a token is unrecoverable. In cert mode the `OnReauth` callback points at `certauth.Flow` instead of the web/OIDC reopen, so an expired *token* with a still-valid *cert* recovers fully unattended.

## BYO validation

A BYO cert skips bootstrap but not Vault's acceptance. Before attempting login, `certauth` validates locally: the cert parses, is currently within its validity window, and chains to the CA that Vault's cert auth method trusts. The trusted CA is discovered by reading the cert auth method's configured CA (`vault.mtls` may optionally pin a `ca_cert` path for the offline check; otherwise the check is "chains to a CA we can fetch from the configured cert mount once we can talk to Vault"). The point is to fail with "your certificate is not signed by the CA Vault trusts" locally rather than as an opaque Vault TLS rejection. For `mtls+tpm`, BYO additionally requires the key be importable into the TPM (`ImportKey`); a key already locked in foreign hardware is rejected with guidance to bootstrap.

## Failure modes — explicit, never silent

The design's hard rule: a hardware-binding request never degrades to plaintext key storage without the user choosing it. Concretely:

- **TPM unavailable** (`mtls+tpm` on a host with no TPM / unsigned macOS): `securestore.Open` → `ErrUnsupported`, the flow aborts with a message naming the missing hardware and the `auth_method: mtls` alternative. No plaintext key is written.
- **Unseal failure** (wrong machine after a blob copy, or PCR mismatch after a firmware/Secure Boot update with `seal_to_pcrs`): surfaced as a clear, distinct error, and the flow offers the bootstrap fallback — LDAP/OIDC → re-issue → re-seal — rather than failing dead or silently dropping hardware binding.
- **Cert expired outside the window**: treated as "no valid credential", falls to BYO-or-bootstrap.
- **PKI issuance denied** (bootstrap token lacks the `pki/issue|sign` policy): surfaced verbatim; this is a Vault-admin misconfiguration, called out as such.

These states feed `dotvault status` and `GET /api/v1/status`, which gain an `mtls` block: method, backend (`tpm`/`file`/`secure-enclave`/`unavailable`), cert serial, `not_after`, in-window/expired, last re-issuance attempt/success/error.

## What Vault needs (admin side)

Not a code change but the operator prerequisite, documented in `docs/authentication/mtls-tpm.md`:

1. **PKI secrets engine** mounted with a CA and a role constraining allowed common names, key type (RSA for Linux/Windows, EC P-256 for macOS — two roles if supporting both), and TTL. Certs cannot be renewed; the TTL is the rotation cadence.
2. **Cert auth method** enabled with the PKI CA registered, and a cert role whose attached policies define what a cert-authenticated token may do (KV paths, SSH signing, etc.).
3. **Bootstrap issuance policy** — the LDAP/OIDC token needs a narrow, time-limited policy permitting `pki/issue/<role>` (or `pki/sign/<role>`) for the bootstrap only.
4. **Operational cert-auth policy** — separate from the above; the ongoing capability of an mTLS-authenticated session.

## Config-surface parity (registry / `.reg` / YAML)

Per the project's non-negotiable three-surface rule, the `vault.mtls` block round-trips through all of: the live YAML loader, the Windows registry loader (`internal/config/registry_windows.go`), and the `.reg` renderer/parser (`internal/regfile/regfile.go`, `parse.go`). The scalar fields map to a `Vault\MTLS` subkey (REG_SZ / REG_DWORD: `BootstrapMethod`, `CertMount`, `CertRole`, `PKIMount`, `PKIRole`, `KeyType`, `CommonName`, `ReissueBefore`, `SealToPCRs` as REG_DWORD, `StorageDir`), with a nested `Vault\MTLS\BYO` subkey for `Cert`/`Key`. The same delete-before-recreate idempotency the Observability headers and Agent keys use applies so a removed field clears on re-import. A round-trip test (platform-neutral, like the other `internal/regfile` tests) is added; the registry loader test stays `//go:build windows`. The credential envelope itself is **not** config — it lives in `{cache_dir}/mtls/`, never in the registry or a `.reg` file.

## Dependencies

| Package | Purpose | Notes |
|---------|---------|-------|
| `github.com/hashicorp/vault/api` | LDAP/OIDC bootstrap login, PKI issue/sign, cert-auth login | already a dependency; stable; preferred over beta `vault-client-go` |
| `github.com/google/go-tpm-tools/client` | TPM seal/unseal, `crypto.Signer` (`StorageRootKeyRSA`, `NewKey`, `LoadCachedKey`, `GetSigner`) | the day-to-day TPM wrapper; manages SRK + handle lifecycle |
| `github.com/google/go-tpm/legacy/tpm2` | TPM 2.0 primitives + Windows TBS transport | one import, build-tags handle Linux `/dev/tpmrm0` vs Windows TBS |
| `google.golang.org/protobuf` | marshal `SealedBytes` for the handle | already transitive via go-tpm-tools |
| `github.com/ebitengine/purego` | macOS Security.framework via `dlopen` (no CGO) | **future** — Enclave backend only |
| `github.com/lstoll/keychain` | no-CGO Keychain wrapper (reference/direct) | **future** — Enclave backend only |
| stdlib `crypto/tls`, `crypto/x509`, `encoding/json` | assemble `tls.Certificate` from the `crypto.Signer`, build CSRs, serialise the envelope | no new dependency |

All pure Go; `CGO_ENABLED=0` static builds are preserved. The macOS rows land only when the Enclave backend is implemented; until then `securestore_darwin.go` is a stub returning `ErrUnsupported` and pulls in no new modules. New gomod dependencies mean a Dependabot grouping check, but the existing `gomod` root entry already covers them.

## Security and trust model

- **The TPM is the at-rest protection for `mtls+tpm`.** The private key is never on disk in plaintext; compromise of the disk yields only the sealed blob, useless off the originating chip (and off the boot state with `seal_to_pcrs`). For plain `mtls` the key *is* on disk at 0600 — the same trust as the token file — which is the documented, deliberate trade-off for TPM-less environments (CI, containers, shared machines that opt out of hardware binding).
- **Bootstrap privilege is narrow and time-limited.** The human-credential token only needs `pki/issue|sign`; it is discarded immediately after issuance and never persisted. The long-lived capability is the cert-auth policy, which the admin scopes independently.
- **No silent downgrade.** The single most important security property: a request for hardware binding either gets hardware binding or a clear error — never a plaintext key behind the user's back.
- **Identity binding.** The envelope is bound to the OS user (`Identity` field), matching the `kv/users/<user>/…` layout the rest of dotvault uses; a blob is never loaded under a different account.
- **Revocation.** `dotvault login --revoke` (future flag) deletes the local credential and best-effort calls `pki/revoke`; absent that, letting the cert expire is the baseline revocation.

## Testing

- **securestore**: a backend conformance suite (generate → load → sign → destroy round-trip, `crypto.Signer` correctness against `crypto/x509` verification) runnable against the `file` backend everywhere and the TPM backend behind a `//go:build tpm` integration tag using a software TPM simulator (`go-tpm-tools` ships one) so CI exercises seal/unseal without real hardware. `ErrUnsupported` paths asserted per platform.
- **certauth.Flow**: table-driven over the decision tree with a fake `SecureStorage` and a fake Vault — in-window cert (no Vault PKI call), expired cert → re-issue, no credential + BYO, no credential → bootstrap, unseal failure → fallback offered, TPM-unavailable → hard error (no plaintext written).
- **vault**: `ClientCert` injection verified with an `httptest` TLS server asserting the client cert reaches the handshake; `LoginCert` token adoption; CSR sign vs issue selection.
- **config / regfile**: `validateMTLS` table (method-gated requirements, macOS EC-only rule, BYO both-or-neither, `reissue_before < TTL` warning) and a `vault.mtls` three-surface round-trip mirroring the observability/agent tests.
- **lifecycle**: `OnReauth` → cert re-login with a still-valid cert recovers a dead token unattended (`-race`).

## Future work

A working macOS Secure Enclave backend (purego + Security.framework, gated on code-signing infrastructure — the interface and build-tag slot are delivered now so this is additive with no caller changes); richer PCR-policy configuration (selecting which PCRs, sealing to a future expected boot state for staged firmware updates); `pki/revoke` orchestration and a `--revoke` flag; certificate transparency / audit export of issued serials; and a hardware-attestation step (TPM `Quote`) so Vault can verify the key is genuinely TPM-resident at cert-auth time, not merely that the holder possesses it.

## Files Changed

| File | Change |
|------|--------|
| `internal/securestore/securestore.go` | New — `SecureStorage` interface, `Handle`, `Capabilities`, `Open`, `ErrUnsupported` |
| `internal/securestore/securestore_tpm.go` | New — Linux/Windows TPM backend (`//go:build linux \|\| windows`) |
| `internal/securestore/securestore_darwin.go` | New — Secure Enclave stub returning `ErrUnsupported` (`//go:build darwin`) |
| `internal/securestore/securestore_file.go` | New — software-key file backend (always built) |
| `internal/certauth/certauth.go` | New — `Flow` orchestration, envelope load/persist, BYO validation, re-issuance |
| `internal/certauth/envelope.go` | New — `SealedCredential` read/write (0600, atomic) |
| `internal/auth/auth.go` | `Login` switch gains `mtls`/`mtls+tpm` → `authenticateMTLS` |
| `internal/auth/lifecycle.go` | `OnReauth` may target `certauth.Flow` in cert mode |
| `internal/vault/client.go` | `Config.ClientCert`, `GetClientCertificate` wiring, `LoginCert`, `IssueCertificate`/`SignCSR` |
| `internal/config/config.go` | `VaultConfig.MTLS` block + `validateMTLS` |
| `internal/config/registry_windows.go` | `Vault\MTLS` (+ `BYO`) subkey loader |
| `internal/regfile/regfile.go`, `parse.go` | Render/parse the `vault.mtls` block |
| `cmd/dotvault/main.go` | Cert-mode wiring; `--byo-cert`/`--byo-key`/(future `--revoke`) on `login`; status `mtls` block |
| `internal/web/server.go`, `api.go` | `mtls` block on `GET /api/v1/status` |
| `config.dev.yaml`, `docker-compose` | Dev PKI + cert auth method seeding for end-to-end exercise |
| `docs/authentication/mtls-tpm.md`, `docs/authentication/overview.md`, `CLAUDE.md` | Documentation (admin Vault setup, platform behaviour, the four-method matrix) |

## Addendum: TPM-sealed token at rest (the `+tpm` suffix generalised)

A follow-up to this design extends TPM sealing from the certificate key to the **cached Vault token** in `~/.dotvault-token`, and in doing so generalises the `+tpm` marker into a method-independent suffix.

Rationale: under `mtls+tpm` the long-lived secret (the cert key) is hardware-sealed, but the operational token the cert mints still rested on disk as plaintext — a disk image lifted off the host yielded a usable token for the remainder of its TTL. Sealing the token closes that window and completes the "nothing sensitive on disk in plaintext" property. Because the token is just bytes, the same value is available to non-cert methods, so `+tpm` becomes a general modifier: `oidc+tpm`, `ldap+tpm`, and `mtls+tpm` all request token sealing; for `mtls` it is additive to the existing key sealing. The suffix parses on any base for uniformity, but `token+tpm` is inert for sealing (the bare `token` method never writes the token file — it reads one you supply — so there is nothing to seal, though a sealed file is still read transparently).

Design points (implementation in `internal/auth/method.go`, `internal/auth/token.go`, `internal/securestore`):

- **Suffix parsing.** `auth.BaseMethod` strips `+tpm` for the login dispatch; `auth.SealTokenAtRest` reports it for the write path. The cert flow keeps keying off the full `mtls+tpm` string via `securestore.ModeForMethod`, so the two concerns (cert-key store vs. token sealing) stay independent.
- **Self-describing file.** `WriteTokenFile(path, token, seal)` writes a `$dotvault-tpm-sealed$v1$`-prefixed base64 envelope when sealing; `ReadTokenFile` detects the prefix and unseals, returning a plaintext file verbatim otherwise. Detection from content alone means every reader — daemon, CLI, token-file watcher, and the exported `client` facade (which already funnels reads through `auth.ResolveToken`) — consumes a sealed token transparently, with no auth-method knowledge and no signature churn on the read path. Migration is therefore free in both directions.
- **Sealing primitive.** `securestore.DataSealer` (`SealData`/`UnsealData`) is an optional capability implemented by the TPM backend and reusing its SRK seal/unseal path; the `file` backend deliberately does not implement it (sealing under a co-located software key is pointless). `securestore.HardwareAvailable` is the cheap preflight. The token is SRK-bound only — never PCR-bound — because it is ephemeral and re-derivable, so boot-state binding would needlessly strand it across a firmware update.
- **No silent fallback.** A `+tpm` method on a TPM-less host fails fast: a `HardwareAvailable` preflight in `Manager.Login` (skipped for the `mtls` base, which owns its own check) and a hard error from `WriteTokenFile(..., seal=true)` rather than a plaintext write. `DOTVAULT_TOKEN` is always plaintext — an environment value cannot be sealed — so sealing covers the file only.
- **Transient SRK, not persisted (Windows fix).** The design table above sketched `client.StorageRootKey*` for the SRK, but that path persists the key to a reserved handle via `TPM2_EvictControl` — an owner-hierarchy operation Windows TBS blocks for standard-user processes (`0x80280400`), so it fails on a perfectly healthy and accessible Windows TPM. The backend therefore derives the SRK as a *transient* primary (`client.NewKey` + `SRKTemplateECC`, via `loadSRK`): a primary key is deterministic, so re-deriving on every operation costs nothing and unseals any blob previously sealed under the persistent SRK of the same ECC template. The transient handle is flushed on `Close`, so the TPM's limited transient slots aren't leaked.
- **PCR7 excluded on Windows.** `seal_to_pcrs` binds to PCRs 0/2/4/7 on Linux but drops PCR7 on Windows (`pcrSelectionFor(runtime.GOOS)`): BitLocker claims PCR7 (Secure Boot state) for its own VMK binding there, so including it would couple our credential's availability to BitLocker's re-seal cycle. PCRs 0/2/4 still move on a tampered boot, keeping the binding meaningful. The token seal never uses PCRs regardless.
