# Certificate Authentication (mTLS and mTLS+TPM)

dotvault can authenticate to Vault with a TLS client certificate instead of a human credential every session. Two methods implement this:

| Method | Human interaction | Long-lived | Hardware-bound |
|--------|-------------------|------------|----------------|
| `mtls` | bootstrap only (or BYO) | yes | no |
| `mtls+tpm` | bootstrap only (or BYO) | yes | yes |

Both demote LDAP/OIDC to a one-time **bootstrap**: it is used once to mint a certificate via Vault's PKI engine, and from then on the certificate logs in against Vault's `cert` auth method with no prompt. A human credential is needed again only when the certificate expires unrotated, the sealed key is lost, or you re-provision.

These methods are additive — `ldap`, `oidc`, and `token` remain valid and unchanged. Pick one per machine via `vault.auth_method`.

## How it works

1. **Seed a certificate.** Either dotvault bootstraps (LDAP/OIDC login → `pki/sign`) or you supply your own (BYO).
2. **Store the key.** For `mtls` the private key is written to disk at `0600`. For `mtls+tpm` the key is sealed into the TPM and only the sealed blob touches disk.
3. **Log in.** dotvault presents the certificate during the TLS handshake to `auth/<cert_mount>/login` and receives an ordinary Vault token. Everything downstream (renewal, sync, enrolment, the SSH agent) is unchanged.
4. **Rotate.** Vault PKI certificates cannot be renewed. dotvault tracks expiry and, once inside the `reissue_before` window, mints a fresh certificate using the still-valid one — no human needed.

`mtls+tpm` adds machine binding: the sealed blob is useless on any other machine (the TPM's Storage Root Key is unique to the chip), and with `seal_to_pcrs` it is also useless after a firmware or Secure Boot change. If an unseal fails, dotvault surfaces a clear error and offers the bootstrap fallback rather than silently dropping hardware protection.

## Configuration

```yaml
vault:
  address: https://vault.example.com:8200
  auth_method: mtls+tpm          # or: mtls
  mtls:
    bootstrap_method: oidc       # ldap | oidc — used only to mint the first cert
    bootstrap_mount: ""          # optional auth-mount override for the bootstrap login
    cert_mount: cert             # Vault cert auth mount (default "cert")
    cert_role: dotvault          # cert auth role name (required)
    pki_mount: pki               # PKI secrets engine mount (default "pki")
    pki_role: dotvault-client    # PKI role (required unless BYO)
    key_type: ec                 # ec (P-256) | rsa (2048); mtls+tpm is ec-only
    common_name: "{{.user}}"     # Go template over {{.user}} (the OS username)
    ttl: ""                      # optional TTL hint; the PKI role TTL is authoritative
    reissue_before: 168h         # rotate this long before expiry (default 7d)
    seal_to_pcrs: false          # mtls+tpm only: bind unseal to the current boot state
    storage_dir: ""              # default: {cache_dir}/mtls
    byo:                         # optional bring-your-own seeding
      cert: ""                   # PEM certificate path
      key: ""                    # PEM key path (mtls+tpm: must be an importable EC key)
```

The whole `vault.mtls` block round-trips losslessly through YAML, the Windows registry (`Vault\MTLS`, with `Vault\MTLS\BYO`), and `reg-import`/`reg-export`, like every other config section.

### Bring-your-own (BYO) certificate

If you already hold a certificate and key signed by the CA that Vault's cert auth method trusts, set `byo.cert` and `byo.key`. dotvault skips the LDAP/OIDC bootstrap entirely: it validates the certificate locally (parses, checks the validity window), imports the key into the secure store, and goes straight to cert-auth login. For `mtls+tpm` the BYO key must be an importable EC P-256 software key — it is sealed into the TPM at import time.

## Platform behaviour

- **Linux** — TPM 2.0 via `/dev/tpmrm0`. A standard user needs membership of the `tss` group; no elevation, no signing.
- **Windows 10/11** — TPM 2.0 via TBS (a system service always running). Any logged-in standard user can access it with no elevation or group membership. dotvault derives the Storage Root Key as a *transient* primary key (TPM2_CreatePrimary) rather than persisting it to a reserved handle — persisting requires TPM2_EvictControl, an owner-hierarchy operation that Windows TBS blocks for standard-user processes (it surfaces as `0x80280400` even on a healthy TPM). Primary keys are deterministic, so re-deriving on every operation still unseals anything previously sealed. With `seal_to_pcrs`, dotvault also **excludes PCR7** (Secure Boot state) on Windows because BitLocker claims PCR7 for its own binding; the seal stays bound to PCRs 0/2/4, so a tampered boot still breaks the unseal without coupling the credential to BitLocker's re-seal cycle.
- **macOS** — the Secure Enclave is the hardware equivalent but requires the binary to be code-signed with Apple keychain entitlements. Until that signing infrastructure is in place, `mtls+tpm` returns a clear "no hardware backend" error on macOS; use `mtls` in the interim. The architecture supports the Enclave with no caller changes once signing lands.

`mtls+tpm` uses EC P-256 only: a TPM sealed-data object's sensitive area is size-bounded (a P-256 scalar fits where an RSA key would not), and EC is also the Secure Enclave's only algorithm, keeping cross-platform configs portable. Plain `mtls` (software key on disk) accepts `rsa` as well.

> **Implementation note.** The TPM backend seals the private scalar and unseals it into process memory to sign; the at-rest protection and machine/boot binding are the security properties it provides. A fully TPM-resident signing key, where the scalar never leaves the chip, is planned follow-up work.

## TPM-sealed token

The `+tpm` suffix is a **general modifier**, not exclusive to mTLS. Append it to a token-minting method — `oidc+tpm`, `ldap+tpm`, or `mtls+tpm` — to seal the cached Vault token in `~/.dotvault-token` under the TPM. The login flow for the base method is unchanged; only how the resulting token rests on disk differs. (The bare `token` method consumes a token you supply and never writes the file itself, so `token+tpm` has nothing to seal — it will still transparently read a sealed file.)

For `mtls+tpm` this is *additive*: the certificate's private key was already sealed, and now the operational token is too, so **nothing sensitive sits on disk in plaintext**. For `oidc+tpm` / `ldap+tpm`, sealing the token is the only use of the TPM — a convenient way to harden the at-rest token without adopting certificate auth.

```yaml
vault:
  address: https://vault.example.com:8200
  auth_method: oidc+tpm          # normal OIDC login; the cached token is TPM-sealed
```

How it behaves:

- **Self-describing file.** A sealed token file carries a `$dotvault-tpm-sealed$v1$` marker and a sealed, base64 body. dotvault detects the marker on read and unseals automatically; a plaintext file is read verbatim. Nothing keys off the auth method to *read* a token, which is why the daemon, `dotvault status`/`enrol`, the token-file watcher, and the embeddable `client` library all consume a sealed token with no extra wiring.
- **Free migration.** Turning the suffix on does not require clearing an existing plaintext token — the next login replaces it with a sealed one; turning it off is equally seamless.
- **No silent plaintext fallback.** A `+tpm` method on a host with no working TPM fails fast at login with a clear error rather than writing a plaintext token. (`mtls+tpm` additionally needs the TPM for its key, and fails for that reason too.)
- **Env var stays plaintext.** `DOTVAULT_TOKEN` cannot be sealed (it is an environment value); the seal protects the on-disk file only.
- **SRK-bound, not PCR-bound.** Unlike the certificate key's optional `seal_to_pcrs`, the token is bound only to the chip, never to the boot state — the token is short-lived and re-derivable, so a firmware update should not strand it. A sealed token copied to another machine (or surviving a TPM clear) simply fails to unseal and triggers a normal re-authentication.

## What your Vault admin must set up

This is a Vault configuration exercise, not a dotvault setting:

1. **PKI secrets engine** — mounted, with a CA and a role constraining allowed common names, key type (RSA for Linux/Windows, EC P-256 for macOS), and TTL. The TTL is the rotation cadence; certificates cannot be renewed.
2. **Cert auth method** — enabled, with the PKI CA registered, and a role whose attached policies define what a certificate-authenticated token may do.
3. **Bootstrap issuance policy** — the LDAP/OIDC token needs a narrow, time-limited policy permitting `pki/sign/<role>` (or `pki/issue/<role>`) for the bootstrap.
4. **Operational cert-auth policy** — separate from the above; the ongoing capability of an mTLS-authenticated session.

## Limitations (v1)

- First-run **bootstrap** uses the LDAP/OIDC CLI flow and needs a terminal (or a BYO certificate). The steady-state cert login is fully headless; only the very first certificate on a new machine needs a human. Driving the bootstrap through the web UI SPA is not yet wired.
- The TPM backend is implemented against `go-tpm`/`go-tpm-tools` and is CGO-free, but has not been exercised against physical TPM hardware in CI (which has no TPM and whose simulator requires CGO). Validate on your target hardware before fleet rollout.
- macOS Secure Enclave is scaffolded (interface + build-tag slot) but not yet functional pending code-signing.
