# Certificate Authentication (mTLS, mTLS+TPM, mTLS+OS)

dotvault can authenticate to Vault with a TLS client certificate instead of a human credential every session. Three methods implement this, differing only in where the certificate's private key is held:

| Method | Human interaction | Long-lived | Key at rest | Visible to other apps |
|--------|-------------------|------------|-------------|-----------------------|
| `mtls` | bootstrap only (or BYO) | yes | disk (`0600` PEM) | no |
| `mtls+tpm` | bootstrap only (or BYO) | yes | TPM-sealed | no |
| `mtls+os` | bootstrap only | yes | OS-native cert store (Windows) | yes |

They all demote LDAP/OIDC to a one-time **bootstrap**: it is used once to mint a certificate via Vault's PKI engine, and from then on the certificate logs in against Vault's `cert` auth method with no prompt. A human credential is needed again only when the certificate expires unrotated, the key is lost, or you re-provision.

These methods are additive — `ldap`, `oidc`, and `token` remain valid and unchanged. Pick one per machine via `vault.auth_method`.

## How it works

1. **Seed a certificate.** Either dotvault bootstraps (LDAP/OIDC login → `pki/sign`) or you supply your own (BYO).
2. **Store the key.** For `mtls` the private key is written to disk at `0600`. For `mtls+tpm` the key is sealed into the TPM and only the sealed blob touches disk. For `mtls+os` the key is generated inside the OS-native certificate store and the certificate is installed alongside it, so the key never touches dotvault's own files.
3. **Log in.** dotvault presents the certificate during the TLS handshake to `auth/<cert_mount>/login` and receives an ordinary Vault token. Everything downstream (renewal, sync, enrolment, the SSH agent) is unchanged.
4. **Rotate.** Vault PKI certificates cannot be renewed. dotvault tracks expiry and, once inside the `reissue_before` window, mints a fresh certificate using the still-valid one — no human needed.

`mtls+tpm` adds machine binding: the certificate's private key is sealed under the TPM, so the sealed blob is useless on any other machine, and with `seal_to_pcrs` it is also useless after a firmware or Secure Boot change. If an unseal fails, dotvault surfaces a clear error and offers the bootstrap fallback rather than silently dropping hardware protection. The hardware backend, its platform support, the EC-P-256 requirement, and the Windows PCR7 handling are all documented in [TPM-Backed Protection](tpm.md) — and `mtls+tpm` also seals the cached token at rest, exactly like any other `+tpm` method.

## OS-native certificate store (`mtls+os`)

`mtls+os` puts the issued certificate **and** its private key into the operating system's own certificate store rather than dotvault's private cache. The point is interoperability: once the certificate lives in the OS store, *other* software on the machine can present it for mTLS — most importantly the system browsers. In a corporate environment where services trust the Vault CA (and honour its CRL), a single Vault-issued certificate becomes a general-purpose user identity for browser-based mTLS authentication, kept fresh automatically by dotvault, with no human credential after the first bootstrap.

On Windows the key is generated in the **current user's** CNG key store (the *Microsoft Software Key Storage Provider*, DPAPI-protected — no administrator rights needed) and the certificate is installed into `Certificates - Current User → Personal` (`CurrentUser\My`), which is exactly where Edge and Chrome look for client certificates. dotvault never exports the key; it stays in the store and dotvault signs through it for both the Vault cert-auth handshake and ongoing rotation.

Differences from the other cert methods:

- **Platform support.** `mtls+os` is **Windows-only** today (it is built on [`github.com/google/certtostore`](https://github.com/google/certtostore), a Windows-CNG library). On Linux and macOS it fails fast with a clear "OS-native certificate store is unavailable" error rather than degrading to an on-disk key — Linux (PKCS#11/NSS) and macOS (Keychain) backends are planned follow-ups. Use `mtls` or `mtls+tpm` on those platforms.
- **No bring-your-own.** The OS store can install a certificate but cannot import an external private key, so `byo` is rejected at config-load for `mtls+os`. The key is always generated in the store and certified via `pki/sign`. (Use `mtls` for BYO.)
- **Certificate TTL defaults to 30 days.** Because the credential doubles as a browser-presented user identity, an unset `ttl` defaults to `720h` (30d) for `mtls+os` (plain `mtls`/`mtls+tpm` leave it to the PKI role). dotvault requests this length; **the Vault PKI role's `max_ttl` is still the authoritative cap**, and `reissue_before` (default 7d) drives automatic rotation well before expiry.
- **Key types.** Both `ec` (P-256) and `rsa` (2048) are accepted, like plain `mtls` (only `mtls+tpm` is EC-only).
- **Token at rest.** `mtls+os` governs the *certificate key* only; the operational Vault token rests as a plaintext `0600` file exactly as with plain `mtls`. Combine the `+tpm` token sealing with a different method if you also want the token sealed.

## Configuration

```yaml
vault:
  address: https://vault.example.com:8200
  auth_method: mtls+tpm          # or: mtls | mtls+os (Windows-only)
  mtls:
    bootstrap_method: oidc       # ldap | oidc — used only to mint the first cert
    bootstrap_mount: ""          # optional auth-mount override for the bootstrap login
    cert_mount: cert             # Vault cert auth mount (default "cert")
    cert_role: dotvault          # cert auth role name (required)
    pki_mount: pki               # PKI secrets engine mount (default "pki")
    pki_role: dotvault-client    # PKI role (required unless BYO)
    key_type: ec                 # ec (P-256) | rsa (2048); mtls+tpm is ec-only
    common_name: "{{.user}}"     # Go template over {{.user}} (the OS username)
    ttl: ""                      # optional TTL hint; PKI role TTL is authoritative (mtls+os defaults to 720h)
    reissue_before: 168h         # rotate this long before expiry (default 7d)
    seal_to_pcrs: false          # mtls+tpm only: bind unseal to the current boot state
    storage_dir: ""              # default: {cache_dir}/mtls
    byo:                         # optional bring-your-own seeding (not supported with mtls+os)
      cert: ""                   # PEM certificate path
      key: ""                    # PEM key path (mtls+tpm: must be an importable EC key)
```

The whole `vault.mtls` block round-trips losslessly through YAML, the Windows registry (`Vault\MTLS`, with `Vault\MTLS\BYO`), and `reg-import`/`reg-export`, like every other config section.

### Bring-your-own (BYO) certificate

If you already hold a certificate and key signed by the CA that Vault's cert auth method trusts, set `byo.cert` and `byo.key`. dotvault skips the LDAP/OIDC bootstrap entirely: it validates the certificate locally (parses, checks the validity window), imports the key into the secure store, and goes straight to cert-auth login. For `mtls+tpm` the BYO key must be an importable EC P-256 software key — it is sealed into the TPM at import time.

For `mtls+tpm`, only EC P-256 keys are supported (the TPM sealed-data object is size-bounded and EC is the Secure Enclave's only algorithm); plain `mtls` keeps the key on disk and accepts `rsa` as well. See [TPM-Backed Protection](tpm.md) for the hardware backend's platform support and limitations — Linux `tss` group access, the Windows TBS / transient-SRK / PCR7 handling, and the macOS Secure Enclave status.

## What your Vault admin must set up

This is a Vault configuration exercise, not a dotvault setting:

1. **PKI secrets engine** — mounted, with a CA and a role constraining allowed common names, key type (RSA for Linux/Windows, EC P-256 for macOS), and TTL. The TTL is the rotation cadence; certificates cannot be renewed.
2. **Cert auth method** — enabled, with the PKI CA registered, and a role whose attached policies define what a certificate-authenticated token may do.
3. **Bootstrap issuance policy** — the LDAP/OIDC token needs a narrow, time-limited policy permitting `pki/sign/<role>` (or `pki/issue/<role>`) for the bootstrap.
4. **Operational cert-auth policy** — separate from the above; the ongoing capability of an mTLS-authenticated session.

## Limitations (v1)

- First-run **bootstrap** runs the configured OIDC or LDAP login directly — the same CLI-style flow used without the web UI, *not* the web SPA's login page. Even when the web UI is enabled, the certificate-auth path takes precedence over web-driven auth, so bootstrap needs a browser dotvault can open (OIDC) or a terminal to prompt on (LDAP); a host with neither must seed a certificate via `byo`. The steady-state cert login is fully headless — only the very first certificate on a new machine needs a human.
- **Bootstrap through the web SPA is not wired.** The SPA's login endpoints know only how to obtain and store an *operational* token; the bootstrap is a different shape — log in for a short-lived token, mint a certificate via `pki/sign`, seal the key, then cert-login — and that server-side issuance flow is not implemented, so the mtls path bypasses the SPA entirely. This is why a browser (OIDC) or TTY (LDAP) is still required even on a web-enabled host.

For `mtls+tpm`, the TPM hardware caveats — no physical-TPM coverage in CI, and the macOS Secure Enclave still being scaffolding — are covered under [TPM-Backed Protection](tpm.md#platform-support-and-limitations).
