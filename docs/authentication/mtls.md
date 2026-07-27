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
5. **Recover.** The Vault *token* and the *certificate* have independent lifetimes, and the token is usually much shorter-lived. If it expires or is revoked mid-session — or reaches its `max_ttl` and can no longer be renewed — dotvault re-runs the certificate login automatically and carries on. Nothing is asked of the user and no restart is required, which is the whole point of a credential that lives on the host. Recovery retries on the token manager's ~10s recovery poll, so a transient outage (Vault briefly unreachable) heals by itself once the cause clears. It deliberately never escalates to a bootstrap: if the certificate itself is gone or expired past re-issue, dotvault reports that rather than launching a browser at a machine nobody is sitting in front of.

`mtls+tpm` adds machine binding: the certificate's private key is sealed under the TPM, so the sealed blob is useless on any other machine, and with `seal_to_pcrs` it is also useless after a firmware or Secure Boot change. If an unseal fails, dotvault surfaces a clear error and offers the bootstrap fallback rather than silently dropping hardware protection. The hardware backend, its platform support, the EC-P-256 requirement, and the Windows PCR7 handling are all documented in [TPM-Backed Protection](tpm.md) — and `mtls+tpm` also seals the cached token at rest, exactly like any other `+tpm` method.

## OS-native certificate store (`mtls+os`)

`mtls+os` puts the issued certificate **and** its private key into the operating system's own certificate store rather than dotvault's private cache. The point is interoperability: once the certificate lives in the OS store, *other* software on the machine can present it for mTLS — most importantly the system browsers. In a corporate environment where services trust the Vault CA (and honour its CRL), a single Vault-issued certificate becomes a general-purpose user identity for browser-based mTLS authentication, kept fresh automatically by dotvault, with no human credential after the first bootstrap.

On Windows the key is generated in the **current user's** CNG key store (the *Microsoft Software Key Storage Provider*, DPAPI-protected — no administrator rights needed) and the certificate is installed into `Certificates - Current User → Personal` (`CurrentUser\My`), which is exactly where Edge and Chrome look for client certificates. dotvault never exports the key; it stays in the store and dotvault signs through it for both the Vault cert-auth handshake and ongoing rotation.

The private key is **non-exportable**. Because dotvault generates the key inside the store (rather than importing a `.pfx`), the key is created with the CNG default export policy — `NCRYPT_ALLOW_EXPORT_NONE` — so a user cannot extract the private key from the certificate store and reuse the Vault-issued identity on another machine; only in-place signing is possible. dotvault verifies this after generation and refuses to proceed if the key is ever reported exportable, rather than assuming the default holds.

Differences from the other cert methods:

- **Platform support.** `mtls+os` is **Windows-only** today (it is built on [`github.com/google/certtostore`](https://github.com/google/certtostore), a Windows-CNG library). On Linux and macOS it fails fast with a clear "OS-native certificate store is unavailable" error rather than degrading to an on-disk key — Linux (PKCS#11/NSS) and macOS (Keychain) backends are planned follow-ups. Use `mtls` or `mtls+tpm` on those platforms.
- **No bring-your-own.** The OS store can install a certificate but cannot import an external private key, so `byo` is rejected at config-load for `mtls+os`. The key is always generated in the store and certified via `pki/sign`. (Use `mtls` for BYO.)
- **Certificate TTL defaults to 30 days.** Because the credential doubles as a browser-presented user identity, an unset `ttl` defaults to `720h` (30d) for `mtls+os` (plain `mtls`/`mtls+tpm` leave it to the PKI role). dotvault requests this length; **the Vault PKI role's `max_ttl` is still the authoritative cap**, and `reissue_before` (default 7d) drives automatic rotation well before expiry.
- **Key types.** Both `ec` (P-256) and `rsa` are accepted, like plain `mtls` (only `mtls+tpm` is EC-only). RSA defaults to 2048 and is sized by `key_bits`; the backend opens the *software* KSP (`ProviderMSSoftware`), whose 16384-bit ceiling means 3072/4096/8192 all work. Had it used the TPM KSP, RSA would be capped at 2048 and larger sizes would fail at runtime.
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
    key_type: ec                 # ec (P-256) | rsa; mtls+tpm is ec-only
    key_bits: 0                  # RSA modulus: 2048 | 3072 | 4096 | 8192; 0 = 2048. rsa only
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

### RSA key size (`key_bits`)

A Vault PKI role's `key_bits` is a **minimum, not an exact match**: `pki/sign` compares the CSR's actual key length against the role's and rejects anything smaller. So a role configured with `key_bits: 4096` — a common hardening convention — refuses a 2048-bit CSR outright, and until this option existed dotvault generated 2048-bit RSA keys unconditionally, leaving operators with a stricter role no way to use certificate auth at all short of weakening the role.

Set `key_bits` to match (or exceed) whatever the PKI role requires:

```yaml
vault:
  auth_method: mtls
  mtls:
    key_type: rsa
    key_bits: 4096   # the PKI role pins RSA at 4096
```

Accepted values are the RSA lengths Vault itself accepts: `2048`, `3072`, `4096`, `8192`. Unset (or `0`) keeps the previous behaviour of 2048, so upgrading changes nothing for anyone who does not set it. It applies to `mtls` and `mtls+os` alike. It is rejected at config load under `key_type: ec` (EC is fixed at P-256, and Vault's EC floor is a curve name rather than a tunable bit count) and under `mtls+tpm` (EC-only, so there is no modulus to size) — rejected rather than ignored, because an operator who sets it believes they have changed the key size.

!!! warning "It applies to the next key, not the current one"
    `key_bits` is consulted only when dotvault *generates* a key — at first enrolment, and at each rotation. An existing, still-valid credential is reused as-is, so changing `key_bits` on a host that already holds a certificate does **not** resize it: that host keeps presenting its current key until the certificate rotates (inside `reissue_before` of expiry) or the credential is removed and re-seeded.

    If you are adopting a stricter PKI role and need the new size immediately, delete the credential envelope from `storage_dir` and let dotvault bootstrap afresh, rather than waiting for rotation.

    Bring-your-own is the subtle case, because the two halves differ. The **seeded** credential uses the key you supplied, so `key_bits` has no effect on it — if that key is 1024-bit, it stays 1024-bit no matter what `key_bits` says. But dotvault generates the key itself at every **rotation**, and that generation *does* honour `key_bits`. So a BYO host silently moves to the configured size at its first rotation. This is deliberate — it is the only way a BYO deployment can ever control the size of the keys dotvault goes on to generate — but do not read `key_bits` as a statement about the certificate a BYO host is presenting *today*.

Note that larger keys are slower to generate: 8192-bit RSA can take several seconds, which is paid once at enrolment and again at each rotation.

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

- First-run **bootstrap** is the only step that needs a human; the steady-state cert login is fully headless. How that human is prompted depends on whether the web UI is enabled. **With `web.enabled: true`** the bootstrap runs through the SPA: the daemon opens the browser at the web UI, the SPA presents whichever credential flow `bootstrap_method` names (the same LDAP-with-MFA or OIDC login it already serves), and no TTY is involved — which is what makes bootstrap work under `dotvaultw.exe`, the GUI-subsystem Windows binary that has no console to prompt on. **Without the web UI** the bootstrap falls back to the CLI flow, needing a browser dotvault can open (OIDC) or a terminal to prompt on (LDAP); a host with neither must seed a certificate via `byo`. Note the sharp edge this leaves on Windows: `dotvaultw.exe` has no console, so `bootstrap_method: ldap` with the web UI disabled cannot prompt and the daemon exits with an error rather than idling. On that combination either enable the web UI (the recommended fix, and the reason this path exists), run the first bootstrap once through `dotvault.exe` from a console, or seed via `byo`. `bootstrap_method: oidc` is unaffected — it opens a browser via `ShellExecute` and needs no console.
- The bootstrap token is **not revoked** after the certificate is minted. It is transient and never persisted — it lives only on an isolated in-memory client, is never downscoped, never written to the token cache, and never exposed through `GET /api/v1/token` — but dotvault does not call `auth/token/revoke-self` on it, so it remains valid at Vault until its own TTL expires. Keep the bootstrap policy narrow and short-lived.

For `mtls+tpm`, the TPM hardware caveats — no physical-TPM coverage in CI, and the macOS Secure Enclave still being scaffolding — are covered under [TPM-Backed Protection](tpm.md#platform-support-and-limitations).
