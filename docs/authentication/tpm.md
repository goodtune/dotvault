# TPM-Backed Protection

dotvault can protect the credentials it caches on disk by sealing them under the machine's Trusted Platform Module (TPM). Sealing binds the data to the physical chip: the sealed blob is tied to that TPM's Storage Root Key and is useless on any other machine. Two kinds of credential can be sealed — the cached Vault token, available to every auth method through a `+tpm` suffix, and (for certificate authentication) the certificate's private key, which `mtls+tpm` seals intrinsically.

## What it protects against

Without sealing, a cached Vault token sits in `~/.dotvault-token` as plaintext at `0600`: anyone who can read the file, or who lifts a disk image or a backup, holds a usable token until it expires. Sealing closes that window — a stolen disk yields only an opaque blob that cannot be unsealed off the originating chip (and, for the certificate key bound with `seal_to_pcrs`, off the sealed boot state). It is at-rest protection that needs no passphrase to manage and stays transparent to everything that reads the credential. For `mtls+tpm` the result is that **nothing sensitive sits on disk in plaintext** — neither the long-lived key nor the operational token.

## How to use it

Append `+tpm` to any token-minting auth method:

```yaml
vault:
  address: https://vault.example.com:8200
  auth_method: oidc+tpm          # normal OIDC login; the cached token is TPM-sealed
```

`oidc+tpm`, `ldap+tpm`, and `mtls+tpm` are all valid. The login flow for the base method is unchanged — only how the resulting token rests on disk differs. For `mtls+tpm` the certificate's private key is sealed as well (see [Certificate Authentication](mtls.md)). The bare `token` method has no token of its own to seal — it consumes one you supply — so `token+tpm` has no sealing effect, though it will still read a sealed file transparently.

### Behaviour

- **Self-describing file.** A sealed token file carries a `$dotvault-tpm-sealed$v1$` marker and a sealed, base64 body; dotvault detects the marker on read and unseals automatically, while a plaintext file is read verbatim. Nothing keys off the auth method to *read* a token, so the daemon, `dotvault status`/`enrol`, the token-file watcher, and the embeddable `client` library all consume a sealed token with no extra wiring.
- **Free migration.** Turning the suffix on does not require clearing an existing token — the next login replaces it with a sealed one — and turning it off again is equally seamless.
- **No silent plaintext fallback.** A `+tpm` method on a host with no working TPM fails fast at login with a clear error rather than quietly writing a plaintext token.
- **The environment variable stays plaintext.** `DOTVAULT_TOKEN` cannot be sealed (it is an environment value); the seal protects the on-disk file only.
- **The token is chip-bound, not boot-bound.** The token seal binds to the TPM only, never to PCRs — the token is short-lived and re-derivable, so a firmware update should not strand it. (The certificate key can optionally bind to boot state via `seal_to_pcrs`; see the certificate doc.) A sealed token copied to another machine, or surviving a TPM clear, simply fails to unseal and triggers a normal re-authentication.

## Platform support and limitations

dotvault speaks to the TPM through a pure-Go backend (`go-tpm`/`go-tpm-tools`) — no CGO and no external daemon. It seals EC P-256 keys only: a TPM sealed-data object's sensitive area is size-bounded (a P-256 scalar fits where an RSA key would not), and EC is also the macOS Secure Enclave's only algorithm, which keeps cross-platform configs portable.

- **Linux** — TPM 2.0 via `/dev/tpmrm0`. A standard user needs membership of the `tss` group; no elevation and no signing.
- **Windows 10/11** — TPM 2.0 via TBS (a system service that is always running); any logged-in standard user can use it with no elevation or group membership. dotvault derives the Storage Root Key as a *transient* primary key rather than persisting it to a reserved handle, because persisting requires `TPM2_EvictControl` — an owner-hierarchy operation Windows TBS blocks for standard-user processes, which would otherwise fail with `0x80280400` even on a healthy TPM. Primary keys are deterministic, so re-deriving on every operation still unseals anything sealed earlier. With `seal_to_pcrs`, dotvault also **excludes PCR7** (Secure Boot state) on Windows because BitLocker claims it; the seal binds to PCRs 0/2/4 instead, so a tampered boot still breaks the unseal without coupling the credential to BitLocker's re-seal cycle.
- **macOS** — the Secure Enclave is the hardware equivalent but requires the binary to be code-signed with Apple keychain entitlements. Until that signing infrastructure is in place, any `+tpm` method returns a clear "no hardware backend" error on macOS rather than degrading to a plaintext credential. The architecture slots the Enclave in with no caller changes once signing lands.

The TPM backend is CGO-free and builds on every platform, but it is not exercised against physical TPM hardware in CI (which has no TPM, and whose simulator requires CGO) — validate on your target hardware before a fleet rollout.
