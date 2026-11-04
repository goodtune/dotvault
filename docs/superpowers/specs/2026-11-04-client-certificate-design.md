# Client certificates for tools (FUSE, Docker volumes, client library)

Status: design, approved in conversation 2026-11-04.

## Intent

dotvault already knows how to get an X.509 client certificate signed by Vault's PKI engine — the certificate auth methods (`mtls`, `mtls+tpm`, `mtls+os`) do it through `vault.Client.SignCSR` → `<pki_mount>/sign/<role>`. This feature points that same capability at *other* services: any tool that speaks mTLS (curl, a database driver, an internal HTTP API, a gRPC client) should be able to identify the signed-in user with a certificate dotvault provides, the same way dotvault identifies the user to Vault.

The service on the far end is deliberately unspecified. The job is the plumbing: make a client certificate and its private key available through three pathways —

1. the FUSE mount (`~/.dotvault/client.crt`, `client.key`, and the combined `client.pem`);
2. Docker volumes (the same three files at the volume root, opt-in per volume);
3. the public `client/` Go package, and through it the Python bindings.

The motivating case is a remote host reached over SSH that authenticates by **borrowing** a token from a workstation (`vault.token_socket` / `vault.borrow_only`). Such a host holds a Vault token but no certificate, so it cannot today establish an mTLS session with anything. With this feature it signs a very short-lived certificate with its token and uses that.

## Goals

- `curl --cert ~/.dotvault/client.pem https://service.example` (or `--cert client.crt --key client.key`) works on any host with the feature enabled and a usable Vault token.
- A container started with a dotvault volume carrying `-o client_cert=true` can do the same with the files at the volume root.
- A Go program can obtain the pair (PEM and `tls.Certificate`) and a ready-made `*tls.Config` from `client/` in one call; a Python program can obtain the PEM pair.
- The certificate stays valid for as long as anything reads it: dotvault replaces it before it expires without any action from the consumer.

## Non-goals

- Choosing or configuring the remote service, its CA trust, or server-certificate verification (`--cacert`). Only the client side is in scope.
- A web API endpoint that hands out the pair, and peer-socket distribution of it. The `client/` package signs its own when it needs to (see below).
- Revocation of short-lived certificates. They expire in minutes; the recommended PKI role uses `no_store`.
- Windows support for the FUSE and Docker pathways (both are already Unix/Linux-only). The `client/` pathway works on every platform.
- Letting the per-user config overlay enable the section (see Configuration).

## Anti-goals

- **Exporting a non-exportable key.** Under `mtls+tpm` and `mtls+os` the Vault-auth key is hardware-sealed or in the OS store; this feature must never extract it, even where the backend technically unseals it into process memory. Those hosts fall back to signing a short-lived certificate.
- **Writing a short-lived key to persistent storage.** The signed key lives only in daemon memory. The one place it reaches a filesystem is a Docker volume directory, which is on the runtime tmpfs and deleted at the last unmount — accepted explicitly, because the engine bind-mounts plain files.
- **Logging key material**, or the certificate PEM, at any level. Log lines may carry serial, NotAfter, source, and CN.

## Decisions made with the owner

### Where the certificate comes from

Two sources, one output shape:

- **Held certificate.** When the daemon holds a Vault-auth certificate whose key is exportable — `auth_method: mtls` (the `file` securestore backend), including a bring-your-own certificate — serve that certificate and key as they are. The owner's reasoning: we trust the user's device, and this is the device's own credential being handed to the device's own processes. The served pair follows the auth credential's rotation (`reissue_before` / `ReissueIfDue`): after a rotation the new pair is served.
- **Ephemeral certificate.** Everywhere else — borrowed token, `oidc`, `ldap`, `token`, `mtls+tpm`, `mtls+os` — generate a key in memory, sign it via `<pki_mount>/sign/<pki_role>` with the daemon's current Vault token, and replace it before it expires. **Default TTL 5 minutes.** Stored only in daemon memory.

The rule "export only where the key is exportable" is decided by the configured method/backend, not by inspecting the in-memory key type: the TPM backend unseals its EC scalar into software, but `mtls+tpm` is still treated as non-exportable (anti-goal above).

### Configuration

A new **static, system-config-only** section:

```yaml
client_cert:
  enabled: false          # default
  pki_mount: pki          # default: vault.mtls.pki_mount if set, else "pki"
  pki_role: user-client   # default: vault.mtls.pki_role; required if still empty and an ephemeral cert may be needed
  common_name: "{{.token_username}}"
  ttl: 5m
```

- Off by default, like `fuse` and `docker`: it needs a PKI role and a token policy granting `pki/sign/<role>`.
- When the host uses plain `mtls`, the `pki_*`/`common_name`/`ttl` fields are unused (the held certificate is served).
- Not user-overridable via the per-user overlay (same posture as `docker`). Refused in a remote-config document (static section).
- Round-trips through YAML, the registry (`ClientCert` subkey), and `.reg`, like every section. Validated whether or not enabled, matching the `fuse`/`docker` convention.

### Files

- `client.crt`: the leaf certificate followed by the issuing CA chain, PEM — the form `vault.IssuedCert.CertPEM` already has, and what curl and most tools expect for `--cert`.
- `client.key`: the private key, PEM (PKCS#8). Mode 0400 in the mount; in a Docker volume it takes the volume's `mode` like every other file.
- `client.pem`: the same certificate chain followed by the same key in one file (decided with the owner after the builder check). Because a tool reads it in one go, it can never pair a certificate with the wrong key across a rotation, which the two separate files can when a replacement lands between two reads. The docs should recommend `curl --cert client.pem` for exactly that reason, and keep the two-file form for tools that need it. All three files are produced from a single in-memory pair, so any one read is self-consistent.
- FUSE: all three files at the mount root, present only when `client_cert.enabled`. They are always read-only, even on a `read_write` mount. If a KV folder named `client.crt`, `client.key` or `client.pem` exists at the root, the certificate wins and the daemon warns once, matching the mount's existing collision rule.
- Docker: `-o client_cert=true` adds all three files at the volume root, beside whatever `secrets=` selects. A volume that sets only `client_cert=true` and selects no secrets must be expressible (see open items).

### Client library

- `(*Client).ClientCertificate(ctx)` returns the PEM pair, the parsed leaf's NotAfter, and a `tls.Certificate`.
- A helper returns a `*tls.Config` whose client-certificate callback always presents a current certificate, so a caller writes `&http.Transport{TLSClientConfig: cfg}` once and never handles rotation.
- When the library has no exportable held certificate, it signs an ephemeral one itself with whichever token it resolved (env, file, peer borrow, or cert login) — so it works on a borrow-only host where no daemon is running.
- Python gets `client_certificate()` returning `(cert_pem, key_pem)`.

### Common name

Decided with the owner after the builder check: the default common name is the **Vault identity** of the token, not the local OS account. On a borrowing remote the OS account (`ubuntu`, `ec2-user`) is often not the person, and the far-end service identifies the user by this name. A PKI role that restricts names to the token's identity would refuse an OS-account name on every such remote.

- `common_name` is a template with two variables: `{{.token_username}}` and `{{.os_user}}` (`paths.Username()`). The default is `{{.token_username}}`.
- `{{.token_username}}` comes from `LookupSelf` on the token being used to sign: `data.meta.username`, which the LDAP and userpass auth methods set and an OIDC role can set through `claim_mappings`. It is looked up once per token and cached against that token's value. *Correction found while planning:* nothing in dotvault reads the token's username today. The SSH agent's `{{.vault_username}}` and the Copy engine's `{{.user}}` both expand to the local OS account, whatever their names suggest. So this lookup is new code, and the variable is deliberately **not** called `vault_username`, which would mean the opposite of what it means in `agent.keys[].principals`.
- *(my call)* Two existing token shapes would otherwise always fail the default, so both are handled:
  - **Downscoped tokens** (`vault.policies` / `no_default_policy`): a child token from `auth/token/create` carries no `meta` of its own. `vault.Client.CreateChildToken` gains a `meta map[string]string` parameter, and `auth.Downscope` passes the parent's `meta`, read with one `LookupSelf` on the isolated sibling client. Borrowed tokens are downscoped workstation tokens, so this is what makes the motivating case work once the workstation runs a build that carries it.
  - **Cert-auth tokens** (`mtls+tpm` / `mtls+os` falling back to an ephemeral certificate): the cert method sets `meta.common_name`, not `meta.username`. `{{.token_username}}` reads `meta.username` first, then `meta.common_name`.
- If the token carries no `meta.username`, signing fails with an error that names the cause and suggests `{{.os_user}}`. It never falls back silently to the OS name, because the service would then see a different person. `display_name` (e.g. `ldap-gary`) is not used: it is prefixed by the auth mount and is not a stable identity.
- *(my call)* `{{.user}}` and `{{.vault_username}}` are not accepted in `client_cert.common_name`, because each already means the OS account elsewhere. Config load rejects them with a message naming the two explicit variables.
- The held-certificate path is unaffected: it serves whatever name `vault.mtls.common_name` produced.

## Constraints from the existing code

- Signing: `vault.Client.SignCSR(ctx, mount, role, csrPEM, commonName, ttl)` in `internal/vault/certauth.go`; CSR construction: `buildCSR` in `internal/auth/mtls.go`. Reuse, don't duplicate — expect to move `buildCSR` (and the key-generation helper) somewhere both `internal/auth` and the new code can share.
- Held credential: the envelope in `internal/auth/mtls_envelope.go` plus the securestore `file` backend. `client/` already reaches this through `CertLoginFromStore` and the `MTLSConfig.StorageDir` projection.
- FUSE: `internal/vaultfs` is platform-neutral except `mount_fuse.go`. The mount sets kernel entry/attr timeouts equal to `cache_ttl` (`mount_fuse.go:200`); the certificate files change content and size on rotation, so they need their own (near-zero) kernel timeouts and must not be served stale by the package cache either.
- Docker: `internal/dockervol` renders then applies; files are replaced atomically. Refresh is per-volume ttl ticker (Community) or event-driven with the ticker *skipped* (Enterprise). Neither cadence tracks a 5-minute certificate, so a volume carrying the certificate needs an additional trigger on certificate replacement.
- `client/` may import `internal/*` but the Python `.so` must not grow dependencies on `internal/web`, `internal/notify`, or `internal/clipboard`.
- `CGO_ENABLED=0` for the binaries; no new cgo.
- Policy documentation: the "Least-privilege token policies" operator requirement gains `pki/sign/<client_cert.pki_role>` when this section is enabled.

## Left to the builder

These are the builder's calls; the ones below marked *(my call)* are what I'd do, recorded so they can be checked.

- **Package layout.** *(my call)* A new `internal/clientcert` package owning a source interface (`Current(ctx) (*Pair, error)` plus a change notification) with two implementations, held and ephemeral, consumed by `vaultfs`, `dockervol`, and `client/`.
- **Rotation timing for ephemeral certificates.** *(my call)* Sign lazily on first use; replace when less than half the certificate's actual lifetime remains (computed from the issued NotAfter, since the PKI role's `max_ttl` may shorten the request). Concurrent readers share one signing call (single-flight).
- **Key type.** *(my call)* EC P-256 by default, with optional `key_type`/`key_bits` mirroring `vault.mtls`'s rules (some services insist on RSA).
- **TTL bounds.** *(my call)* Positive duration, floor 1 minute so half-life rotation isn't continuous; no ceiling beyond the PKI role's own `max_ttl`.
- **`pki_*` defaults under `borrow_only`.** *(my call)* Inherit from `vault.mtls` even though `borrow_only` skips validating that block, so one base config serves the workstation and its remotes.
- **Behaviour with no token.** FUSE read returns an I/O error; Docker `Mount` of a volume needing a fresh certificate returns `ErrNoToken` as today; `client/` returns `ErrLoginRequired`. A 403 from `pki/sign` maps to `ErrDenied` in `client/` and to a status/log line naming the role in the daemon.
- **Status.** *(my call)* A `client_cert` block in `GET /api/v1/status` and `dotvault status`: source (held/ephemeral), CN, serial, NotAfter, last error. Never key or PEM.
- **Metrics.** *(my call)* Reuse `RecordVaultCall` (already emitted by `SignCSR`); no new instrument unless one falls out naturally.
- **Docs.** New guide page or sections in `docs/guide/filesystem.md` and `docs/guide/docker-volumes.md`, config reference entry, `client/README.md`, `python/README.md`, CLAUDE.md config-section bullet, `config.dev.yaml` entry, and a PKI role + policy in the dev stack's vault-init.

## Settled after the builder check

- **The held certificate is a Vault login credential, and that is accepted.** Under plain `mtls`, anything that reads `client.key` (a local process or a container holding the volume) can log in to Vault as the user until the certificate expires. The owner decided this on the grounds that the device and its processes are trusted, and that FUSE and Docker are reachable only by the user's own processes. Similarly, when `pki_role` is inherited from `vault.mtls.pki_role`, every ephemeral certificate also works as a Vault cert-auth login for its 5-minute life. The docs must say both plainly, and must recommend a separate `client_cert.pki_role` (with its own CA, or a role cert auth does not trust) for operators who want the two kept apart.
- **Rotation of the held certificate revokes the old one** (`vault.mtls.revoke_superseded`, default on). A consumer that loaded the old pair loses it at rotation. That is acceptable because rotation happens `reissue_before` (default 7 days) ahead of expiry and consumers re-read the files per connection. The docs must state it for long-lived processes that load the pair once.
- **The library is gated by the same section.** *(my call)* `client.LoadConfig` projects `client_cert` (enabled, pki mount, role, common name, ttl, key type) onto a new `client.ClientCertConfig`. `ClientCertificate` returns a new `ErrNotConfigured` sentinel when the section is disabled, or when no role is available and no exportable held certificate exists. A consumer on a host with no system config can fill `ClientCertConfig` by hand. This deliberately relaxes the current rule that the facade cannot issue anything. That rule exists to keep the *auth-credential* bootstrap (browser/TTY + persisted certificate) out of library callers, and that stays true. Signing an in-memory ephemeral certificate with an already-resolved token needs no human and persists nothing. CLAUDE.md's "Public client API" section must be updated to say so.
- **Under plain `mtls` with no usable held certificate** (missing, expired, unreadable envelope): fall back to an ephemeral certificate when a role is available (configured or inherited), otherwise return an error naming the cause. *(my call)* This keeps `pki_role` optional under `mtls`, and validation does not change.

## Open items

- Docker volume with `client_cert=true` and nothing else: today an empty `secrets=` means "the whole subtree". The builder must pick an explicit spelling for "no secrets" rather than letting `client_cert=true` silently publish everything.
