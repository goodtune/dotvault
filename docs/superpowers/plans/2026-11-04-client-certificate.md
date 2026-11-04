# Client Certificates for Tools Implementation Plan

> **Historical.** This is the plan the feature was built from. Several details changed in review, so the shipped behaviour is described by CLAUDE.md ("Client certificates for tools") and the user docs, not here.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve a client certificate (`client.crt`, `client.key`, `client.pem`) that tools can use for mTLS. It comes through the FUSE mount, Docker volumes, the `client/` Go package and the Python bindings. The certificate is either the held `mtls` credential or a 5-minute certificate signed in memory.

**Architecture:** A new `internal/clientcert` package owns one `Source` interface with two implementations, *held* (export the plain-`mtls` envelope) and *ephemeral* (in-memory key, `pki/sign`, half-life rotation). A selector picks between them from config. `vaultfs`, `dockervol` and `client/` consume `clientcert.Source` and render one `Pair` into three byte slices. A new static `client_cert` config section drives it and round-trips through YAML, the registry and `.reg`.

**Tech Stack:** Go (`crypto/x509`, `crypto/tls`; single-flight via a mutex-guarded in-flight channel — `golang.org/x/sync` is not a dependency and must not be added for this), `github.com/hanwen/go-fuse/v2`, cgo bridge + ctypes for Python.

**Spec:** `docs/superpowers/specs/2026-11-04-client-certificate-design.md`

## Global Constraints

- Config section name `client_cert`; fields `enabled`, `pki_mount`, `pki_role`, `common_name`, `ttl`, `key_type`, `key_bits`. Defaults: `enabled: false`, `ttl: 5m`, `common_name: "{{.token_username}}"`, `key_type: ec`. `pki_mount` falls back to `vault.mtls.pki_mount`, else `"pki"`. `pki_role` falls back to `vault.mtls.pki_role`. Both inherit even under `vault.borrow_only`.
- TTL floor 1 minute, no ceiling. Rotation when less than half of the *issued* lifetime (`NotAfter − NotBefore`) remains.
- Template variables are only `{{.token_username}}` and `{{.os_user}}`. `{{.user}}` and `{{.vault_username}}` are rejected at config load with a message naming both.
- `{{.token_username}}` = `LookupSelf` `data.meta.username`, else `data.meta.common_name`. If neither is present it is an error naming the cause and suggesting `{{.os_user}}`. It never silently falls back.
- Held source only when `auth.BaseMethod(auth_method) == "mtls"` and the full method is exactly `mtls` (the securestore `file` backend). `mtls+tpm`, `mtls+os` and every non-cert method use the ephemeral source. The decision is based on the configured method, never on the in-memory key type.
- Under plain `mtls` with no usable held credential: ephemeral if a role is resolvable, else an error.
- File names: `client.crt` (leaf + chain, exactly `IssuedCert.CertPEM` / envelope `CertPEM`), `client.key` (PKCS#8 PEM), `client.pem` (crt bytes followed by key bytes). All three are produced from one `Pair` value.
- Section is static (restart required), refused in remote documents, and not user-overridable (the overlay's reflection-based section check already refuses it; add a test).
- Key material and PEM never appear in logs or errors. Log only serial, NotAfter, source, CN.
- `CGO_ENABLED=0` for binaries; no new cgo; the Python `.so` must not import `internal/web`, `internal/notify`, `internal/clipboard`.
- PR bodies/commit bodies in flowing prose (repo CLAUDE.md); never `git add -A`.

## Review Focus

1. **Token lost mid-life** (web-mode re-auth clears the token): a read of `client.pem` while the cached pair is still valid must still succeed. Only a *refresh* needs a token. → Task 5 test `TestEphemeralServesCachedPairWithoutToken`.
2. **Concurrent first reads** (`curl` reading `.crt` and `.key` in parallel, or many containers mounting at once) must cause one `pki/sign`, not N. → Task 5 test `TestEphemeralSingleFlight`.
3. **PKI role caps the TTL** below the request (e.g. role `max_ttl=2m`, request `5m`): rotation must use the issued NotAfter, not the requested TTL. Otherwise the file serves an expired certificate. → Task 5 test `TestEphemeralRotatesOnIssuedLifetime`.
4. **Held credential rotated by `ReissueIfDue`** while the daemon runs: the next read must serve the new pair, not a cached old (revoked) one. → Task 6 test `TestHeldReloadsAfterRotation`.
5. **Docker volume on Enterprise with a live event subscription** (ticker skipped) must still re-render before the certificate expires. → Task 9 test `TestVolumeClientCertRefreshesWhileEventsDrive`.

---

### Task 1: Downscoped tokens carry the parent's metadata

**Files:**
- Modify: `internal/vault/client.go:313-370` (`CreateChildToken`, `CreateChildTokenFor`)
- Modify: `internal/auth/downscope.go:63`
- Test: `internal/auth/downscope_test.go`, `internal/vault/client_test.go`

**Interfaces:**
- Produces: `func (c *Client) CreateChildToken(ctx context.Context, policies []string, noDefaultPolicy bool, meta map[string]string) (string, error)`. `CreateChildTokenFor` reads the parent's `meta` via `LookupSelf` on the sibling, then passes it on. It is best effort: if the lookup fails or `meta` is absent, it mints without meta and logs one DEBUG line. The downscope must not fail closed on a metadata read.
- Produces: `func TokenMeta(secret *vaultapi.Secret) map[string]string` in `internal/vault/client.go` (extracts `data.meta` as strings; nil-safe). Task 5 reuses it.

- [ ] **Step 1: Write failing tests.** `TestDownscopeCopiesParentMeta`: the fake server answers `GET /v1/auth/token/lookup-self` with `{"data":{"meta":{"username":"gary","role":"r"}}}` and asserts the `POST /v1/auth/token/create` body has `"meta":{"username":"gary","role":"r"}`. `TestDownscopeMintsWhenLookupFails`: lookup-self returns 403, create still succeeds, `Downscope` returns the child. Update `TestDownscopeActive` so it accepts the lookup-self path. `TestTokenMeta` covers a nil secret, absent meta, and non-string values being skipped.
- [ ] **Step 2: Run** `go test ./internal/auth/ ./internal/vault/ -run 'Downscope|TokenMeta'`. Expected: FAIL (meta missing / undefined `TokenMeta`).
- [ ] **Step 3: Implement.** Set `vaultapi.TokenCreateRequest.Metadata`. Fix every existing `CreateChildToken` caller (`grep -rn CreateChildToken`).
- [ ] **Step 4: Run** `go test ./internal/auth/ ./internal/vault/`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(auth): carry parent token metadata onto downscoped child tokens`.

### Task 2: `client_cert` config section — struct, defaults, validation

**Files:**
- Create: `internal/config/clientcert.go`, `internal/config/clientcert_test.go`
- Modify: `internal/config/config.go:119-120` (add `ClientCert ClientCertConfig \`yaml:"client_cert,omitempty"\`` after `Docker`), `internal/config/config.go:1429` (call `validateClientCert`), `internal/config/partial.go:34` (add `"client_cert"` to the static list), `cmd/dotvault/main.go:424-546` (`staticSections` struct + `changedStaticSections` entry `"client_cert"`)

**Interfaces:**
- Produces:
  ```go
  const DefaultClientCertTTL = 5 * time.Minute
  const MinClientCertTTL = time.Minute
  const DefaultClientCertCommonName = "{{.token_username}}"
  type ClientCertConfig struct {
      Enabled    bool   `yaml:"enabled"`
      PKIMount   string `yaml:"pki_mount"`
      PKIRole    string `yaml:"pki_role"`
      CommonName string `yaml:"common_name"`
      RawTTL     string `yaml:"ttl"`
      TTL        time.Duration `yaml:"-"`
      KeyType    string `yaml:"key_type"`
      KeyBits    int    `yaml:"key_bits"`
  }
  func (c *Config) ClientCertPKIMount() string   // own → vault.mtls.pki_mount → "pki"
  func (c *Config) ClientCertPKIRole() string    // own → vault.mtls.pki_role → ""
  func (c *Config) ClientCertCommonName() string // own → DefaultClientCertCommonName
  func (c *Config) ClientCertHeld() bool         // Enabled && Vault.AuthMethod == "mtls"
  ```
  The inner fields carry no `omitempty` (the round-trip rule in the `DockerConfig` comment).
- `validateClientCert` runs whether or not the section is enabled. It parses `RawTTL` (empty → default; `< MinClientCertTTL` → error), checks `key_type`/`key_bits` with the same rules and messages as `validateMTLS` (factor out a shared helper `validateKeyParams(prefix, keyType string, bits int) (string, error)` rather than copying), and parses `common_name` as a `text/template`. A template that references a field other than `token_username`/`os_user` is rejected. Detect references by walking the parse tree's `FieldNode`s. When enabled and `!ClientCertHeld()` and `ClientCertPKIRole() == ""`, it errors: `client_cert.pki_role is required (no vault.mtls.pki_role to inherit)`.

- [ ] **Step 1: Write failing tests** in `clientcert_test.go`: `TestClientCertDefaults` (TTL 5m, CN default, key_type ec, mount "pki"), `TestClientCertInheritsMTLSPKI` (including under `borrow_only: true`), `TestClientCertTTLFloor` (`30s` → error containing `1m0s`), `TestClientCertRejectsAmbiguousTemplateVars` (`{{.user}}` and `{{.vault_username}}` → error containing both `token_username` and `os_user`), `TestClientCertRoleRequired`, `TestClientCertHeldNeedsNoRole` (method `mtls`, no role anywhere → ok), `TestClientCertValidatedWhenDisabled` (bad ttl with `enabled: false` → error), `TestClientCertRefusedInRemoteDocument` (`ParsePartial` with `client_cert:` → static-section error), `TestClientCertNotUserOverridable` (`ParseUserConfig` with `client_cert:` → error naming it). Existing mtls key tests must still pass after the helper is factored out.
- [ ] **Step 2: Run** `go test ./internal/config/ -run ClientCert`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** the struct, accessors, validation and the static-section entries.
- [ ] **Step 4: Run** `go test ./internal/config/ ./cmd/dotvault/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(config): add client_cert section`.

### Task 3: `client_cert` registry and `.reg` round-trip

**Files:**
- Modify: `internal/config/registry_windows.go` (layer fields + read `ClientCert` subkey beside `Docker` at :556 and apply beside :786), `internal/regfile/regfile.go:54,421` (`writeClientCert`), `internal/regfile/parse.go:~910` (parse `ClientCert` key)
- Test: create `internal/regfile/clientcert_test.go`; add to `internal/config/registry_windows_test.go`

**Interfaces:**
- Registry subkey `ClientCert` with: `Enabled` (REG_DWORD) and `KeyBits` (REG_DWORD, omitted when 0), plus `PKIMount`, `PKIRole`, `CommonName`, `TTL` (the raw string) and `KeyType` (all REG_SZ, always emitted, even empty).

- [ ] **Step 1: Write failing tests.** `TestClientCertRegRoundTrip`: a YAML config with every field set → `reg-import` render → parse → equal `ClientCertConfig`. Run it for both ASCII and UTF-16. `TestClientCertRegClearsEmpty`: an empty `pki_role` re-emits as `""`. Add a Windows-tagged loader test mirroring the Docker one.
- [ ] **Step 2: Run** `go test ./internal/regfile/ -run ClientCert`. Expected: FAIL.
- [ ] **Step 3: Implement** the three surfaces in lockstep.
- [ ] **Step 4: Run** `go test ./internal/regfile/ ./internal/config/ && GOOS=windows go vet ./internal/config/`. Expected: PASS / clean.
- [ ] **Step 5: Commit** `feat(config): round-trip client_cert through the registry and .reg`.

### Task 4: Export the held certificate and share CSR/key helpers

**Files:**
- Modify: `internal/auth/mtls.go:891` (export `buildCSR` as `BuildCSR`; keep a private alias only if needed by tests), `internal/securestore/securestore.go:265` (export `newSoftwareKey` as `NewSoftwareKey(kt KeyType, bits int) (crypto.Signer, error)`)
- Create: `internal/auth/held.go`, `internal/auth/held_test.go`

**Interfaces:**
- Produces:
  ```go
  type HeldCertificate struct {
      CertPEM  []byte    // leaf + chain, verbatim from the envelope
      KeyPEM   []byte    // PKCS#8
      NotAfter time.Time
      Serial   string
      ModTime  time.Time // credential.json mtime, for change detection
  }
  var ErrHeldNotExportable = errors.New("held certificate key is not exportable")
  func ExportHeldCertificate(storageDir, method, username string) (*HeldCertificate, error)
  func BuildCSR(signer crypto.Signer, commonName string) (string, error)
  ```
  `ExportHeldCertificate` returns `ErrHeldNotExportable` unless `method == "mtls"` and the envelope's `Backend == "file"`. It wraps `ErrNoCertCredential` when the envelope is absent, expired, or belongs to another identity (the same checks as `loginWithCredential`). The key comes from `securestore.Open("file").Load(handle)` and is re-marshalled to PKCS#8. Never return the handle bytes as-is: they may be a legacy encoding.

- [ ] **Step 1: Write failing tests.** `TestExportHeldCertificate` writes an envelope with a file-backend key and asserts that `KeyPEM` parses and matches the certificate's public key. `TestExportHeldRefusesTPMAndOS` covers envelopes with `Backend: "tpm"` / `"os"` and method `mtls+tpm` and returns `ErrHeldNotExportable`. `TestExportHeldExpired` returns an error wrapping `ErrNoCertCredential`. `TestExportHeldWrongIdentity` covers an envelope belonging to a different user.
- [ ] **Step 2: Run** `go test ./internal/auth/ -run ExportHeld`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/auth/ ./internal/securestore/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(auth): export the held mtls certificate for tool use`.

### Task 5: `internal/clientcert` — Pair, Source, ephemeral source

**Files:**
- Create: `internal/clientcert/clientcert.go`, `internal/clientcert/ephemeral.go`, `internal/clientcert/ephemeral_test.go`

**Interfaces:**
- Produces:
  ```go
  type Pair struct {
      CertPEM    []byte    // client.crt
      KeyPEM     []byte    // client.key
      NotBefore  time.Time
      NotAfter   time.Time
      RefreshAt  time.Time // NotBefore + (NotAfter-NotBefore)/2
      Serial     string
      CommonName string
      Source     string    // "held" | "ephemeral"
  }
  func (p *Pair) Combined() []byte                         // client.pem: CertPEM + KeyPEM (newline-separated if CertPEM lacks a trailing \n)
  func (p *Pair) TLSCertificate() (tls.Certificate, error)
  type Source interface { Current(ctx context.Context) (*Pair, error) }
  var ErrNoToken = errors.New("clientcert: no Vault token to sign a certificate with")
  var ErrNoUsername = errors.New("clientcert: the Vault token carries no username (meta.username or meta.common_name); set client_cert.common_name to {{.os_user}} or configure the auth method to record one")
  type Signer interface {
      Token() string
      LookupSelf(ctx context.Context) (*vaultapi.Secret, error)
      SignCSR(ctx context.Context, mount, role, csrPEM, commonName, ttl string) (*vault.IssuedCert, error)
  }   // *vault.Client satisfies it
  type EphemeralOptions struct {
      PKIMount, PKIRole, CommonName string
      TTL     time.Duration
      KeyType string; KeyBits int
      OSUser  string
      Now     func() time.Time // nil = time.Now
  }
  func NewEphemeral(s Signer, o EphemeralOptions) (Source, error) // parses the CN template once
  func (p *Pair) Fingerprint() string // SHA-256 of the leaf DER, hex; for status/tests
  ```
- Behaviour: `Current` returns the cached pair while `now < RefreshAt`. Otherwise it signs a new one. Concurrent callers share one in-flight sign. If signing fails while the cached pair has not reached `NotAfter`, it returns the cached pair and logs a WARN once per failure streak. If signing fails and no valid pair is cached, it returns the error. With no token (`Token() == ""`), a valid cached pair is still returned; otherwise the error is `ErrNoToken`. `token_username` is looked up once per distinct token value: store the SHA-256 of the token, never the token itself. Key generation goes through `securestore.NewSoftwareKey`, the CSR through `auth.BuildCSR`. The TTL goes to Vault as `TTL.String()`.

- [ ] **Step 1: Write failing tests** against a fake `Signer` that issues real certificates from an in-test CA, so NotBefore/NotAfter are honoured:
  - `TestEphemeralSignsOnFirstUse`: one `SignCSR` call. The CN is `gary` from `meta.username`. `KeyPEM` matches the certificate. `Combined()` equals crt+key.
  - `TestEphemeralCachesUntilHalfLife`: two calls before RefreshAt make one sign; advancing `Now` past RefreshAt gives a second sign and a different serial.
  - `TestEphemeralRotatesOnIssuedLifetime`: the fake caps the lifetime at 2m when 5m is requested, so RefreshAt = NotBefore+1m.
  - `TestEphemeralSingleFlight`: 20 goroutines make 1 sign.
  - `TestEphemeralServesCachedPairWithoutToken`: after a pair exists, `Token()` returns "" and the cached pair is still returned. Past NotAfter the result is `ErrNoToken`.
  - `TestEphemeralKeepsCachedPairOnSignFailure`: past RefreshAt the sign fails, and the old pair is returned until NotAfter.
  - `TestEphemeralCommonNameFallsBackToMetaCommonName`, `TestEphemeralNoUsernameErrors` (`errors.Is(err, ErrNoUsername)`), and `TestEphemeralOSUserTemplate` (`{{.os_user}}` → `OSUser`, no LookupSelf call).
  - `TestEphemeralNeverLogsKey`: capture slog through a buffer handler across a failure path and assert that `-----BEGIN` is absent.
- [ ] **Step 2: Run** `go test ./internal/clientcert/`. Expected: FAIL (package missing).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./internal/clientcert/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(clientcert): in-memory short-lived client certificates`.

### Task 6: Held source and source selection

**Files:**
- Create: `internal/clientcert/held.go`, `internal/clientcert/select.go`, tests beside them

**Interfaces:**
- Consumes: `auth.ExportHeldCertificate` (Task 4), `NewEphemeral` (Task 5), the `config.ClientCert*` accessors (Task 2).
- Produces:
  ```go
  func NewHeld(storageDir, method, username string, reissueBefore time.Duration) Source
  type Params struct {
      Enabled       bool
      Held          bool          // config.ClientCertHeld()
      Method        string        // vault.auth_method, for NewHeld
      StorageDir    string        // vault.mtls storage dir
      ReissueBefore time.Duration // vault.mtls.reissue_before
      Ephemeral     EphemeralOptions // PKIRole may be "" (then no fallback)
  }
  func ParamsFromConfig(cfg *config.Config, osUser, mtlsStorageDir string) Params
  func NewFromParams(p Params, s Signer) (Source, error) // nil, nil when !p.Enabled — the ONE selection function
  func New(cfg *config.Config, s Signer, osUser, mtlsStorageDir string) (Source, error) // = NewFromParams(ParamsFromConfig(...), s)
  ```
  `client/` (Task 11) builds a `Params` from its own projection and calls `NewFromParams`, so selection has one implementation.
  `NewHeld.Current` stats `credential.json` and re-exports only when mtime changed. `RefreshAt` = NotAfter minus `vault.mtls.reissue_before`. Pass that in, or use `NotAfter − (NotAfter−NotBefore)/2` when it is unknown. Its job is to tell Docker when to look again. `New` returns a `fallbackSource` when `cfg.ClientCertHeld()`. That source tries held first. On an error wrapping `auth.ErrNoCertCredential`, it uses the ephemeral source if `cfg.ClientCertPKIRole() != ""`; otherwise it returns the held error. When the section is not held, `New` returns the ephemeral source directly.

- [ ] **Step 1: Write failing tests.** `TestHeldServesEnvelope`. `TestHeldReloadsAfterRotation`: rewrite the envelope with a new cert and bump its mtime, and the next `Current` has the new serial. `TestNewPicksEphemeralForTPMAndOIDC` (table over `mtls+tpm`, `mtls+os`, `oidc`, `ldap`, `token`). `TestHeldFallsBackToEphemeral`: no envelope and a role present means an ephemeral pair. `TestHeldNoFallbackWithoutRole`. `TestNewDisabledReturnsNil`.
- [ ] **Step 2: Run** `go test ./internal/clientcert/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./internal/clientcert/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(clientcert): serve the held mtls certificate, falling back to short-lived`.

### Task 7: FUSE — certificate files at the mount root

**Files:**
- Modify: `internal/vaultfs/tree.go` (`Tree` gains `clientCert clientcert.Source`), `internal/vaultfs/service.go:14` (`Options.ClientCert clientcert.Source`), `internal/vaultfs/mount_fuse.go:306-626` (Getattr / Lookup / newChild / Open for certificate nodes)
- Test: `internal/vaultfs/tree_test.go`, `internal/vaultfs/mount_fuse_test.go`

**Interfaces:**
- Produces: `const ClientCertFile = "client.crt"; ClientKeyFile = "client.key"; ClientPEMFile = "client.pem"`, and `func IsClientCertPath(p string) bool` (true only for those names at the root).
- `NewTree(store, readWrite, cacheTTL)` keeps its signature. Add `func (t *Tree) SetClientCert(s clientcert.Source)`, called by `NewService`.
- `Tree.Readdir("")` adds the three entries as `KindFile` when a source is set. A KV folder with one of those names is dropped from the listing, through `warnCollision` with a cause naming the certificate. `Tree.Lookup("", name)` answers those names before any Vault call. `Tree.Document(path)` for those names calls `Current` and builds a `Document{Bytes, ModTime: pair.NotBefore, Version: 0}`. It never reads or writes `t.cache`. A source error is returned wrapped; no PEM goes in the message. `Put`/`Remove` on those paths return `ErrReadOnly` even when `readWrite`. `Mkdir`/`Create` of those names at the root fail too.
- In `mount_fuse.go`, certificate nodes get `EntryOut`/`AttrOut` timeouts of 0. `Open` returns `fuse.FOPEN_DIRECT_IO` for them, and the handle snapshots one `Document` at open so a reader never sees a crt from one pair and the tail of another in the same file. File mode stays 0400 (the same as `fileMode()` on a read-only mount); on a read-write mount it is forced to 0400 too.

- [ ] **Step 1: Write failing tests** in `tree_test.go` against the in-memory store plus a fake `clientcert.Source`:
  - `TestTreeRootListsClientCertFiles`.
  - `TestTreeClientCertAbsentWithoutSource`.
  - `TestTreeClientCertDocumentsShareOnePair`: crt, key and pem bytes all come from the same `Pair`; pem equals crt+key.
  - `TestTreeClientCertBypassesCache`: the source returns pair A, then pair B, and two `Document` calls return A then B even with cacheTTL 30s.
  - `TestTreeClientCertReadOnlyOnReadWriteMount`.
  - `TestTreeClientCertWinsCollision`: the store has the folder `client.crt/` and the listing shows a file.
  - `TestTreeClientCertNotAtDepth`: `sub/client.crt` is an ordinary missing path.
  - `TestTreeClientCertSourceError`: the error has no `BEGIN`.

  In `mount_fuse_test.go` (tagged like its neighbours, skips without `/dev/fuse`), add `TestMountClientCertRotates`: read `client.pem`, switch the fake source, and read again for different bytes and size.
- [ ] **Step 2: Run** `go test ./internal/vaultfs/ -run ClientCert`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/vaultfs/` and, on a Linux host with FUSE, `go test ./internal/vaultfs/ -run TestMount`. Then `GOOS=windows go build ./...`. Expected: PASS / builds.
- [ ] **Step 5: Commit** `feat(vaultfs): serve client certificate files at the mount root`.

### Task 8: Docker — `client_cert` volume option

**Files:**
- Modify: `internal/dockervol/dockervol.go:115-240` (`OptClientCert = "client_cert"`, `Spec.ClientCert ClientCertMode \`json:"client_cert,omitempty"\``, `ParseOptions`, `validate`), `internal/dockervol/materialise.go:42` (`render` takes `cert *clientcert.Pair`), `internal/dockervol/driver.go:28` (`Options.ClientCert clientcert.Source`), `Create` and `Mount`
- Test: `internal/dockervol/spec_test.go`, `internal/dockervol/materialise_test.go`, `internal/dockervol/driver_test.go`

**Interfaces:**
- Produces: `type ClientCertMode string; const ClientCertOff ClientCertMode = ""; ClientCertWith = "true"; ClientCertOnly = "only"`.
  - `client_cert=true` adds the three files beside the selection. An absent `secrets=` still means the whole subtree, as today; the docs must say so.
  - `client_cert=only` adds the files and selects no secrets. It conflicts with `secrets=`, which is an error.
  - `false` is accepted and means off. Any other value is an error listing `true, false, only`.

  This resolves the spec's open item. Extend the "accepted:" list in the unknown-option error.
- `render(ctx, store, spec, cert)` adds `client.crt`, `client.key` and `client.pem` at the root with `modTime = cert.NotBefore`, before the collision fold. A KV entry with one of those names at the root loses, through `warnCollision`. `materialise` gets the pair from `d.opts.ClientCert.Current(ctx)` only when `spec.ClientCert != ClientCertOff`.
- `Create` with `client_cert` set while `Options.ClientCert == nil` returns the error `client_cert is not enabled in dotvault's configuration (client_cert.enabled)`. For a persisted volume resumed under a config that has since disabled it, the refresh error names the same cause.

- [ ] **Step 1: Write failing tests.**
  - `TestParseOptionsClientCert` (table over true/only/false/garbage, and only+secrets).
  - `TestMaterialiseClientCertFiles`: pem equals crt+key and the file mode follows `spec.Mode`.
  - `TestMaterialiseClientCertOnly`: only the three files, and a store with secrets is not listed (assert the fake store's List was never called).
  - `TestMaterialiseClientCertWinsCollision`.
  - `TestCreateClientCertRequiresSource`.
  - `TestSpecValidateClientCertRoundTrip`: the persisted JSON reloads.
- [ ] **Step 2: Run** `go test ./internal/dockervol/ -run ClientCert`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./internal/dockervol/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dockervol): client_cert volume option`.

### Task 9: Docker — re-render before the certificate expires

**Files:**
- Modify: `internal/dockervol/refresh.go:76-130` (`runVolume`, `refresh`)
- Test: `internal/dockervol/driver_test.go`

**Interfaces:**
- Consumes: `Pair.RefreshAt` (Task 5).
- After each refresh of a volume with `ClientCert != Off`, `runVolume` arms a `time.Timer` for the pair's `RefreshAt` (minimum 1s), plus a small jitter (≤5% of the lifetime). When it fires, it refreshes **regardless of `eventsDriving()`**. `materialise` returns the pair it used so the loop can read `RefreshAt`. Change its signature to `(int, *clientcert.Pair, error)`. If a refresh fails, the timer re-arms at the ordinary ticker cadence.

- [ ] **Step 1: Write failing tests.** `TestVolumeClientCertRefreshesWhileEventsDrive`: the driver has `eventsLive=true` and a fake source with RefreshAt = now+200ms. Assert that the file changes within 2s with no event and no tick (TTL 10m). `TestVolumeWithoutClientCertNoExtraRefresh`: no timer-driven render within 1s.
- [ ] **Step 2: Run** `go test ./internal/dockervol/ -run RefreshesWhileEventsDrive`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./internal/dockervol/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(dockervol): refresh certificate-carrying volumes on the certificate's schedule`.

### Task 10: Daemon wiring and status

**Files:**
- Create: `cmd/dotvault/clientcert.go`, `cmd/dotvault/clientcert_test.go`
- Modify: `cmd/dotvault/main.go:1190` and `:1485` (build the source once, before both calls; pass it in), `cmd/dotvault/fusemount.go:56,67`, `cmd/dotvault/dockervol.go:~95`, `cmd/dotvault/main.go:2028-2030` (`printClientCertStatus(cfg)`), `internal/web/server.go:~765` (`SetClientCertStatus`), `internal/web/api.go:~146` (`status["client_cert"]`)

**Interfaces:**
- Produces: `func buildClientCertSource(cfg *config.Config, vc *vault.Client, username string) clientcert.Source`. It logs a WARN and returns nil on a construction error (never fatal). `startFUSE(ctx, cfg, vc, username, certSrc)` and `startDockerVolumes(..., certSrc)` gain the parameter.
- Produces: `type clientcert.Status struct { Source, CommonName, Serial string; NotAfter time.Time; LastError string }` and `func StatusOf(s Source) Status`, which reports the last pair served and never signs. Add `func (e *ephemeral) Last() (*Pair, error)` and `func (h *held) Last() (*Pair, error)` behind an unexported interface. `/api/v1/status` carries `client_cert` (unauthenticated, like `fuse`/`docker`: serial and expiry only). `dotvault status` prints `client certificate:` with the source that would be used (`held` / `short-lived`), the PKI role, and the TTL from config. It never signs. If the source is held and the envelope is readable, it prints serial/NotAfter via `auth.InspectCertCredential`.

- [ ] **Step 1: Write failing tests.** `TestBuildClientCertSourceDisabled` returns nil. `TestPrintClientCertStatusNeverSigns`: inject a signer that fails the test if `SignCSR` is called. `TestStatusAPIClientCertBlock`, in `internal/web/api_test.go`: the block is present when set, has no `cert_pem`/`key` keys, and is absent when unset. Update the existing `startFUSE`/`startDockerVolumes` test call sites.
- [ ] **Step 2: Run** `go test ./cmd/dotvault/ ./internal/web/ -run ClientCert`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./cmd/dotvault/ ./internal/web/ && make build-all`. Expected: PASS, all five targets build.
- [ ] **Step 5: Commit** `feat(daemon): wire client certificates into the mount, volumes and status`.

### Task 11: Public `client/` API

**Files:**
- Modify: `client/config.go:29-300` (`ClientCertConfig`, projection in `fromInternal`, defaults), `client/errors.go` (`ErrNotConfigured`, classify a 403 from `pki/sign` as `ErrDenied`), `client/client.go` (methods)
- Create: `client/clientcert.go`, `client/clientcert_test.go`
- Modify: `client/README.md`

**Interfaces:**
- Produces:
  ```go
  type ClientCertConfig struct {
      Enabled bool
      PKIMount, PKIRole, CommonName string
      TTL time.Duration
      KeyType string; KeyBits int
  }   // Config.ClientCert; fromInternal fills it from cfg.ClientCertPKIMount() etc. (already resolved)
  var ErrNotConfigured = errors.New("dotvault: client certificate not configured")
  type ClientCertificate struct {
      CertPEM, KeyPEM, CombinedPEM []byte
      NotAfter    time.Time
      Certificate tls.Certificate
  }
  func (c *Client) ClientCertificate(ctx context.Context) (*ClientCertificate, error)
  func (c *Client) TLSConfig(base *tls.Config) (*tls.Config, error) // clones base (nil ok), sets GetClientCertificate
  ```
- `Client` lazily builds one `clientcert.Source` via `clientcert.NewFromParams` (Task 6), using the client's own vault client as the `Signer` and `c.identity` as `OSUser`. `client.VaultConfig` gains the `ReissueBefore` it needs (method and `StorageDir` are already present). If no token is held, `ClientCertificate` first calls `AuthenticateCached`, so it never prompts. A disabled section, or no role with no exportable held cert, returns `ErrNotConfigured`. `GetClientCertificate` calls `Current` on every handshake, so rotation is automatic. Its errors fail the handshake.

- [ ] **Step 1: Write failing tests** with an `httptest` Vault in the style of `client/client_test.go`, faking `auth/token/lookup-self` and `pki/sign/<role>` with an in-test CA:
  - `TestClientCertificateEphemeral`.
  - `TestClientCertificateNotConfigured` (`errors.Is(err, ErrNotConfigured)`).
  - `TestClientCertificateDeniedIs403` (`ErrDenied`).
  - `TestClientCertificateHeld`: write an envelope in a temp `StorageDir` with method `mtls`; no `pki/sign` call is made.
  - `TestTLSConfigPresentsCurrentCert`: an `httptest.NewTLSServer` with `ClientAuth: RequireAndVerifyClientCert` trusting the in-test CA; an HTTP GET through `TLSConfig` succeeds and the server sees CN `gary`.
  - `TestClientCertificateNeverPrompts`: no token and no socket gives `ErrLoginRequired`.
- [ ] **Step 2: Run** `go test ./client/ -run 'ClientCert|TLSConfig'`. Expected: FAIL.
- [ ] **Step 3: Implement**, and update `client/README.md` with a curl-equivalent Go snippet.
- [ ] **Step 4: Run** `go test -race ./client/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(client): ClientCertificate and TLSConfig`.

### Task 12: Python bindings

**Files:**
- Modify: `python/bridge/bridge.go` (category `catNotConfigured = 7`, `//export dotvault_client_certificate`), `python/bridge/bridge_test.go`, `python/src/dotvault/_errors.py` (`NotConfigured(DotvaultError)`, code 7), `python/src/dotvault/_ffi.py` (argtypes), `python/src/dotvault/__init__.py` (`Client.client_certificate(timeout=None) -> tuple[str, str]`), `python/tests/`, `python/README.md`

**Interfaces:**
- `dotvault_client_certificate(h C.longlong, timeoutMillis C.longlong, certOut **C.char, keyOut **C.char, errOut **C.char) C.int`. Both out-strings are malloc'd and freed through `dotvault_free`, as `take_str` already does. `syncEnv()` runs first.

- [ ] **Step 1: Write failing tests.** `TestCategoryNotConfigured` in `bridge_test.go`. A Python test points at a closed port with the section disabled and asserts `NotConfigured`, then with it enabled and no token asserts `LoginRequired`. Category codes must match on both sides.
- [ ] **Step 2: Run** `go test ./python/bridge/... && make python-lib && uv run --no-project --with pytest python -m pytest python/tests`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Rerun the same commands.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(python): client_certificate()`.

### Task 13: Documentation, dev stack and an integration test

**Files:**
- Modify: `docs/configuration/config-reference.md` (the `client_cert` section, the `{{.token_username}}` resolution, the policy requirement `pki/sign/<role>`, the "the held cert is a Vault login" and "an inherited role means each short-lived cert is a Vault login" warnings, and a recommendation of `no_store=true` and a separate role/CA), `docs/guide/filesystem.md` and `docs/guide/docker-volumes.md` (curl examples with `client.pem` first; `client_cert=true` vs `only`; a whole-subtree reminder), `CLAUDE.md` (a config bullet for `client_cert`, an update to "Public client API" on the relaxed issuance rule, a note under FUSE/Docker, and corrections to the two existing false claims: the Copy engine `{{.user}}` and agent `{{.vault_username}}` are the OS user), `config.dev.yaml` (a `client_cert` entry), `docker-compose.yaml:~183` (a `pki/roles/dotvault-tools` with `no_store=true`, `max_ttl=1h`, `allow_any_name=true`, `client_flag=true`, `server_flag=false`; grant `pki/sign/dotvault-tools` in the `dotvault` policy)
- Create: `test/integration/clientcert_test.go`

- [ ] **Step 1: Write the integration test** `TestClientCertEphemeralAgainstVault` (uses `skipIfNoVault`). The dev stack has no LDAP or userpass, so with the root token the test creates a token via `auth/token/create` with `meta={username: testuser}` and policy `dotvault`. Build `clientcert.NewEphemeral` over a real `vault.Client` holding that token and sign against `pki/sign/dotvault-tools`. Assert that the CN is `testuser`, the certificate chains to the PKI root (`pki/cert/ca`), and `NotAfter − NotBefore ≈ 5m`. A second case runs `auth.Downscope` on that token to `[dotvault]` (Task 1) and asserts that the CN is still `testuser`.
- [ ] **Step 2: Run** `docker compose up -d && go test ./test/integration/ -run ClientCert`. Expected: PASS. Then run `go run ./cmd/dotvault run --config config.dev.yaml` with `fuse.enabled` and check that `curl --cert ~/.dotvault/client.pem -v https://example.invalid` gets as far as the TLS client hello. A real mTLS echo can be `openssl s_server -Verify 1 -CAfile pki-ca.crt`.
- [ ] **Step 3: Write the docs.**
- [ ] **Step 4: Run** `make test`. Expected: PASS.
- [ ] **Step 5: Commit** `docs: client certificates for tools`.

---

## Before pushing

Run `/precommit-review` (repo CLAUDE.md), address findings in the same series, then push once.
