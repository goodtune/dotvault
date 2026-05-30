# Copilot instructions for dotvault

dotvault is a cross-platform Go daemon that authenticates to HashiCorp Vault and synchronises KVv2 secrets into local config files. These notes capture project conventions so reviews and suggestions stay aligned with how the codebase actually works. Prefer them over generic Go heuristics where they conflict.

## Go examples (`ExampleXxx` in `_test.go`)

`go test` only **executes** an example function when it has an `// Output:` (or `// Unordered output:`) comment. An example with no output directive is **compiled but never run** — it serves purely as godoc. This is standard `testing` package behaviour (see https://pkg.go.dev/testing#hdr-Examples), not a project quirk.

Consequently, in `client/example_test.go`:

- `Example` and `ExampleClient_AuthenticateCached` have **no** `// Output:` directive. They are never run by `go test`, so they do **not** load host config, contact Vault, prompt interactively, or call `os.Exit`. They are intentionally illustrative godoc showing the real-world flow, mirroring how the standard library ships compile-checked-but-not-run examples.
- `ExampleReader` is the only runnable example: it is fully in-memory (a fake `client.Reader`) with a deterministic `// Output:`.

Do **not** flag the non-running examples as making the test suite non-hermetic, hang CI, or risk `os.Exit` — they cannot, because they never execute. Suggestions to gate them behind an env var or add an `os` import are unnecessary (that import would be unused in functions that don't run). This point has been raised and resolved repeatedly; please don't re-raise it.

## Error wrapping

The public `client` package uses `errors.Is`-able sentinels (`ErrLoginRequired`, `ErrAuthFailed`, `ErrDenied`, `ErrUnreachable`). Categorised errors wrap the sentinel with `%w`, and where a Vault cause exists they wrap it too (a second `%w`, valid since Go 1.20), so a value can both `errors.Is` the sentinel and `errors.As` the underlying `*vaultapi.ResponseError`. `New`'s input-validation errors (nil config, missing address) are deliberately plain, non-categorised programmer errors. Don't suggest replacing the documented `%w` pattern with `%v`.

## Vault SDK behaviour worth knowing

- `Sys().Health()`/`HealthWithContext` sends `uninitcode`/`sealedcode`/`standbycode=299` query params, so an uninitialised, sealed, or standby node returns a **non-error 2xx**. `internal/vault.ServerHealth` therefore errors only on a genuine transport failure — it is a reachability probe, not a readiness check. Don't flag standby/sealed as an error path for it.
- The Vault API decodes JSON with `UseNumber()`, so numbers arrive as `json.Number` (a string kind); `fmt`'s `%v` renders them in canonical decimal form. No scientific-notation hazard.

## Identity / KV path convention

dotvault lays out secrets at `{kv_mount}/{user_prefix}{identity}/{service}`. The `<identity>` segment defaults to the **OS username** (domain-stripped), not the Vault token's display name — this is load-bearing and matches what the sync engine and enrolment manager write. `client.WithIdentity(name)` overrides only the KV-path identity; it deliberately does **not** change the OS-derived username used as the LDAP login-prompt default. Don't suggest deriving identity from the token by default.

## General

- Pure Go only; `CGO_ENABLED=0` is an invariant. Don't suggest CGO-requiring dependencies.
- Vault KV paths use literal `/`, never `filepath.Join` (which would break on Windows).
- The public surface is `client/`; `internal/*` is the implementation. The facade legally imports `internal/*` because it is in the same module.
