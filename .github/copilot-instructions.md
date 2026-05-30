# Copilot review instructions — dotvault

Go daemon syncing HashiCorp Vault KVv2 secrets to local files. Project facts below override generic Go heuristics. Don't re-raise points already covered here.

## Go examples — do not flag as non-hermetic

`go test` runs an `ExampleXxx` only if it has an `// Output:` comment; without one it is compiled but never executed (https://pkg.go.dev/testing#hdr-Examples). In `client/example_test.go`, `Example` and `ExampleClient_AuthenticateCached` have no `// Output:`, so they never run — they cannot load host config, contact Vault, prompt, hang CI, or call `os.Exit`. They are deliberate godoc. `ExampleReader` is the only runnable one (in-memory fake, deterministic output). Do not suggest env-guards, an `os` import, renaming, or httptest rewrites for the non-running examples.

## Error wrapping

`client` uses `errors.Is`-able sentinels (`ErrLoginRequired`, `ErrAuthFailed`, `ErrDenied`, `ErrUnreachable`). Categorised errors wrap the sentinel with `%w`, and where a Vault cause exists wrap it too (second `%w`, valid Go 1.20+) so the value also `errors.As`-es to `*vaultapi.ResponseError`. Keep `%w`; don't suggest `%v`. `New`'s validation errors (nil config, missing address) are intentionally plain, non-categorised programmer errors.

## Vault SDK facts

- `Sys().Health()` sends `uninitcode`/`sealedcode`/`standbycode=299`, so uninitialised/sealed/standby return non-error 2xx. `internal/vault.ServerHealth` errors only on transport failure — it's a reachability probe, not readiness. Don't flag standby/sealed as an error path.
- Vault decodes JSON with `UseNumber()`; numbers are `json.Number` (string kind), so `%v` renders canonical decimal. No scientific-notation hazard.

## Identity / KV paths

Layout: `{kv_mount}/{user_prefix}{identity}/{service}`. `<identity>` defaults to the OS username (domain-stripped), matching what the sync engine and enrolment write — not the token display name. `client.WithIdentity(name)` overrides only the KV-path identity, deliberately not the OS-derived username used as the LDAP prompt default. Don't suggest token-derived identity by default. Vault KV paths use literal `/`, never `filepath.Join`.

## Invariants

Pure Go; `CGO_ENABLED=0` — no CGO deps. Public surface is `client/`; `internal/*` is implementation (the facade legally imports it, same module).
