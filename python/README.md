# dotvault — Python bindings

Python bindings for [dotvault](https://github.com/goodtune/dotvault)'s public client API. They let a Python program read the per-user secrets a dotvault daemon enrolled and keeps current — talking to the same Vault, resolving a token the same way, and reading from the exact `kv/users/<user>/...` path dotvault writes to.

The package is a thin [ctypes](https://docs.python.org/3/library/ctypes.html) wrapper over dotvault's Go `client` package compiled to a shared library with `go build -buildmode=c-shared`. Connectivity, token precedence, the OS-user identity convention, and the path layout all come from the one canonical Go implementation rather than being re-derived in Python, so a consumer can't silently diverge from the daemon. The native bridge imports only the public Go `client` package — never dotvault's internals.

## Scope

This first release exposes the **read-only + cached-auth** subset of the Go facade:

- `Client(config_path=None, identity=None)` — load config, build the client.
- `authenticate_cached(timeout=None)` — resolve a token (`DOTVAULT_TOKEN` → token file → peer socket borrow when `vault.token_socket` is configured) and validate it. The socket borrow is a plain read with no browser or prompt, so a host with no local token but a live peer socket authenticates without an interactive login. **Never prompts.**
- `identity_name()`, `token()`.
- `read_user_secret(service, field, timeout=None)`, `read_kv_field(mount, path, field, timeout=None)`.

Interactive login (OIDC browser pop, LDAP password + MFA terminal prompts) is **deliberately out of scope** — driving it across an FFI boundary from inside a Python process is awkward and not what a library caller wants. Provision a token out of band (`dotvault login`, or the daemon) and these bindings consume it.

## Install

Released wheels are published to PyPI (Linux `manylinux_2_28`, macOS arm64, Windows x86_64):

```sh
pip install dotvault          # or: uv pip install dotvault
```

The wheel is tagged `py3-none-<platform>`: it carries a native shared library (so it is platform-specific) but contains no CPython C-extension — it is pure ctypes — so a single wheel per OS installs on **any** Python ≥ 3.9, not one wheel per interpreter version. Its version is derived from the repo's git tags by `setuptools-scm` (the same tags that version the daemon); `dotvault.__version__` reports it.

Wheels are built for glibc Linux x86_64 (`manylinux_2_28`), Apple-Silicon macOS, and Windows x86_64. There are currently no wheels for Linux aarch64, musl/Alpine, Intel macOS, or Windows arm64 — `pip install` on those reports "no matching distribution"; build from a checkout instead.

To build from a checkout instead — the tooling is [uv](https://docs.astral.dev/uv/):

```sh
make python-wheel               # -> python/dist/dotvault-*.whl  (runs `uv build`)
uv pip install python/dist/dotvault-*.whl
```

or an editable install (requires Go on `PATH`, since the bridge is compiled on install):

```sh
cd python && uv pip install -e .
```

Building from source needs the Go toolchain and a C compiler — `go build -buildmode=c-shared` is the one place dotvault uses cgo (`CGO_ENABLED=1`). The main dotvault binaries remain pure-Go static builds; only this binding links libc. On Windows the C compiler must be a mingw-w64 gcc (the `c-shared` build does not work with MSVC); GitHub's `windows-latest` runners ship one, but a local Windows build needs it on `PATH`.

Concurrency note: set `DOTVAULT_TOKEN` before the first use of a `Client`, not concurrently with reads from another thread. The bridge re-reads the facade's env vars from libc on each token-resolving call; that read/write is serialised internally, but it cannot be made safe against the host process mutating its own environment from another thread.

## Quick start

```python
import dotvault

# Defaults: dotvault's system config path, identity = the OS user.
with dotvault.Client() as c:
    try:
        c.authenticate_cached(timeout=5)          # env -> token file; no prompt
    except dotvault.LoginRequired:
        raise SystemExit("run `dotvault login` first")
    except dotvault.Unreachable:
        raise SystemExit("vault is unreachable; retry later")

    token = c.read_user_secret("gh", "oauth_token")   # -> str | None
    if token is None:
        raise SystemExit("github enrolment not present")
    use(token)
```

A read returns the field value, or `None` when the secret or field is absent — a missing path and a missing field are not distinguished (both are "not there"), matching the Go facade. Transport/authorisation failures raise instead.

## Identity is the OS user, not the Vault token

dotvault derives the `<user>` segment of `kv/users/<user>/...` from the **OS account the process runs as** (with any `DOMAIN\` prefix stripped), *not* from the Vault token's `display_name` or entity. By default a consumer must therefore run as the **same OS user** as the dotvault that populated the secrets — normally true for a per-user daemon.

If your process runs as a different user (a service account, a container), pass `identity=` to read that user's secrets:

```python
dotvault.Client(identity="alice")
```

A wrong identity reads a non-existent path, which surfaces as a `None` read — not an error.

## Errors

Every failure is a `DotvaultError` or a subclass:

| Exception | Meaning | What to do |
| --- | --- | --- |
| `LoginRequired` | No usable cached token. | Provision a token (`dotvault login`). |
| `Unreachable` | Vault down / 5xx / timeout. | Retry, back off. |
| `Denied` | Vault rejected the read (401/403). | Fail closed; the token lacks the policy. |
| `AuthFailed` | A login ran but failed. | Surface the auth problem (rare on this surface). |
| `DotvaultError` | Anything else (config load, closed client). | Fail closed. |

A not-found read is `None`, never an exception.

## Environment variables

The bindings honour the same variables as dotvault: `DOTVAULT_TOKEN` (a token supplied via the environment) and `VAULT_NAMESPACE`. `VAULT_TOKEN` is **deliberately ignored** — it belongs to the `vault` CLI and must not leak into dotvault's session; use `DOTVAULT_TOKEN`.

The Go runtime snapshots its environment at load time, so the bridge re-reads these two variables from the live process environment on each call. That means setting `os.environ["DOTVAULT_TOKEN"]` after `import dotvault` works as you'd expect.

## Development

```sh
make python-lib     # build the native bridge into the package for local use
make python-test    # build the bridge + run the Python test suite (via `uv run`)
go test ./python/bridge/...   # the Go-side bridge unit tests
```

`make python-test` and `make python-wheel` shell out to `uv`, which provisions Python and the test/build dependencies; only the Go toolchain and a C compiler need to be present beforehand.

The Python tests run fully offline — they point at a closed Vault port and assert the error categorisation — so no live Vault is needed.

## Releasing

Publishing a GitHub Release with a `vX.Y.Z` tag drives both the Go release (`release.yml`) and the Python wheels: the `.github/workflows/python.yml` `publish` job builds the per-OS wheels and uploads them to PyPI via the official `pypa/gh-action-pypi-publish` action using **Trusted Publishing** (OIDC — no stored token). One-time setup before the first release: register a [pending publisher](https://docs.pypi.org/trusted-publishers/) on PyPI for project `dotvault` pointing at this repository, workflow `python.yml`, and environment `pypi`. A dev/untagged build produces a PEP 440 local version that PyPI rejects, so only exact tagged releases publish. Consider a one-off TestPyPI dry run (temporarily pointing the action at TestPyPI) before the first real release to validate the OIDC/publisher wiring.
