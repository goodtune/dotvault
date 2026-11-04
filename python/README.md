# dotvault — Python bindings

Python bindings for [dotvault](https://github.com/goodtune/dotvault)'s public client API. They let a Python program read the per-user secrets a dotvault daemon enrolled and keeps current — talking to the same Vault, resolving a token the same way, and reading from the exact `kv/users/<user>/...` path dotvault writes to.

The package is a thin [ctypes](https://docs.python.org/3/library/ctypes.html) wrapper over dotvault's Go `client` package compiled to a shared library with `go build -buildmode=c-shared`. Connectivity, token precedence, the OS-user identity convention, and the path layout all come from the one canonical Go implementation rather than being re-derived in Python, so a consumer can't silently diverge from the daemon. The native bridge imports only the public Go `client` package — never dotvault's internals.

## Scope

This package exposes the **read-only + cached-auth** subset of the Go facade, the mutual-TLS **client certificate**, and the socket-forwarded **peer actions**:

- `Client(config_path=None, identity=None)` — load config, build the client.
- `authenticate_cached(timeout=None)` — resolve a token (`DOTVAULT_TOKEN` → token file, skipped under the `mtls+os` auth method → the local daemon's API socket when `api.enabled` → a peer socket when `vault.token_socket` is configured → this host's client certificate under an `mtls*` auth method) and validate it. `mtls+os` keeps no Vault token at rest, so a token file found there is a leftover from a previous auth method and is deliberately ignored rather than silently used for the rest of its TTL; the certificate answers instead. The local socket is tried first because it outlives the SSH session a forwarded peer socket depends on. The socket borrow is a plain read, and presenting an already-enrolled certificate involves no browser or terminal, so both stay within the no-prompt contract: a host with no local token authenticates from either without an interactive login. Certificate auth is **consumption-only** here — the bindings can use a certificate the dotvault daemon or CLI enrolled, but never mint, rotate, or bootstrap one. **Never prompts.**
- `identity_name()`, `token()`.
- `read_user_secret(service, field, timeout=None)`, `read_kv_field(mount, path, field, timeout=None)`.
- `client_certificate(timeout=None)` — return `(cert_pem, key_pem)`: the mutual-TLS client certificate the `client_cert` config section describes, the same one the daemon serves through the filesystem mount and Docker volumes. `cert_pem` is the leaf followed by its CA chain; `key_pem` is the PKCS#8 private key. It never prompts: signing needs a Vault token, so when none is held it first tries the cached sources (token file, peer socket, enrolled certificate) as `authenticate_cached` does. Raises `NotConfigured` when the section is disabled, `LoginRequired` when signing needs a token and none is found, `Denied` on a policy without `pki/sign`, and `Unreachable` for transport failures. **The key is a secret**; see [Using the client certificate](#using-the-client-certificate).
- `browse(url, timeout=None)`, `notify(level, title, body="", action_url="", timeout=None)`, `clipboard(text, timeout=None)` — ask the `vault.token_socket` peer to open a URL in a browser, raise a native desktop notification, or put text on the clipboard, **on the workstation**. For the headless topology: a Python program on a machine with no browser hands a URL, a notification, or a value to paste (a one-time token for a page `browse` just opened) back over the same forwarded socket it borrows tokens from. These need **no** local token. The peer validates/sanitizes the input; there is no local fallback (an unreachable peer raises `PeerUnavailable`). `notify` levels: `info`, `warning`, `error`, `attention`; the optional `action_url` is an http/https link the notification opens when clicked (on Windows; appended to the body on macOS/Linux). `clipboard` text is written verbatim (non-empty UTF-8, no NUL bytes, ≤ 64 KiB) and the peer logs only its length, never the content.

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

## Using the client certificate

`client_certificate()` returns PEM text. The certificate is short-lived and is replaced well before it expires, so ask again when you start a new connection or session rather than holding the result for long. The private key is a secret: do not log it, do not put it in an exception message, and do not write it anywhere other users can read. It also stays in Python memory for as long as the strings are referenced, because Python cannot zero a `str`.

`requests` takes file paths for `cert=(crt_path, key_path)`, so the PEMs must be on disk. If you take that route, write them to a `tempfile` created with mode 0600 and delete them as soon as the session is built:

```python
import os
import tempfile

import dotvault
import requests

with dotvault.Client() as c:
    c.authenticate_cached(timeout=5)
    cert_pem, key_pem = c.client_certificate(timeout=10)

with tempfile.TemporaryDirectory() as d:        # the directory is created 0700
    crt, key = os.path.join(d, "client.crt"), os.path.join(d, "client.key")
    for path, pem in ((crt, cert_pem), (key, key_pem)):
        # os.open with an explicit mode: the file is never visible with wider bits.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pem)
    r = requests.get("https://mtls.example.com/", cert=(crt, key))
```

To avoid keeping files around for the life of the session, load the PEMs into an `ssl.SSLContext` instead (for `urllib3`, `http.client`, `aiohttp` and similar). `load_cert_chain` only accepts a path, so the key is still on disk for the instant of the load; the file is removed straight after and the context keeps presenting the certificate:

```python
import ssl

ctx = ssl.create_default_context()
with tempfile.TemporaryDirectory() as d:
    combined = os.path.join(d, "client.pem")
    fd = os.open(combined, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(cert_pem + key_pem)
    ctx.load_cert_chain(combined)               # key is read into the context here
# The file is gone; ctx keeps presenting the certificate until it expires.
# Build a new context from a fresh client_certificate() for later sessions.
```

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
| `NotConfigured` | `client_certificate`: the `client_cert` section is disabled, or has no PKI role and no usable held certificate. | Change the dotvault config; retrying will not help. |
| `PeerUnavailable` | `browse`/`notify`/`clipboard`: no socket, peer down, or the action failed. | Retry, or fall back to your own handling. |
| `DotvaultError` | Anything else (config load, closed client, a peer-*rejected* request). | Fail closed. |

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
