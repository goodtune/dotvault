"""dotvault — Python bindings for the dotvault public client API.

This package lets a Python program read the per-user secrets a dotvault daemon
enrolled and keeps current, talking to the same Vault, resolving a token the
same way, and reading from the exact ``kv/users/<user>/...`` path dotvault
writes to. It is a thin ctypes wrapper over dotvault's Go client compiled to a
shared library, so the connectivity, token precedence, and identity convention
all come from the one canonical Go implementation rather than being re-derived
in Python.

The surface is the read-only + cached-auth subset of the Go facade, plus the
socket-forwarded peer actions (``browse``/``notify``):

    import dotvault

    with dotvault.Client() as c:           # default config path, OS-user identity
        c.authenticate_cached(timeout=5)   # env -> token file; never prompts
        token = c.read_user_secret("gh", "oauth_token")
        c.browse("https://example.com")    # opens on the workstation peer
        c.notify("info", "Done", "job finished")

``browse`` and ``notify`` post over the same ``vault.token_socket`` peer this
client borrows tokens from, so a headless program hands a URL or a notification
back to the workstation where a human is looking. They need no local token.

Authentication never prompts: it resolves ``DOTVAULT_TOKEN`` then the token
file and validates it. If no usable token is present it raises ``LoginRequired``
— provision one with ``dotvault login`` (or let the daemon do it). Interactive
browser/terminal login is deliberately out of scope for these bindings.

Identity is the OS user, not the Vault token: by default the ``<user>`` path
segment is the OS account the process runs as. A process running as a different
user (a service, a container) must pass ``identity=`` to read another user's
secrets. See the package README for the full rationale.
"""

from __future__ import annotations

from ctypes import byref, c_int, c_longlong, c_void_p

from . import _ffi
from ._errors import (
    CAT_OK,
    AuthFailed,
    Denied,
    DotvaultError,
    LoginRequired,
    PeerUnavailable,
    Unreachable,
    error_for,
)

__all__ = [
    "Client",
    "default_config_path",
    "DotvaultError",
    "LoginRequired",
    "AuthFailed",
    "Denied",
    "Unreachable",
    "PeerUnavailable",
    "__version__",
]

# Resolve the installed distribution's version (baked in at build time by
# setuptools-scm from the repo's git tags). Running from an uninstalled source
# tree — e.g. the test suite, which adds src/ to sys.path without installing —
# has no metadata, so fall back to a sentinel rather than failing import.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    __version__ = _pkg_version("dotvault")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

# Sentinel handle for a closed/never-opened client. The bridge never issues 0.
_CLOSED = 0


def default_config_path() -> str:
    """Return dotvault's platform default system-config path.

    The same file the daemon loads — ``/etc/xdg/dotvault/config.yaml`` on Linux
    (honouring ``XDG_CONFIG_DIRS``), ``%ProgramData%\\dotvault\\config.yaml`` on
    Windows (or the GPO registry when policy keys are present), Application
    Support on macOS.
    """
    return _ffi.take_str(_ffi.lib.dotvault_default_config_path()) or ""


def _millis(timeout: float | None) -> int:
    """Convert a seconds timeout to whole milliseconds.

    ``None`` means no deadline (-> 0). A positive ``timeout`` is truncated to
    whole milliseconds; note that a sub-millisecond or non-positive value also
    yields 0, which the bridge treats as "no deadline" — so a 0.0004s timeout
    is effectively unbounded. Pass at least 0.001 for a real deadline.
    """
    if timeout is None:
        return 0
    ms = int(timeout * 1000)
    return ms if ms > 0 else 0


def _check(code: int, err_ptr: c_void_p) -> None:
    """Raise the mapped exception for a non-OK category, consuming the message."""
    message = _ffi.take_str(err_ptr)
    if code != CAT_OK:
        raise error_for(code, message)


class Client:
    """A connection to dotvault's Vault, following dotvault's own conventions.

    Construction loads dotvault's system config and builds the underlying Vault
    client; it performs no network call and does not authenticate. Call
    :meth:`authenticate_cached` before reading.

    Args:
        config_path: Path to dotvault's system config. ``None`` uses
            :func:`default_config_path`.
        identity: Override for the ``<user>`` path segment. ``None`` derives it
            from the OS account (the common case — a per-user daemon). Set it
            explicitly when the process runs as a different OS user than the
            dotvault that wrote the secrets.

    Use as a context manager, or call :meth:`close` to release the native
    handle deterministically. The object is also cleaned up on GC.
    """

    def __init__(self, config_path: str | None = None, identity: str | None = None) -> None:
        err = c_void_p()
        handle = _ffi.lib.dotvault_client_new(
            _ffi.encode(config_path), _ffi.encode(identity), byref(err)
        )
        if handle == _CLOSED:
            # Config-load/validation failures are not facade sentinels; the
            # bridge returns 0 with the detail in the error string.
            raise DotvaultError(_ffi.take_str(err) or "dotvault: failed to create client")
        self._handle = handle

    def authenticate_cached(self, timeout: float | None = None) -> None:
        """Resolve and validate a cached token; never prompts.

        Resolves ``DOTVAULT_TOKEN`` then the configured token file and validates
        it against Vault. Returns ``None`` on success.

        Raises:
            LoginRequired: No usable cached token.
            Unreachable: Vault could not be reached to validate the token.
            DotvaultError: The client handle is invalid (use-after-close).
        """
        self._require_open()
        err = c_void_p()
        code = _ffi.lib.dotvault_authenticate_cached(self._handle, _millis(timeout), byref(err))
        _check(code, err)

    def identity_name(self) -> str:
        """Return the ``<user>`` path segment (the OS user, or the override).

        No Vault call — a local OS lookup. This is the value
        :meth:`read_user_secret` composes paths with.
        """
        self._require_open()
        out = c_void_p()
        err = c_void_p()
        code = _ffi.lib.dotvault_identity_name(self._handle, byref(out), byref(err))
        _check(code, err)
        return _ffi.take_str(out) or ""

    def token(self) -> str:
        """Return the Vault token the client currently holds, or ``""``.

        Useful to hand the same token to other Vault-aware tooling. Empty until
        a successful :meth:`authenticate_cached`.
        """
        self._require_open()
        out = c_void_p()
        err = c_void_p()
        code = _ffi.lib.dotvault_token(self._handle, byref(out), byref(err))
        _check(code, err)
        return _ffi.take_str(out) or ""

    def read_kv_field(
        self, mount: str, path: str, field: str, timeout: float | None = None
    ) -> str | None:
        """Read one field of a KV v2 secret, or ``None`` if absent.

        Returns the field value, or ``None`` when the secret or the field does
        not exist (a missing path and a missing field are not distinguished —
        both are "not there"). A missing or disabled KV mount also reads as
        ``None`` rather than an error, matching the Go facade.

        Raises:
            Denied: Vault rejected the read (401/403).
            Unreachable: Vault could not be reached.
        """
        self._require_open()
        out = c_void_p()
        found = c_int(0)
        err = c_void_p()
        code = _ffi.lib.dotvault_read_kv_field(
            self._handle,
            _ffi.encode(mount),
            _ffi.encode(path),
            _ffi.encode(field),
            _millis(timeout),
            byref(out),
            byref(found),
            byref(err),
        )
        _check(code, err)
        return _ffi.take_str(out) if found.value else None

    def read_user_secret(
        self, service: str, field: str, timeout: float | None = None
    ) -> str | None:
        """Read one field of ``kv/users/<identity>/<service>``, or ``None``.

        Composes the path from dotvault's configured KV mount and user prefix,
        :meth:`identity_name`, and ``service``. Return semantics match
        :meth:`read_kv_field`.

        Example: ``read_user_secret("gh", "oauth_token")`` reads the
        ``oauth_token`` field of the github enrolment.
        """
        self._require_open()
        out = c_void_p()
        found = c_int(0)
        err = c_void_p()
        code = _ffi.lib.dotvault_read_user_secret(
            self._handle,
            _ffi.encode(service),
            _ffi.encode(field),
            _millis(timeout),
            byref(out),
            byref(found),
            byref(err),
        )
        _check(code, err)
        return _ffi.take_str(out) if found.value else None

    def browse(self, url: str, timeout: float | None = None) -> None:
        """Ask the peer dotvault to open ``url`` in a browser on its host.

        Posts ``url`` to the peer named by ``vault.token_socket`` — the same
        SSH-forwarded socket this client borrows a token from — so a
        browser-driven flow opens on the workstation where a human is looking.
        The programmatic equivalent of ``dotvault browse <url>``. Unlike the
        CLI there is no local fallback: a headless library caller has no local
        browser, so an unreachable peer raises rather than opening locally.

        The URL is validated by the peer (``http``/``https`` only, a host, no
        embedded credentials). Returns ``None`` once the peer reports success.

        Raises:
            PeerUnavailable: No socket configured, peer unreachable, or the peer
                could not open the browser.
            DotvaultError: The peer rejected the URL as invalid (carrying its
                message), or the client handle is invalid.
        """
        self._require_open()
        err = c_void_p()
        code = _ffi.lib.dotvault_remote_browse(
            self._handle, _ffi.encode(url), _millis(timeout), byref(err)
        )
        _check(code, err)

    def notify(
        self, level: str, title: str, body: str = "", timeout: float | None = None
    ) -> None:
        """Ask the peer dotvault to raise a desktop notification on its host.

        The notification sibling of :meth:`browse` over the same socket: a
        long-running job on a headless box surfaces a native notification
        (Windows toast / macOS Notification Center / Linux D-Bus) on the
        workstation. The programmatic equivalent of
        ``dotvault notify <level> <title> [body]``.

        Args:
            level: One of ``"info"``, ``"warning"``, ``"error"``,
                ``"attention"`` — sets urgency and, where supported, the icon.
            title: The notification title (required).
            body: Optional detail line.

        The level and text are validated and sanitized by the peer. Returns
        ``None`` once the peer reports delivery.

        Raises:
            PeerUnavailable: No socket configured, peer unreachable, or the peer
                could not deliver the notification.
            DotvaultError: The peer rejected the level/title as invalid
                (carrying its message), or the client handle is invalid.
        """
        self._require_open()
        err = c_void_p()
        code = _ffi.lib.dotvault_remote_notify(
            self._handle,
            _ffi.encode(level),
            _ffi.encode(title),
            _ffi.encode(body),
            _millis(timeout),
            byref(err),
        )
        _check(code, err)

    def close(self) -> None:
        """Release the native handle. Idempotent; safe to call more than once."""
        if getattr(self, "_handle", _CLOSED) != _CLOSED:
            _ffi.lib.dotvault_client_free(c_longlong(self._handle))
            self._handle = _CLOSED

    def _require_open(self) -> None:
        if getattr(self, "_handle", _CLOSED) == _CLOSED:
            raise DotvaultError("dotvault: client is closed")

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort cleanup on GC; interpreter teardown may have already
        # dropped _ffi, so guard against that.
        try:
            self.close()
        except Exception:
            pass
