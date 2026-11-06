"""dotvault — Python bindings for the dotvault public client API.

This package lets a Python program read the per-user secrets a dotvault daemon
enrolled and keeps current, talking to the same Vault, resolving a token the
same way, and reading from the exact ``kv/users/<user>/...`` path dotvault
writes to. It is a thin ctypes wrapper over dotvault's Go client compiled to a
shared library, so the connectivity, token precedence, and identity convention
all come from the one canonical Go implementation rather than being re-derived
in Python.

The surface is the read-only + cached-auth subset of the Go facade, plus the
mutual-TLS ``client_certificate()`` and the socket-forwarded peer actions
(``browse``/``notify``/``clipboard``):

    import dotvault

    with dotvault.Client() as c:           # default config path, OS-user identity
        c.authenticate_cached(timeout=5)   # env -> token file; never prompts
        token = c.read_user_secret("gh", "oauth_token")
        c.browse("https://example.com")    # opens on the workstation peer
        c.clipboard(token)                 # ready to paste on the workstation
        c.notify("info", "Done", "job finished")

        with c.subscribe() as events:      # writes to your secrets, as they happen
            for event in events:
                if event.key == "gh":
                    token = c.read_user_secret("gh", "oauth_token")

``browse``, ``notify``, and ``clipboard`` post over the same
``vault.token_socket`` peer this client borrows tokens from, so a headless
program hands a URL, a notification, or a value to paste back to the
workstation where a human is looking. They need no local token.

``subscribe`` listens for writes to the user's secrets on the local daemon's
API socket and the same peer sockets, so a program can re-read a credential
when it is rotated instead of polling. An event carries the key and the new
version, never the value.

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

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from ctypes import byref, c_int, c_longlong, c_void_p
from typing import Iterator, Optional

from . import _ffi
from ._errors import (
    CAT_OK,
    AuthFailed,
    Denied,
    DotvaultError,
    LoginRequired,
    NotConfigured,
    PeerUnavailable,
    SubscriptionClosed,
    Unreachable,
    error_for,
)

__all__ = [
    "Client",
    "Event",
    "Subscription",
    "default_config_path",
    "DotvaultError",
    "LoginRequired",
    "AuthFailed",
    "Denied",
    "Unreachable",
    "PeerUnavailable",
    "NotConfigured",
    "SubscriptionClosed",
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


@dataclass(frozen=True)
class Event:
    """A write to one of the user's secrets, reported by :meth:`Client.subscribe`.

    Attributes:
        key: The secret's name relative to the user's prefix — the same name
            :meth:`Client.read_user_secret` takes, such as ``"gh"`` or
            ``"databricks/prod"``.
        version: The KVv2 version the write produced.
        source: What wrote it, when the daemon knows: ``"refresh"`` for a
            credential rotation, ``"watch"`` for a mirrored copy, else ``""``.
        time: When this host received the notice (UTC), or ``None`` if unknown.

    An event never carries the secret's value; re-read it when you need it.
    """

    key: str
    version: int
    source: str = ""
    time: Optional[datetime] = None


def _parse_time(value: str) -> Optional[datetime]:
    if not value:
        return None
    # fromisoformat only accepts a trailing "Z" from Python 3.11, and only
    # microsecond precision before then; the bridge emits RFC 3339 with up to
    # nanoseconds.
    text = value.replace("Z", "+00:00")
    if "." in text:
        head, _, rest = text.partition(".")
        n = 0
        while n < len(rest) and rest[n].isdigit():
            n += 1
        digits, tz = rest[:n], rest[n:]
        text = f"{head}.{digits[:6].ljust(6, '0')}{tz}"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except ValueError:
        return None


# How long each wait inside Subscription.__iter__ blocks in native code. The
# GIL is released while it waits, but a KeyboardInterrupt is only raised once
# control returns to Python, so the wait is kept short.
_ITER_POLL_SECONDS = 1.0


class Subscription:
    """A live stream of :class:`Event` objects from :meth:`Client.subscribe`.

    Iterate it to block for events — the loop runs until the subscription is
    closed, then ends quietly — or call :meth:`next` with a timeout. Events a
    slow reader has not yet taken are coalesced per key: a key written twice
    before you read it is reported once, with the later version, so you never
    miss the current state of a secret.

    It is blocking by design. From asyncio, run ``next`` in a thread:
    ``await asyncio.to_thread(sub.next, 1.0)``.

    Use as a context manager, or call :meth:`close`, to stop listening.
    """

    def __init__(self, handle: int) -> None:
        self._handle = handle

    def next(self, timeout: float | None = None) -> Optional[Event]:
        """Return the next event, or ``None`` if ``timeout`` seconds pass first.

        ``timeout=None`` waits indefinitely (and, being a single native call,
        is not interruptible by Ctrl-C; prefer iteration or a finite timeout
        in an interactive program). A finite timeout waits at least one
        millisecond, so ``timeout=0`` is a near-immediate poll rather than —
        as a zero would mean to the native layer — no deadline at all.

        Raises:
            SubscriptionClosed: The subscription is closed.
        """
        if self._handle == _CLOSED:
            raise SubscriptionClosed("dotvault: subscription closed")
        millis = 0 if timeout is None else max(1, _millis(timeout))
        out = c_void_p()
        err = c_void_p()
        code = _ffi.lib.dotvault_subscription_next(
            c_longlong(self._handle), millis, byref(out), byref(err)
        )
        _check(code, err)
        raw = _ffi.take_str(out)
        if raw is None:
            return None
        data = json.loads(raw)
        return Event(
            key=data["key"],
            version=int(data["version"]),
            source=data.get("source", ""),
            time=_parse_time(data.get("time", "")),
        )

    def __iter__(self) -> Iterator[Event]:
        while True:
            try:
                event = self.next(timeout=_ITER_POLL_SECONDS)
            except SubscriptionClosed:
                return
            if event is not None:
                yield event

    def close(self) -> None:
        """Stop listening. Idempotent. A blocked :meth:`next` returns."""
        if getattr(self, "_handle", _CLOSED) != _CLOSED:
            handle, self._handle = self._handle, _CLOSED
            _ffi.lib.dotvault_subscription_close(c_longlong(handle))

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


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

        Resolves ``DOTVAULT_TOKEN``, then the configured token file, then a
        borrow from the ``vault.token_socket`` peer, then this host's client
        certificate under an ``mtls*`` auth method, and validates the result
        against Vault. Returns ``None`` on success.

        Under ``mtls+os`` the token file is skipped: that method keeps no Vault
        token at rest, so a file found there is a leftover from a previous auth
        method and must not be used.

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
        self,
        level: str,
        title: str,
        body: str = "",
        action_url: str = "",
        timeout: float | None = None,
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
            action_url: Optional http/https link the notification takes the user
                to when clicked. Clickable on Windows (the toast opens the URL);
                on macOS/Linux, where a one-shot notification cannot register a
                click handler, it is appended to the body so it stays visible.

        The level, text, and action URL are validated and sanitized by the peer.
        Returns ``None`` once the peer reports delivery.

        Raises:
            PeerUnavailable: No socket configured, peer unreachable, or the peer
                could not deliver the notification.
            DotvaultError: The peer rejected the level/title/action_url as
                invalid (carrying its message), or the client handle is invalid.
        """
        self._require_open()
        err = c_void_p()
        code = _ffi.lib.dotvault_remote_notify(
            self._handle,
            _ffi.encode(level),
            _ffi.encode(title),
            _ffi.encode(body),
            _ffi.encode(action_url),
            _millis(timeout),
            byref(err),
        )
        _check(code, err)

    def clipboard(self, text: str, timeout: float | None = None) -> None:
        """Ask the peer dotvault to put ``text`` on its host's clipboard.

        The third peer action over the same socket as :meth:`browse` and
        :meth:`notify`: where ``browse`` opens a login page on the workstation
        and ``notify`` tells the user something happened, ``clipboard``
        delivers the value they need to paste — a one-time token, a device
        code — right where their Ctrl+V is. The programmatic equivalent of
        ``dotvault clipboard``. Like the other peer actions there is no local
        fallback: a headless caller has no clipboard, so an unreachable peer
        raises.

        The text is validated by the peer (non-empty, valid UTF-8, no NUL
        bytes, at most 64 KiB) and written verbatim; the peer never logs the
        content, only its length. Returns ``None`` once the peer reports the
        clipboard set.

        Raises:
            PeerUnavailable: No socket configured, peer unreachable, or the
                peer could not write its clipboard.
            DotvaultError: The peer rejected the text as invalid (carrying its
                message), or the client handle is invalid.
        """
        self._require_open()
        err = c_void_p()
        code = _ffi.lib.dotvault_remote_clipboard(
            self._handle, _ffi.encode(text), _millis(timeout), byref(err)
        )
        _check(code, err)

    def client_certificate(self, timeout: float | None = None) -> tuple[str, str]:
        """Return the mutual-TLS client certificate as ``(cert_pem, key_pem)``.

        ``cert_pem`` is the leaf certificate followed by its CA chain; ``key_pem``
        is the PKCS#8 private key. This is the certificate the daemon serves
        through the filesystem mount and Docker volumes: the one this host
        already logs in to Vault with (plain ``mtls``), else a short-lived one
        signed on demand by Vault's PKI engine and held only in memory. The same
        value comes back until it is due for replacement, so it is cheap to call
        again; call it again rather than holding the result for long.

        It never prompts. Signing needs a Vault token, so when none is held the
        call first tries the cached sources (token file, peer socket, enrolled
        certificate) as :meth:`authenticate_cached` does.

        **The key is a secret.** It lives in Python memory for as long as you
        hold it (Python strings cannot be zeroed), so do not log it, include it
        in an exception message, or write it anywhere world-readable.

        Raises:
            NotConfigured: The ``client_cert`` section is disabled, or has no PKI
                role and no usable held certificate.
            LoginRequired: Signing needs a token and none could be found.
            Denied: Vault rejected the sign (401/403), typically a policy
                without ``pki/sign``.
            Unreachable: Vault could not be reached, or returned a 5xx.
            DotvaultError: The client handle is invalid, or a signing attempt
                came too soon after the last one (transient; retry).
        """
        self._require_open()
        cert = c_void_p()
        key = c_void_p()
        err = c_void_p()
        code = _ffi.lib.dotvault_client_certificate(
            self._handle, _millis(timeout), byref(cert), byref(key), byref(err)
        )
        # Free every out-string unconditionally (a NULL is a no-op) so neither
        # the key nor the error leaks on any path.
        cert_pem = _ffi.take_str(cert)
        key_pem = _ffi.take_str(key)
        _check(code, err)
        return cert_pem or "", key_pem or ""

    def subscribe(self) -> Subscription:
        """Listen for writes to the user's secrets.

        Listens on every dotvault socket this client knows — the local
        daemon's API socket (when ``api.enabled``), which carries that
        daemon's own writes and everything it relays from its peers, and the
        peer sockets in ``vault.token_socket`` — and reports each write once.
        Sockets that are absent or go away are retried in the background, so
        this succeeds even before any daemon is listening. It needs no token.

        An event means Vault holds a new version; a file the daemon renders
        from it is rewritten by the daemon's own sync a moment later.

        Raises:
            PeerUnavailable: No dotvault socket is configured at all.
            DotvaultError: The client handle is invalid.
        """
        self._require_open()
        sub = c_longlong()
        err = c_void_p()
        code = _ffi.lib.dotvault_subscribe(self._handle, byref(sub), byref(err))
        _check(code, err)
        return Subscription(sub.value)

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
