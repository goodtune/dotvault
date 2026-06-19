"""Exception taxonomy mirroring the Go facade's ``errors.Is``-able sentinels.

The integer category codes here are the SAME values the cgo bridge returns
across the ABI (see ``cat*`` in ``python/bridge/bridge.go``). The two must be
extended together — a new sentinel needs a new code on both sides and a new
exception class below.
"""

from __future__ import annotations

# Category codes, mirrored verbatim from the Go bridge.
CAT_OK = 0
CAT_LOGIN_REQUIRED = 1
CAT_DENIED = 2
CAT_UNREACHABLE = 3
CAT_AUTH_FAILED = 4
CAT_OTHER = 5


class DotvaultError(Exception):
    """Base class for every error raised by this package.

    Catch this to handle any dotvault failure generically; catch a subclass to
    distinguish the categories below. An error that matches no specific
    category (a config-load/validation failure, an unknown handle) is raised as
    a bare ``DotvaultError``.
    """


class LoginRequired(DotvaultError):
    """No usable cached token was found and no interactive login was attempted.

    Maps to the facade's ``ErrLoginRequired``. The remedy is to provision a
    token out of band — run ``dotvault login`` (or let the daemon do it). This
    package never prompts interactively.
    """


class AuthFailed(DotvaultError):
    """A login flow ran but did not yield a usable token (``ErrAuthFailed``).

    Read-only callers will rarely see this — it surfaces only if a future
    interactive path is added — but the category exists so the mapping is total.
    """


class Denied(DotvaultError):
    """Vault rejected a read with 401/403 (``ErrDenied``).

    The token is valid but lacks the policy for the path, or was revoked
    between the auth check and the read.
    """


class Unreachable(DotvaultError):
    """Vault could not be reached or could not service the request now.

    DNS/connection/TLS/timeout, or a 5xx/429 from the server (``ErrUnreachable``).
    Retryable — back off and try again.
    """


_BY_CATEGORY = {
    CAT_LOGIN_REQUIRED: LoginRequired,
    CAT_DENIED: Denied,
    CAT_UNREACHABLE: Unreachable,
    CAT_AUTH_FAILED: AuthFailed,
}


def error_for(code: int, message: str | None) -> DotvaultError:
    """Build the exception for a non-OK category code and message."""
    cls = _BY_CATEGORY.get(code, DotvaultError)
    return cls(message or "dotvault: unknown error")
