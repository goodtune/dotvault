"""ctypes binding to the cgo c-shared bridge (``_dotvault.<ext>``).

This module owns three things and nothing else: locating and loading the shared
library that ships inside the package, declaring the C signatures of every
exported symbol, and the low-level helpers for moving owned C strings across
the boundary. The ergonomic surface (``Client``) lives in ``__init__``.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import POINTER, c_char_p, c_int, c_longlong, c_void_p


def _library_path() -> str:
    """Locate the bundled shared library next to this module.

    The artifact is named ``_dotvault`` plus the platform extension
    (``.so`` / ``.dylib`` / ``.dll``) and is dropped into the package directory
    at build time. We match by prefix rather than hard-coding the extension so
    the same code loads on every platform.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for name in sorted(os.listdir(here)):
        if name.startswith("_dotvault.") and not name.endswith((".py", ".pyi", ".h")):
            return os.path.join(here, name)
    raise ImportError(
        "dotvault: native library not found next to "
        f"{here!r}; the package was built without its compiled bridge"
    )


_lib = ctypes.CDLL(_library_path())


def _declare(name: str, restype, argtypes) -> None:
    fn = getattr(_lib, name)
    fn.restype = restype
    fn.argtypes = argtypes


# Owned out-strings are typed as c_void_p (not c_char_p) so ctypes hands back
# the raw pointer rather than auto-copying-and-dropping it — we need the pointer
# intact to hand to dotvault_free. take_str() does the read-then-free.
_declare("dotvault_default_config_path", c_void_p, [])
_declare("dotvault_free", None, [c_void_p])
_declare("dotvault_client_new", c_longlong, [c_char_p, c_char_p, POINTER(c_void_p)])
_declare("dotvault_client_free", None, [c_longlong])
_declare("dotvault_authenticate_cached", c_int, [c_longlong, c_longlong, POINTER(c_void_p)])
_declare("dotvault_identity_name", c_int, [c_longlong, POINTER(c_void_p), POINTER(c_void_p)])
_declare("dotvault_token", c_int, [c_longlong, POINTER(c_void_p), POINTER(c_void_p)])
_declare(
    "dotvault_read_kv_field",
    c_int,
    [c_longlong, c_char_p, c_char_p, c_char_p, c_longlong, POINTER(c_void_p), POINTER(c_int), POINTER(c_void_p)],
)
_declare(
    "dotvault_read_user_secret",
    c_int,
    [c_longlong, c_char_p, c_char_p, c_longlong, POINTER(c_void_p), POINTER(c_int), POINTER(c_void_p)],
)
_declare(
    "dotvault_remote_browse",
    c_int,
    [c_longlong, c_char_p, c_longlong, POINTER(c_void_p)],
)
_declare(
    "dotvault_remote_notify",
    c_int,
    [c_longlong, c_char_p, c_char_p, c_char_p, c_char_p, c_longlong, POINTER(c_void_p)],
)

lib = _lib


def take_str(ptr: int | c_void_p | None) -> str | None:
    """Decode an owned C string and free it; ``None``/NULL yields ``None``.

    Every string the bridge writes out is malloc'd on the Go side and owned by
    us. This reads it as UTF-8 and releases it with dotvault_free, so a single
    call site can't leak. ``ptr`` is whatever a ``c_void_p`` out-param holds
    (an int) or a NULL.
    """
    value = ptr.value if isinstance(ptr, c_void_p) else ptr
    if not value:
        return None
    try:
        raw = ctypes.cast(value, c_char_p).value
        return raw.decode("utf-8") if raw is not None else None
    finally:
        _lib.dotvault_free(value)


def encode(s: str | None) -> bytes | None:
    """Encode a Python str to NUL-terminable UTF-8 bytes for a c_char_p arg."""
    return None if s is None else s.encode("utf-8")
