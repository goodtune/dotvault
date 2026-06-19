"""Shared pytest fixtures.

The tests exercise the real native bridge, so they require the compiled
``_dotvault.<ext>`` to be present in the package. Run ``make python-lib`` (from
the repo root) or ``pip install -e .`` first. If the library is missing the
whole suite is skipped with a clear reason rather than erroring on import.
"""

import os
import sys

import pytest

# Prefer the in-tree source over any installed copy so a plain `pytest` in a
# checkout tests what's on disk.
_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    import dotvault  # noqa: F401
except ImportError as exc:  # native library not built
    pytest.skip(f"native bridge not built: {exc}", allow_module_level=True)


@pytest.fixture
def config_file(tmp_path):
    """A minimal valid dotvault config pointing at an unreachable Vault.

    Reads/auth against it categorise as Unreachable (port closed), which is what
    the offline tests assert without needing a live Vault.
    """
    path = tmp_path / "config.yaml"
    path.write_text(
        "vault:\n"
        "  address: http://127.0.0.1:59999\n"
        "  auth_method: token\n"
        "rules:\n"
        "  - name: dummy\n"
        "    target:\n"
        "      path: /tmp/dotvault-test-dummy.txt\n"
        "      format: text\n"
        "      template: \"x\"\n"
    )
    return str(path)
