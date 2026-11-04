"""Offline tests for Client.client_certificate().

Neither case reaches a live Vault. With the section disabled the call is refused
before any lookup (NotConfigured). With it enabled and no token anywhere,
AuthenticateCached runs, finds nothing, and the call raises LoginRequired.
Everything that could supply a token is isolated: DOTVAULT_TOKEN is unset, HOME
and the XDG dirs point at an empty temp dir (so there is no token file), and the
config disables the peer socket (token_socket: []) and leaves the API socket off.
"""

import os
import subprocess
import sys

import dotvault
import pytest

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")

# The Go runtime snapshots its environment when the native library loads, and
# the bridge re-syncs only DOTVAULT_TOKEN and VAULT_NAMESPACE afterwards. HOME
# (which locates ~/.dotvault-token) therefore cannot be isolated from inside an
# already-running test process, so each isolation-sensitive case runs in a fresh
# interpreter whose environment is clean from the start.
_CHILD = """
import sys
sys.path.insert(0, sys.argv[1])
import dotvault
with dotvault.Client(config_path=sys.argv[2]) as c:
    try:
        c.client_certificate(timeout=2)
    except dotvault.DotvaultError as e:
        print(type(e).__name__)
    else:
        print("no error")
"""


def _outcome(tmp_path, cfg: str) -> str:
    """Run client_certificate() against cfg in a hermetic child; return the
    exception class name raised (or "no error")."""
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DOTVAULT_", "VAULT_"))}
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_RUNTIME_DIR=str(home / "run"),
    )
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, _SRC, cfg],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _write_config(tmp_path, client_cert: str, token_socket: str = "[]") -> str:
    path = tmp_path / "config.yaml"
    path.write_text(
        "vault:\n"
        "  address: http://127.0.0.1:59999\n"
        "  auth_method: token\n"
        f"  token_socket: {token_socket}\n"
        f"{client_cert}"
        "rules:\n"
        "  - name: dummy\n"
        "    target:\n"
        "      path: /tmp/dotvault-test-dummy.txt\n"
        "      format: text\n"
        "      template: \"x\"\n"
    )
    return str(path)


def test_client_certificate_disabled_is_not_configured(tmp_path):
    cfg = _write_config(tmp_path, "")
    assert _outcome(tmp_path, cfg) == "NotConfigured"


def test_client_certificate_enabled_without_token_is_login_required(tmp_path):
    cfg = _write_config(
        tmp_path,
        "client_cert:\n  enabled: true\n  pki_mount: pki\n  pki_role: client\n",
    )
    assert _outcome(tmp_path, cfg) == "LoginRequired"


def test_client_certificate_use_after_close_raises(tmp_path):
    cfg = _write_config(tmp_path, "")
    c = dotvault.Client(config_path=cfg)
    c.close()
    with pytest.raises(dotvault.DotvaultError):
        c.client_certificate()
