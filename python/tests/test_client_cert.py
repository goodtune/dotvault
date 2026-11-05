"""Offline tests for Client.client_certificate().

Neither case reaches a live Vault. With the section disabled the call is refused
before any lookup (NotConfigured). With it enabled and no token anywhere,
AuthenticateCached runs, finds nothing, and the call raises LoginRequired.
Everything that could supply a token is isolated: DOTVAULT_TOKEN is unset, HOME
and the XDG dirs point at an empty temp dir (so there is no token file), and the
config disables the peer socket (token_socket: []) and leaves the API socket off.
"""

import base64
import datetime
import getpass
import json
import os
import shutil
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
_CHILD_OK = """
import json, sys
sys.path.insert(0, sys.argv[1])
import dotvault
with dotvault.Client(config_path=sys.argv[2]) as c:
    cert, key = c.client_certificate(timeout=5)
print(json.dumps({"cert": cert, "key": key}))
"""

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


def _child_env(tmp_path) -> dict:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DOTVAULT_", "VAULT_"))}
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_RUNTIME_DIR=str(home / "run"),
    )
    return env


def _outcome(tmp_path, cfg: str) -> str:
    """Run client_certificate() against cfg in a hermetic child; return the
    exception class name raised (or "no error")."""
    env = _child_env(tmp_path)
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


def _os_user() -> str:
    # The held envelope is served only to the OS account it was issued to; the
    # facade resolves that from the uid, not from LOGNAME/USER.
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except ImportError:  # Windows
        return getpass.getuser().split("\\")[-1]


def _openssl(*args: str, cwd) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
def test_client_certificate_returns_held_cert_and_key_unswapped(tmp_path):
    """The success path: a held mtls credential is served with no token and no
    Vault, and the two out-strings arrive as (certificate, key) -- not swapped,
    not truncated, byte for byte what is on disk."""
    user = _os_user()
    storage = tmp_path / "mtls"
    storage.mkdir()
    gen = tmp_path / "gen"
    gen.mkdir()
    # PKCS#8 EC key + self-signed client certificate, as auth's file backend
    # stores them.
    _openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-out", "key.pem", cwd=gen)
    _openssl("req", "-new", "-x509", "-key", "key.pem", "-out", "cert.pem",
             "-subj", f"/CN={user}", "-days", "10", cwd=gen)
    cert_pem = (gen / "cert.pem").read_text()
    key_pem = (gen / "key.pem").read_text()
    assert "BEGIN CERTIFICATE" in cert_pem and "PRIVATE KEY" in key_pem

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    envelope = {
        "schema": 1,
        "method": "mtls",
        "backend": "file",
        "cert_pem": cert_pem,
        # The file backend's handle is the PEM key itself; Go's []byte is
        # base64 in JSON.
        "handle": base64.b64encode(key_pem.encode()).decode(),
        "serial": "ignored",
        "not_after": (now + datetime.timedelta(days=10)).isoformat().replace("+00:00", "Z"),
        "identity": user,
        "issued_at": (now - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    }
    cred = storage / "credential.json"
    cred.write_text(json.dumps(envelope))
    os.chmod(cred, 0o600)

    cfg = _write_config(
        tmp_path,
        "client_cert:\n  enabled: true\n",
    )
    # A held certificate needs the cert-auth method and a storage dir; the
    # PKI/cert roles only have to satisfy validation (nothing is signed).
    text = open(cfg).read().replace(
        "  auth_method: token\n",
        "  auth_method: mtls\n"
        "  mtls:\n"
        "    cert_role: dotvault\n"
        "    pki_role: dotvault\n"
        f"    storage_dir: {storage}\n",
    )
    open(cfg, "w").write(text)

    proc = subprocess.run(
        [sys.executable, "-c", _CHILD_OK, _SRC, cfg],
        env=_child_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)

    assert "BEGIN CERTIFICATE" in got["cert"]
    assert "PRIVATE KEY" not in got["cert"]
    assert "PRIVATE KEY" in got["key"]
    assert "BEGIN CERTIFICATE" not in got["key"]
    assert got["cert"].strip() == cert_pem.strip()
    assert got["key"].strip() == key_pem.strip()
