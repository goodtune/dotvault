"""Tests for the peer-action surface (browse / notify) over a Unix socket.

These drive the real native bridge against a throwaway HTTP server bound to a
Unix domain socket standing in for a peer dotvault. No Vault is involved — the
peer endpoints are the only thing exercised.
"""

import http.server
import socket
import socketserver
import threading
import urllib.parse

import pytest

import dotvault


class _PeerHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        form = urllib.parse.parse_qs(body)
        self.server.received.append((self.path, form))
        status, payload = self.server.responder(self.path, form)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, *args):  # silence
        pass


class _UnixHTTPServer(socketserver.UnixStreamServer):
    # http.server expects a (host, port) client address tuple; AF_UNIX accept
    # yields "" — substitute a dummy so BaseHTTPRequestHandler is happy.
    def get_request(self):
        request, _ = super().get_request()
        return request, ("localhost", 0)


@pytest.fixture
def peer(tmp_path):
    """Start a peer HTTP server on a Unix socket and yield (socket_path, ctl).

    ``ctl.received`` collects (path, form) tuples; set ``ctl.responder`` to a
    ``(path, form) -> (status, json_body)`` callable to control the reply.
    """
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("AF_UNIX unavailable on this platform")
    sock_path = str(tmp_path / "peer.sock")

    server = _UnixHTTPServer(sock_path, _PeerHandler)
    server.received = []
    server.responder = lambda path, form: (200, '{"status":"ok"}')

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield sock_path, server
    finally:
        server.shutdown()
        server.server_close()


def _client_with_socket(tmp_path, sock_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "vault:\n"
        "  address: http://127.0.0.1:59999\n"
        "  auth_method: token\n"
        f"  token_socket: {sock_path}\n"
        "rules:\n"
        "  - name: dummy\n"
        "    target:\n"
        "      path: /tmp/dotvault-test-dummy.txt\n"
        "      format: text\n"
        '      template: "x"\n'
    )
    return dotvault.Client(config_path=str(cfg))


def test_browse_posts_to_peer(tmp_path, peer):
    sock_path, ctl = peer
    with _client_with_socket(tmp_path, sock_path) as c:
        c.browse("https://example.com/x", timeout=5)
    assert ctl.received
    path, form = ctl.received[-1]
    assert path == "/api/v1/remote/browse"
    assert form["url"] == ["https://example.com/x"]


def test_notify_posts_to_peer(tmp_path, peer):
    sock_path, ctl = peer
    ctl.responder = lambda path, form: (200, '{"status":"notification delivered"}')
    with _client_with_socket(tmp_path, sock_path) as c:
        c.notify("error", "Job failed", "see logs", timeout=5)
    path, form = ctl.received[-1]
    assert path == "/api/v1/remote/notify"
    assert form["level"] == ["error"]
    assert form["title"] == ["Job failed"]
    assert form["body"] == ["see logs"]


def test_browse_without_socket_is_peer_unavailable(config_file):
    # config_file has no token_socket -> the client cannot reach a peer.
    with dotvault.Client(config_path=config_file) as c:
        with pytest.raises(dotvault.PeerUnavailable):
            c.browse("https://example.com", timeout=5)


def test_browse_peer_rejection_is_plain_error(tmp_path, peer):
    # A 400 from the peer (validated + rejected) must NOT be PeerUnavailable.
    sock_path, ctl = peer
    ctl.responder = lambda path, form: (400, '{"error":"unsupported url scheme"}')
    with _client_with_socket(tmp_path, sock_path) as c:
        with pytest.raises(dotvault.DotvaultError) as exc:
            c.browse("file:///etc/passwd", timeout=5)
    assert not isinstance(exc.value, dotvault.PeerUnavailable)
    assert "unsupported url scheme" in str(exc.value)


def test_notify_peer_delivery_failure_is_unavailable(tmp_path, peer):
    # A 502 (peer reached, delivery failed) maps to PeerUnavailable.
    sock_path, ctl = peer
    ctl.responder = lambda path, form: (502, '{"error":"no daemon"}')
    with _client_with_socket(tmp_path, sock_path) as c:
        with pytest.raises(dotvault.PeerUnavailable):
            c.notify("info", "hi", timeout=5)
