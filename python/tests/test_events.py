"""Tests for Client.subscribe over a Unix socket.

These drive the real native bridge against a throwaway HTTP server bound to a
Unix domain socket that streams change notices the way a dotvault daemon's
GET /api/v1/events does. No Vault is involved.
"""

import http.server
import queue
import socket
import shutil
import socketserver
import tempfile
import threading
from datetime import datetime, timezone

import pytest

import dotvault

if not hasattr(socket, "AF_UNIX"):
    pytest.skip("AF_UNIX unavailable on this platform", allow_module_level=True)


class _EventsHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 (http.server API)
        if self.path != "/api/v1/events":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self._write(": connected\n\n")
        while not self.server.stopping.is_set():
            try:
                notice = self.server.notices.get(timeout=0.1)
            except queue.Empty:
                continue
            self._write(f"event: kv-write\ndata: {notice}\n\n")

    def _write(self, text):
        # No Content-Length on a stream: send it chunked so the Go client
        # reads each notice as it arrives.
        data = text.encode()
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def send_response(self, code, message=None):
        super().send_response(code, message)
        if code == 200:
            self.send_header("Transfer-Encoding", "chunked")

    def log_message(self, *args):  # silence
        pass


class _ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        request, _ = super().get_request()
        return request, ("localhost", 0)


@pytest.fixture
def daemon():
    # Not tmp_path: a Unix socket path is limited to about 104 bytes on macOS,
    # and pytest's per-test directory under $TMPDIR is already near that.
    sock_dir = tempfile.mkdtemp(prefix="dvt", dir="/tmp")
    sock_path = sock_dir + "/events.sock"
    server = _ThreadingUnixHTTPServer(sock_path, _EventsHandler)
    server.notices = queue.Queue()
    server.stopping = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield sock_path, server
    finally:
        server.stopping.set()
        server.shutdown()
        server.server_close()
        shutil.rmtree(sock_dir, ignore_errors=True)


def _client(tmp_path, token_socket=None):
    cfg = tmp_path / "config.yaml"
    lines = [
        "vault:",
        "  address: http://127.0.0.1:59999",
        "  auth_method: token",
    ]
    if token_socket is None:
        lines.append("  token_socket: []")
    else:
        lines.append(f"  token_socket: {token_socket}")
    lines += [
        "rules:",
        "  - name: dummy",
        "    target:",
        "      path: /tmp/dotvault-test-dummy.txt",
        "      format: text",
        '      template: "x"',
    ]
    cfg.write_text("\n".join(lines) + "\n")
    return dotvault.Client(config_path=str(cfg))


def test_subscribe_delivers_events(tmp_path, daemon):
    sock_path, server = daemon
    with _client(tmp_path, sock_path) as c, c.subscribe() as sub:
        server.notices.put(
            '{"key":"gh","version":41,"source":"refresh","time":"2026-11-07T01:02:03.123456789Z"}'
        )
        before = datetime.now(timezone.utc)
        event = sub.next(timeout=5)
        assert (event.key, event.version, event.source) == ("gh", 41, "refresh")
        # The peer's own timestamp is a claim; the event carries the time it
        # was received here.
        assert event.time is not None and event.time.tzinfo is not None
        assert event.time >= before.replace(microsecond=0)


def test_subscribe_next_times_out_with_none(tmp_path, daemon):
    sock_path, _ = daemon
    with _client(tmp_path, sock_path) as c, c.subscribe() as sub:
        assert sub.next(timeout=0.2) is None


def test_subscribe_iterates(tmp_path, daemon):
    sock_path, server = daemon
    with _client(tmp_path, sock_path) as c, c.subscribe() as sub:
        server.notices.put('{"key":"gh","version":1}')
        server.notices.put('{"key":"databricks/prod","version":2}')
        got = []
        for event in sub:
            got.append((event.key, event.version))
            if len(got) == 2:
                break
        assert got == [("gh", 1), ("databricks/prod", 2)]


def test_subscribe_without_sockets_raises_peer_unavailable(tmp_path):
    with _client(tmp_path) as c:
        with pytest.raises(dotvault.PeerUnavailable):
            c.subscribe()


def test_closed_subscription_raises(tmp_path, daemon):
    sock_path, _ = daemon
    with _client(tmp_path, sock_path) as c:
        sub = c.subscribe()
        sub.close()
        sub.close()  # idempotent
        with pytest.raises(dotvault.SubscriptionClosed):
            sub.next(timeout=0.1)


def test_zero_timeout_polls_rather_than_blocking(tmp_path, daemon):
    sock_path, _ = daemon
    with _client(tmp_path, sock_path) as c, c.subscribe() as sub:
        done = threading.Event()

        def poll():
            sub.next(timeout=0)
            done.set()

        threading.Thread(target=poll, daemon=True).start()
        assert done.wait(5), "next(timeout=0) blocked instead of polling"


def test_close_ends_iteration_in_another_thread(tmp_path, daemon):
    sock_path, _ = daemon
    with _client(tmp_path, sock_path) as c:
        sub = c.subscribe()
        finished = threading.Event()

        def consume():
            for _ in sub:
                pass
            finished.set()

        threading.Thread(target=consume, daemon=True).start()
        sub.close()
        assert finished.wait(5), "iteration did not end after close()"
