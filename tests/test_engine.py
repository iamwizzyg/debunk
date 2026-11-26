import gzip
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from debunk.engine import (
    BlockedError,
    Engine,
    HttpConfig,
    HttpError,
    ReadOnlyError,
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        srv = self.server
        path = self.path
        if path == "/ok":
            self._reply(200, b"hello", {"Content-Type": "text/plain"})
        elif path == "/gzip":
            body = gzip.compress(b"zipped hello")
            self._reply(200, body, {"Content-Encoding": "gzip"})
        elif path == "/latin1":
            body = "caf\u00e9".encode("latin-1")
            self._reply(200, body, {"Content-Type": "text/plain; charset=iso-8859-1"})
        elif path == "/cookie":
            self._reply(200, b"x", {"Set-Cookie": "session=abc123"})
        elif path == "/redir":
            self._reply(302, headers={"Location": "/ok"})
        elif path == "/loop":
            self._reply(302, headers={"Location": "/loop"})
        elif path == "/out":
            self._reply(302, headers={"Location": "http://blocked.invalid/x"})
        elif path == "/flaky":
            with srv.lock:
                srv.flaky += 1
                count = srv.flaky
            if count <= 2:
                self._reply(503)
            else:
                self._reply(200, b"finally")
        elif path == "/down":
            self._reply(503)
        elif path == "/big":
            self._reply(200, b"a" * 5000)
        elif path == "/slow":
            with srv.lock:
                srv.active += 1
                srv.peak = max(srv.peak, srv.active)
            time.sleep(0.2)
            with srv.lock:
                srv.active -= 1
            self._reply(200, b"slow")
        else:
            self._reply(404, b"nope")

    do_HEAD = do_GET


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.lock = threading.Lock()
    srv.flaky = 0
    srv.active = 0
    srv.peak = 0
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def make(**kw):
    opts = {"delay": 0.0, "backoff": 0.0}
    opts.update(kw)
    return Engine(HttpConfig(**opts))


def test_get_returns_status_body_and_text(server):
    resp = make().request("GET", server.base + "/ok")
    assert resp.status == 200
    assert resp.body == b"hello"
    assert resp.text == "hello"
    assert resp.attempts == 1


def test_head_has_no_body(server):
    resp = make().request("HEAD", server.base + "/ok")
    assert resp.status == 200
    assert resp.body == b""


def test_gzip_body_is_decoded(server):
    assert make().request("GET", server.base + "/gzip").text == "zipped hello"


def test_declared_charset_is_used(server):
    assert make().request("GET", server.base + "/latin1").text == "caf\u00e9"


def test_large_body_is_truncated(server):
    resp = make(max_body=1000).request("GET", server.base + "/big")
    assert resp.truncated is True
    assert len(resp.body) == 1000


def test_redirect_not_followed_when_disabled(server):
    resp = make().request("GET", server.base + "/redir", follow=False)
    assert resp.status == 302
    assert resp.header("LOCATION") == "/ok"
    assert resp.redirects == ()


def test_redirect_followed_and_chain_recorded(server):
    resp = make().request("GET", server.base + "/redir")
    assert resp.status == 200
    assert resp.text == "hello"
    assert resp.redirects == ((302, server.base + "/redir"),)


def test_redirect_loop_is_stopped(server):
    with pytest.raises(HttpError, match="redirects"):
        make(max_redirects=3).request("GET", server.base + "/loop")


def test_guard_blocks_redirect_to_out_of_scope_host(server):
    engine = Engine(
        HttpConfig(delay=0.0, backoff=0.0),
        guard=lambda url: "blocked.invalid" not in url,
    )
    with pytest.raises(BlockedError, match="out of scope"):
        engine.request("GET", server.base + "/out")


def test_retries_on_5xx_with_fixed_backoff(server):
    sleeps = []
    engine = Engine(
        HttpConfig(delay=0.0, backoff=0.5, retries=2), sleep=sleeps.append
    )
    resp = engine.request("GET", server.base + "/flaky")
    assert resp.status == 200
    assert resp.attempts == 3
    assert sleeps == [0.5, 1.0]


def test_persistent_5xx_returns_last_response(server):
    resp = make(retries=1).request("GET", server.base + "/down")
    assert resp.status == 503
    assert resp.attempts == 2


def test_unreachable_host_raises_after_retries():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(HttpError, match="failed after 2"):
        make(retries=1, timeout=2).request("GET", f"http://127.0.0.1:{port}/")


def test_writes_are_refused():
    with pytest.raises(ReadOnlyError):
        make().request("POST", "http://127.0.0.1:1/")


def test_unsupported_scheme_is_refused():
    with pytest.raises(HttpError, match="unsupported"):
        make().request("GET", "ftp://example.com/")


def test_set_cookie_is_redacted_in_safe_headers(server):
    resp = make().request("GET", server.base + "/cookie")
    assert ("Set-Cookie", "[REDACTED]") in resp.safe_headers()


def test_delay_spaces_requests_to_the_same_host(server):
    sleeps = []
    engine = Engine(
        HttpConfig(delay=0.25, backoff=0.0),
        sleep=sleeps.append,
        clock=lambda: 100.0,
    )
    engine.request("GET", server.base + "/ok")
    engine.request("GET", server.base + "/ok")
    assert sleeps == [pytest.approx(0.25)]


def test_per_host_concurrency_cap(server):
    engine = make(per_host=2)
    threads = [
        threading.Thread(target=engine.request, args=("GET", server.base + "/slow"))
        for _ in range(6)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert 1 <= server.peak <= 2
