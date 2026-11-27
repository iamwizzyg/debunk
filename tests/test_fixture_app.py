"""Smoke tests proving the fixture app itself behaves as intended -- not
testing debunk here, just the fixture it will be tested against."""

import threading
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

import pytest

from tests.fixtures.app import make_server


@pytest.fixture
def server():
    srv = make_server()
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


class _NoRedirect(HTTPRedirectHandler):
    """Report a 3xx as-is instead of urllib's default of following it."""

    def redirect_request(self, *args, **kwargs):
        return None


_opener = build_opener(_NoRedirect)


def get(url: str, headers: dict | None = None) -> tuple[int, str, dict]:
    req = Request(url, headers=headers or {})
    try:
        with _opener.open(req) as resp:
            return resp.status, resp.read().decode(), dict(resp.headers)
    except Exception as exc:  # urllib raises HTTPError for non-2xx
        status = getattr(exc, "code", 0)
        body = exc.read().decode() if hasattr(exc, "read") else ""
        headers = dict(getattr(exc, "headers", {}) or {})
        return status, body, headers


def test_xss_reflects_the_query_unencoded(server):
    status, body, _ = get(f"{server.base}/xss?q=<script>alert(1)</script>")
    assert status == 200
    assert "<script>alert(1)</script>" in body


def test_sqli_true_condition_returns_rows(server):
    condition = quote("' OR '1'='1")
    status, body, _ = get(f"{server.base}/sqli?id={condition}")
    assert status == 200
    assert "Alice" in body and "Bob" in body


def test_sqli_false_condition_returns_no_rows(server):
    condition = quote("' OR '1'='2")
    status, body, _ = get(f"{server.base}/sqli?id={condition}")
    assert status == 200
    assert "Alice" not in body


def test_sqli_plain_id_behaves_like_a_normal_lookup(server):
    _, body1, _ = get(f"{server.base}/sqli?id=1")
    _, body2, _ = get(f"{server.base}/sqli?id=999")
    assert "Alice" in body1
    assert "Alice" not in body2


def test_redirect_sends_a_302_to_the_given_url(server):
    status, _, headers = get(f"{server.base}/redirect?next=https://evil.example/")
    assert status == 302
    assert headers["Location"] == "https://evil.example/"


def test_account_known_id_is_visible(server):
    status, body, _ = get(f"{server.base}/account?id=42")
    assert status == 200
    assert "Invoice #42" in body


def test_account_unknown_id_is_denied(server):
    status, body, _ = get(f"{server.base}/account?id=999")
    assert status == 404
    assert "not found" in body.lower()


def test_admin_is_forbidden_without_the_header(server):
    status, body, _ = get(f"{server.base}/admin")
    assert status == 403
    assert "forbidden" in body.lower()


def test_admin_is_allowed_with_the_debug_header(server):
    status, body, _ = get(f"{server.base}/admin", {"X-Debug": "1"})
    assert status == 200
    assert "admin panel" in body.lower()


def test_env_file_contains_a_recognisable_secret(server):
    status, body, headers = get(f"{server.base}/.env")
    assert status == 200
    assert "DB_PASSWORD=" in body
    assert headers["Content-Type"].startswith("text/plain")


def test_unknown_path_is_404(server):
    status, _, _ = get(f"{server.base}/nope")
    assert status == 404


def test_head_request_has_no_body(server):
    req = Request(f"{server.base}/xss?q=hi", method="HEAD")
    with _opener.open(req) as resp:
        assert resp.status == 200
        assert resp.read() == b""
