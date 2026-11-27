from debunk.checkers.base import Context, Verdict, registry
from debunk.checkers.file_exposure import FileExposure
from debunk.engine import Response
from debunk.schema import Finding

HTML = (("Content-Type", "text/html; charset=utf-8"),)
PLAIN = (("Content-Type", "text/plain; charset=utf-8"),)
ENV_BODY = "DB_PASSWORD=hunter2\nAPI_SECRET=abc123\n"


class FakeEngine:
    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def request(self, method, url, headers=None, follow=None):
        self.calls.append((method, url, dict(headers or {}), follow))
        return self.respond(url)


def resp(url, status=200, body="", headers=PLAIN, truncated=False):
    return Response(url, status, headers, body.encode(), body, truncated)


def finding(target="https://e.com/.env", **kw):
    fields = {"id": "f1", "vuln_class": "file_exposure", "target": target}
    fields.update(kw)
    return Finding(**fields)


def run(respond, target="https://e.com/.env"):
    engine = FakeEngine(respond)
    result = FileExposure().check(finding(target), Context(engine))
    return result, engine


def test_checker_is_registered():
    assert isinstance(registry.get("file_exposure"), FileExposure)


def test_confirmed_env_file_and_catchall_404():
    def respond(url):
        if url.endswith(".env"):
            return resp(url, 200, ENV_BODY)
        return resp(url, 404, "<p>not found</p>", HTML)

    result, engine = run(respond)
    assert result.verdict is Verdict.CONFIRMED
    assert "secret-looking" in result.reason
    assert engine.calls[0][3] is False
    assert engine.calls[1][0] == "GET"


def test_confirmed_private_key():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"

    def respond(url):
        if "id_rsa" in url:
            return resp(url, 200, body)
        return resp(url, 404)

    result, _ = run(respond, target="https://e.com/.ssh/id_rsa")
    assert result.verdict is Verdict.CONFIRMED
    assert "private key" in result.reason


def test_confirmed_git_config():
    body = "[core]\n\trepositoryformatversion = 0\n"

    def respond(url):
        if url.endswith("config"):
            return resp(url, 200, body)
        return resp(url, 404)

    result, _ = run(respond, target="https://e.com/.git/config")
    assert result.verdict is Verdict.CONFIRMED


def test_confirmed_sql_dump():
    body = "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"

    def respond(url):
        if "backup" in url:
            return resp(url, 200, body)
        return resp(url, 404)

    result, _ = run(respond, target="https://e.com/backup.sql")
    assert result.verdict is Verdict.CONFIRMED


def test_catchall_server_is_inconclusive():
    result, _ = run(lambda url: resp(url, 200, ENV_BODY))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "catch-all" in result.reason


def test_not_found_is_unconfirmed():
    result, _ = run(lambda url: resp(url, 404, "<p>not found</p>", HTML))
    assert result.verdict is Verdict.UNCONFIRMED
    assert "HTTP 404" in result.reason


def test_redirect_is_unconfirmed():
    def respond(url):
        return Response(url, 302, (("Location", "/login"),), b"", "")

    result, _ = run(respond)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "HTTP 302" in result.reason


def test_no_signature_match_is_unconfirmed():
    def respond(url):
        if url.endswith(".env"):
            return resp(url, 200, "<html><body>hello</body></html>", HTML)
        return resp(url, 404)

    result, _ = run(respond)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "does not match" in result.reason


def test_server_error_is_inconclusive():
    def respond(url):
        return resp(url, 500 if url.endswith(".env") else 404)

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 500" in result.reason


def test_rate_limited_is_inconclusive():
    result, _ = run(lambda url: resp(url, 429))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 429" in result.reason


def test_truncated_is_inconclusive():
    def respond(url):
        if url.endswith(".env"):
            return resp(url, 200, ENV_BODY, truncated=True)
        return resp(url, 404)

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "size limit" in result.reason
