
from debunk.checkers.auth import AuthBypass
from debunk.checkers.base import Context, Verdict, registry
from debunk.engine import Response
from debunk.schema import Finding, Request

HTML = (("Content-Type", "text/html; charset=utf-8"),)


class FakeEngine:
    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def request(self, method, url, headers=None, follow=None):
        headers = dict(headers or {})
        self.calls.append((method, url, headers, follow))
        return self.respond(method, url, headers)


def resp(status=200, body="", truncated=False):
    return Response("https://e.com/admin", status, HTML, body.encode(), body, truncated)


def redirect_resp(location, status=302):
    return Response("https://e.com/admin", status, (("Location", location),), b"", "")


def finding(request=None, **kw):
    fields = {"id": "f1", "vuln_class": "auth_bypass", "target": "https://e.com/admin"}
    fields.update(kw)
    if request is not None:
        fields["request"] = request
    return Finding(**fields)


def run(respond, request):
    engine = FakeEngine(respond)
    result = AuthBypass().check(finding(request=request), Context(engine))
    return result, engine


def test_checker_is_registered():
    assert isinstance(registry.get("auth_bypass"), AuthBypass)


def test_confirmed_bypass_via_extra_header():
    def respond(method, url, headers):
        if "X-Original-URL" in headers:
            return resp(200, "<p>Welcome admin</p>")
        return resp(403, "<p>forbidden</p>")

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, engine = run(respond, req)
    assert result.verdict is Verdict.CONFIRMED
    assert len(engine.calls) == 2
    assert engine.calls[0][2] == {}
    assert engine.calls[1][2] == {"X-Original-URL": "/admin"}
    assert engine.calls[0][3] is False and engine.calls[1][3] is False


def test_confirmed_bypass_via_path_trick():
    def respond(method, url, headers):
        return resp(200, "<p>ok</p>") if ".." in url else resp(403, "<p>no</p>")

    req = Request("GET", "https://e.com/public/../admin")
    result, _ = run(respond, req)
    assert result.verdict is Verdict.CONFIRMED


def test_confirmed_via_redirect_to_login_counted_as_denial():
    def respond(method, url, headers):
        if "X-Original-URL" in headers:
            return resp(200, "<p>welcome</p>")
        return redirect_resp("https://e.com/login")

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, _ = run(respond, req)
    assert result.verdict is Verdict.CONFIRMED


def test_unconfirmed_when_both_denied():
    def respond(method, url, headers):
        return resp(403, "<p>forbidden</p>")

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, _ = run(respond, req)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "no sign of a bypass" in result.reason


def test_inconclusive_when_plain_request_is_not_denied():
    def respond(method, url, headers):
        return resp(200, "<p>ok</p>")

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, _ = run(respond, req)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "may not require authorization" in result.reason


def test_inconclusive_when_responses_are_nearly_identical():
    # Same status on both sides (so same_page is not ruled out by status
    # alone) -- only the denial wording differs, by one token.
    filler = " ".join(["same"] * 40)

    def respond(method, url, headers):
        if "X-Original-URL" in headers:
            return resp(200, f"{filler} welcome")
        return resp(200, f"{filler} access denied")

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, _ = run(respond, req)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "identical to the plain denied response" in result.reason


def test_server_error_is_inconclusive():
    def respond(method, url, headers):
        return resp(500) if "X-Original-URL" in headers else resp(403)

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, _ = run(respond, req)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 500" in result.reason


def test_rate_limited_control_is_inconclusive():
    result, _ = run(lambda m, u, h: resp(429), Request("GET", "https://e.com/admin"))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "control request got HTTP 429" in result.reason


def test_truncated_response_is_inconclusive():
    def respond(method, url, headers):
        if "X-Original-URL" in headers:
            return resp(200, "<p>ok</p>", truncated=True)
        return resp(403, "<p>no</p>")

    req = Request("GET", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, _ = run(respond, req)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "size limit" in result.reason


def test_missing_request_data_is_an_error():
    engine = FakeEngine(lambda m, u, h: resp(200))
    result = AuthBypass().check(finding(), Context(engine))
    assert result.verdict is Verdict.ERROR
    assert "no request data" in result.reason
    assert engine.calls == []


def test_credentials_are_stripped_from_both_requests():
    def respond(method, url, headers):
        assert "Cookie" not in headers
        assert "Authorization" not in headers
        if "X-Original-URL" in headers:
            return resp(200, "<p>ok</p>")
        return resp(403, "<p>no</p>")

    req = Request(
        "GET",
        "https://e.com/admin?token=abc123",
        {
            "Cookie": "session=real",
            "Authorization": "Bearer abc",
            "X-Original-URL": "/admin",
        },
    )
    result, engine = run(respond, req)
    assert result.verdict is Verdict.CONFIRMED
    assert "token=" not in engine.calls[1][1]


def test_head_method_relies_on_status_for_denial():
    def respond(method, url, headers):
        assert method == "HEAD"
        return resp(200, "") if "X-Original-URL" in headers else resp(403, "")

    req = Request("HEAD", "https://e.com/admin", {"X-Original-URL": "/admin"})
    result, engine = run(respond, req)
    assert result.verdict is Verdict.CONFIRMED
    assert engine.calls[0][0] == "HEAD"
