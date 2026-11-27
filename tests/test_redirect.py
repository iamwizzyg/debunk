from urllib.parse import parse_qs, urlsplit

import pytest

from debunk.baseline import BaselineError
from debunk.checkers.base import Context, Verdict, registry
from debunk.checkers.redirect import OpenRedirect, _explicit_host
from debunk.engine import Response
from debunk.schema import Finding

ATTACKER = "https://evil.example"


class FakeEngine:
    def __init__(self, respond):
        self.respond = respond
        self.methods = []
        self.follows = []

    def request(self, method, url, headers=None, follow=None):
        self.methods.append(method)
        self.follows.append(follow)
        q = parse_qs(urlsplit(url).query).get("dest", [""])[0]
        return self.respond(q, url)


def resp(url, status=200, location=None, body="", truncated=False):
    headers = (("Location", location),) if location else ()
    return Response(url, status, headers, body.encode(), body, truncated)


def finding(payload, **kw):
    fields = {
        "id": "f1",
        "vuln_class": "open_redirect",
        "target": "https://e.com/go",
        "parameter": "dest",
        "payload": payload,
    }
    fields.update(kw)
    return Finding(**fields)


def run(respond, payload=f"{ATTACKER}/"):
    engine = FakeEngine(respond)
    result = OpenRedirect().check(finding(payload), Context(engine))
    return result, engine


def test_checker_is_registered():
    assert isinstance(registry.get("open_redirect"), OpenRedirect)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://evil.example/x", "evil.example"),
        ("//evil.example/x", "evil.example"),
        ("/\\evil.example/x", "evil.example"),
        ("https://evil.example", "evil.example"),
        ("/path/only", None),
        ("evil.example", None),
        ("ftp://evil.example", None),
    ],
)
def test_explicit_host_parsing(url, expected):
    assert _explicit_host(url) == expected


def test_confirmed_via_location_header_and_control_does_not_redirect():
    def respond(q, url):
        if q == f"{ATTACKER}/":
            return resp(url, 302, f"{ATTACKER}/")
        return resp(url, 200)

    result, engine = run(respond)
    assert result.verdict is Verdict.CONFIRMED
    assert engine.methods == ["GET", "GET"]
    assert engine.follows == [False, False]
    assert "Location header" in " ".join(result.evidence)


def test_confirmed_via_meta_refresh_attribute_order_independent():
    body = f'<meta content="0;url={ATTACKER}/" http-equiv="refresh">'

    def respond(q, url):
        if q == f"{ATTACKER}/":
            return resp(url, 200, body=body)
        return resp(url, 200, body="<p>hi</p>")

    result, _ = run(respond)
    assert result.verdict is Verdict.CONFIRMED
    assert "meta refresh tag" in " ".join(result.evidence)


def test_no_redirect_at_all_is_unconfirmed():
    result, _ = run(lambda q, url: resp(url, 200, body="<p>hi</p>"))
    assert result.verdict is Verdict.UNCONFIRMED
    assert "does not redirect" in result.reason


def test_redirect_to_targets_own_host_is_unconfirmed():
    def respond(q, url):
        if "evil" in q:
            return resp(url, 302, "https://e.com/home")
        return resp(url, 200)

    result, _ = run(respond)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "target's own host" in result.reason


def test_redirect_to_a_different_host_than_the_payload_is_unconfirmed():
    def respond(q, url):
        if "evil" in q:
            return resp(url, 302, "https://other-site.example/")
        return resp(url, 200)

    result, _ = run(respond)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "different host" in result.reason


def test_control_also_redirecting_offsite_is_inconclusive():
    def respond(q, url):
        return resp(url, 302, f"{ATTACKER}/")

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "may not be caused by the payload" in result.reason


def test_control_redirecting_elsewhere_does_not_block_confirmed():
    def respond(q, url):
        if "evil" in q:
            return resp(url, 302, f"{ATTACKER}/")
        return resp(url, 302, "https://e.com/login")

    result, _ = run(respond)
    assert result.verdict is Verdict.CONFIRMED


def test_firewall_block_is_inconclusive():
    def respond(q, url):
        return resp(url, 403 if "evil" in q else 200)

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "firewall" in result.reason


def test_server_error_is_inconclusive():
    def respond(q, url):
        return resp(url, 500 if "evil" in q else 200)

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 500" in result.reason


def test_truncated_with_no_destination_is_inconclusive():
    result, _ = run(lambda q, url: resp(url, 200, truncated=True))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "size limit" in result.reason


def test_empty_payload_is_an_error():
    result, _ = run(lambda q, url: resp(url, 200), payload="")
    assert result.verdict is Verdict.ERROR
    assert "no payload" in result.reason


def test_payload_without_a_host_is_an_error():
    result, _ = run(lambda q, url: resp(url, 200), payload="/account/settings")
    assert result.verdict is Verdict.ERROR
    assert "does not name an external host" in result.reason


def test_payload_naming_the_targets_own_host_is_an_error():
    result, _ = run(lambda q, url: resp(url, 200), payload="https://e.com/evil")
    assert result.verdict is Verdict.ERROR
    assert "same as the target's host" in result.reason


def test_head_request_is_sent_as_get():
    def respond(q, url):
        if "evil" in q:
            return resp(url, 302, f"{ATTACKER}/")
        return resp(url, 200)

    engine = FakeEngine(respond)
    from debunk.schema import Request

    req = Request("HEAD", f"https://e.com/go?dest={ATTACKER}/")
    f = finding(f"{ATTACKER}/", request=req)
    result = OpenRedirect().check(f, Context(engine))
    assert engine.methods == ["GET", "GET"]
    assert result.verdict is Verdict.CONFIRMED


def test_no_parameter_and_payload_not_in_url_raises_baseline_error():
    engine = FakeEngine(lambda q, url: resp(url, 200))
    f = finding(f"{ATTACKER}/", parameter="")
    with pytest.raises(BaselineError):
        OpenRedirect().check(f, Context(engine))
