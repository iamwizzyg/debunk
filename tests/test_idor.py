from urllib.parse import parse_qs, urlsplit

import pytest

from debunk.baseline import BaselineError
from debunk.checkers.base import Context, Verdict, registry
from debunk.checkers.idor import Idor
from debunk.engine import Response
from debunk.schema import Finding, Request

HTML = (("Content-Type", "text/html; charset=utf-8"),)


class FakeEngine:
    def __init__(self, respond):
        self.respond = respond
        self.methods = []

    def request(self, method, url, headers=None, follow=None):
        self.methods.append(method)
        idval = parse_qs(urlsplit(url).query).get("id", [""])[0]
        return self.respond(idval, url)


def resp(url, status=200, body="", truncated=False):
    return Response(url, status, HTML, body.encode(), body, truncated)


def finding(payload="other-user-42", **kw):
    fields = {
        "id": "f1",
        "vuln_class": "idor",
        "target": "https://e.com/invoice",
        "parameter": "id",
        "payload": payload,
    }
    fields.update(kw)
    return Finding(**fields)


def run(respond, payload="other-user-42"):
    engine = FakeEngine(respond)
    result = Idor().check(finding(payload), Context(engine))
    return result, engine


def test_checker_is_registered():
    assert isinstance(registry.get("idor"), Idor)


def test_confirmed_when_madeup_id_denied_and_payload_id_succeeds():
    def respond(idval, url):
        if idval == "other-user-42":
            return resp(url, 200, "<p>Invoice #42 for Example Corp</p>")
        return resp(url, 404, "<p>Not found</p>")

    result, engine = run(respond)
    assert result.verdict is Verdict.CONFIRMED
    assert engine.methods == ["GET", "GET"]
    assert "baseline status 404" in " ".join(result.evidence)


def test_confirmed_via_access_denied_text_on_baseline():
    def respond(idval, url):
        if idval == "other-user-42":
            return resp(url, 200, "<p>Invoice #42</p>")
        return resp(url, 200, "<p>Access denied</p>")

    result, _ = run(respond)
    assert result.verdict is Verdict.CONFIRMED


def test_unconfirmed_when_payload_id_is_also_denied():
    def respond(idval, url):
        return resp(url, 403, "<p>forbidden</p>")

    result, _ = run(respond)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "denied just like" in result.reason


def test_catchall_baseline_is_inconclusive_even_when_replay_differs():
    def respond(idval, url):
        if idval == "other-user-42":
            return resp(url, 200, "<p>Invoice #42 for Example Corp</p>")
        return resp(url, 200, "<p>Invoice #999 for Someone Else</p>")

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "may return the same content for any id" in result.reason


def test_inconclusive_when_pages_are_identical_despite_denial_text():
    filler = " ".join(["same"] * 40)

    def respond(idval, url):
        if idval == "other-user-42":
            return resp(url, 200, f"{filler} ok visible")
        return resp(url, 200, f"{filler} access denied")

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "also identical" in result.reason


def test_server_error_is_inconclusive():
    def respond(idval, url):
        return resp(url, 500 if idval == "other-user-42" else 404)

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 500" in result.reason


def test_rate_limited_baseline_is_inconclusive():
    result, _ = run(lambda idval, url: resp(url, 429))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "baseline request got HTTP 429" in result.reason


def test_truncated_response_is_inconclusive():
    def respond(idval, url):
        if idval == "other-user-42":
            return resp(url, 200, "<p>ok</p>", truncated=True)
        return resp(url, 404, "<p>no</p>")

    result, _ = run(respond)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "size limit" in result.reason


def test_empty_payload_is_an_error():
    result, _ = run(lambda idval, url: resp(url, 200), payload="")
    assert result.verdict is Verdict.ERROR
    assert "no payload" in result.reason


def test_head_request_is_sent_as_get():
    def respond(idval, url):
        if idval == "other-user-42":
            return resp(url, 200, "<p>Invoice #42</p>")
        return resp(url, 404, "<p>not found</p>")

    req = Request("HEAD", "https://e.com/invoice?id=other-user-42")
    engine = FakeEngine(respond)
    result = Idor().check(finding(request=req), Context(engine))
    assert engine.methods == ["GET", "GET"]
    assert result.verdict is Verdict.CONFIRMED


def test_no_parameter_and_payload_not_in_url_raises_baseline_error():
    engine = FakeEngine(lambda idval, url: resp(url, 200))
    f = finding(parameter="")
    with pytest.raises(BaselineError):
        Idor().check(f, Context(engine))
