from urllib.parse import parse_qs, urlsplit

import pytest

from debunk.baseline import BaselineError
from debunk.checkers.base import Context, Verdict, registry
from debunk.checkers.sqli import BooleanSqli, _flip
from debunk.engine import Response
from debunk.schema import Finding, Request

HTML = (("Content-Type", "text/html; charset=utf-8"),)
TRUE_PAYLOAD = "' OR '1'='1"


class FakeEngine:
    def __init__(self, render, status=None, headers=HTML, truncated=False):
        self.render = render
        self.status = status or (lambda q: 200)
        self.headers = headers
        self.truncated = truncated
        self.methods = []

    def request(self, method, url, headers=None, follow=None):
        self.methods.append(method)
        q = parse_qs(urlsplit(url).query).get("q", [""])[0]
        body = self.render(q)
        return Response(
            url, self.status(q), self.headers, body.encode(), body, self.truncated
        )


def finding(payload, **kw):
    fields = {
        "id": "f1",
        "vuln_class": "sqli_boolean",
        "target": "https://e.com/s",
        "parameter": "q",
        "payload": payload,
    }
    fields.update(kw)
    return Finding(**fields)


def run(render, payload, **kw):
    engine = FakeEngine(render, **kw)
    result = BooleanSqli().check(finding(payload), Context(engine))
    return result, engine


def test_checker_is_registered():
    assert isinstance(registry.get("sqli_boolean"), BooleanSqli)


def test_flip_numeric_equality():
    assert _flip("OR 1=1") == "OR 1=2"


def test_flip_quoted_equality_with_trailing_quote():
    assert _flip("' OR '1'='1'--") == "' OR '1'='2'--"


def test_flip_quoted_equality_without_trailing_quote():
    assert _flip("' OR '1'='1") == "' OR '1'='2"


def test_flip_true_keyword_case_preserved():
    assert _flip("OR TRUE") == "OR FALSE"
    assert _flip("or true") == "or false"
    assert _flip("Or True") == "Or False"


def test_flip_returns_none_for_unrecognised_payload():
    assert _flip("SLEEP(5)") is None


def test_confirmed_when_conditions_diverge_and_false_matches_baseline():
    def render(q):
        return "<p>rows found: 3</p>" if "'1'='1" in q else "<p>no rows</p>"

    result, engine = run(render, TRUE_PAYLOAD)
    assert result.verdict is Verdict.CONFIRMED
    assert engine.methods == ["GET", "GET", "GET"]
    assert "true vs false" in " ".join(result.evidence)


def test_head_request_is_sent_as_get():
    from urllib.parse import quote

    req = Request("HEAD", f"https://e.com/s?q={quote(TRUE_PAYLOAD, safe='')}")

    def render(q):
        return "<p>rows found: 3</p>" if "'1'='1" in q else "<p>no rows</p>"

    engine = FakeEngine(render)
    f = finding(TRUE_PAYLOAD, request=req)
    result = BooleanSqli().check(f, Context(engine))
    assert engine.methods == ["GET", "GET", "GET"]
    assert result.verdict is Verdict.CONFIRMED


def test_unconfirmed_when_true_and_false_are_identical():
    result, _ = run(lambda q: "<p>same every time</p>", TRUE_PAYLOAD)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "does not appear to control" in result.reason


def test_inconclusive_when_false_does_not_match_baseline():
    def render(q):
        if "'1'='1" in q:
            return "<p>rows found: 3</p>"
        if "'1'='2" in q:
            return "<p>unexpected error near token</p>"
        return "<p>no rows</p>"

    result, _ = run(render, TRUE_PAYLOAD)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "may be error-based" in result.reason


def test_firewall_block_is_inconclusive():
    def blocked(q):
        return 403 if "'1'='1" in q or "'1'='2" in q else 200

    result, _ = run(lambda q: "<p>x</p>", TRUE_PAYLOAD, status=blocked)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "firewall" in result.reason


def test_server_error_is_inconclusive():
    def failing(q):
        return 500 if "'1'='1" in q else 200

    result, _ = run(lambda q: "<p>x</p>", TRUE_PAYLOAD, status=failing)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 500" in result.reason


def test_truncated_response_is_inconclusive():
    result, _ = run(lambda q: "<p>x</p>", TRUE_PAYLOAD, truncated=True)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "size limit" in result.reason


def test_cannot_build_false_twin_is_an_error():
    result, _ = run(lambda q: q, "SLEEP(5)")
    assert result.verdict is Verdict.ERROR
    assert "cannot build a false-condition" in result.reason


def test_empty_payload_is_an_error():
    result, _ = run(lambda q: q, "")
    assert result.verdict is Verdict.ERROR
    assert "no payload" in result.reason


def test_no_parameter_and_payload_not_in_url_raises_baseline_error():
    engine = FakeEngine(lambda q: q)
    f = finding(TRUE_PAYLOAD, parameter="")
    with pytest.raises(BaselineError):
        BooleanSqli().check(f, Context(engine))
