import html
from urllib.parse import parse_qs, urlsplit

import pytest

from debunk.baseline import BaselineError
from debunk.checkers.base import Context, Verdict, registry
from debunk.checkers.xss import ReflectedXss
from debunk.engine import Response
from debunk.schema import Finding, Request

HTML = (("Content-Type", "text/html; charset=utf-8"),)
SCRIPT = "<script>alert(1)</script>"


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
        "vuln_class": "xss_reflected",
        "target": "https://e.com/s",
        "parameter": "q",
        "payload": payload,
    }
    fields.update(kw)
    return Finding(**fields)


def run(render, payload, **kw):
    engine = FakeEngine(render, **kw)
    return ReflectedXss().check(finding(payload), Context(engine)), engine


def test_checker_is_registered():
    assert isinstance(registry.get("xss_reflected"), ReflectedXss)


def test_raw_reflection_creating_a_script_is_confirmed():
    result, engine = run(lambda q: f"<p>{q}</p>", SCRIPT)
    assert result.verdict is Verdict.CONFIRMED
    assert any("<script>" in line for line in result.evidence)
    assert engine.methods == ["GET", "GET"]


def test_head_request_is_sent_as_get():
    req = Request("HEAD", "https://e.com/s?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    engine = FakeEngine(lambda q: f"<p>{q}</p>")
    result = ReflectedXss().check(finding(SCRIPT, request=req), Context(engine))
    assert engine.methods == ["GET", "GET"]
    assert result.verdict is Verdict.CONFIRMED


def test_missing_content_type_is_treated_as_html():
    result, _ = run(lambda q: f"<p>{q}</p>", SCRIPT, headers=())
    assert result.verdict is Verdict.CONFIRMED


def test_attribute_breakout_is_confirmed():
    payload = '" onmouseover="alert(1)'
    result, _ = run(lambda q: f'<input value="{q}">', payload)
    assert result.verdict is Verdict.CONFIRMED
    assert 'onmouseover="alert(1)"' in " ".join(result.evidence)


def test_tag_breakout_with_event_handler_is_confirmed():
    payload = '"><img src=x onerror=alert(1)>'
    result, _ = run(lambda q: f'<div title="{q}">hi</div>', payload)
    assert result.verdict is Verdict.CONFIRMED
    assert "onerror" in " ".join(result.evidence)


def test_javascript_url_is_confirmed():
    result, _ = run(lambda q: f'<a href="{q}">x</a>', "javascript:alert(1)")
    assert result.verdict is Verdict.CONFIRMED
    assert "javascript:alert(1)" in " ".join(result.evidence)


def test_html_encoded_reflection_is_unconfirmed():
    result, _ = run(lambda q: f"<p>{html.escape(q)}</p>", SCRIPT)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "HTML-encoded" in result.reason


def test_not_reflected_is_unconfirmed():
    result, _ = run(lambda q: "<p>nothing</p>", SCRIPT)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "not reflected" in result.reason


def test_payload_already_in_the_page_is_unconfirmed():
    result, _ = run(lambda q: f"<p>{SCRIPT}</p>", SCRIPT)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "already in the page" in result.reason


def test_non_html_response_is_unconfirmed():
    json_type = (("Content-Type", "application/json"),)
    result, _ = run(lambda q: q, SCRIPT, headers=json_type)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "not HTML" in result.reason


@pytest.mark.parametrize(
    "template",
    [
        '<input value="{q}">',
        "<textarea>{q}</textarea>",
        "<!-- {q} -->",
    ],
)
def test_reflection_where_script_cannot_run_is_unconfirmed(template):
    result, _ = run(lambda q: template.format(q=q), SCRIPT)
    assert result.verdict is Verdict.UNCONFIRMED
    assert "will not run" in result.reason


def test_html_injection_without_script_is_unconfirmed():
    page = '<a onclick="go()">x</a><p>{q}</p>'
    result, _ = run(lambda q: page.format(q=q), "<b>hi</b>")
    assert result.verdict is Verdict.UNCONFIRMED


def test_reflection_inside_an_existing_handler_is_not_new():
    result, _ = run(lambda q: f'<a onclick="go(\'{q}\')">x</a>', "<b>hi</b>")
    assert result.verdict is Verdict.UNCONFIRMED


def test_payload_inside_a_script_block_is_inconclusive():
    result, _ = run(lambda q: f'<script>var q="{q}";</script>', '";alert(1);//')
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "<script> block" in result.reason


def test_firewall_block_is_inconclusive():
    result, _ = run(
        lambda q: f"<p>{q}</p>", SCRIPT, status=lambda q: 403 if "<" in q else 200
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "blocked" in result.reason


def test_server_error_is_inconclusive():
    result, _ = run(
        lambda q: f"<p>{q}</p>", SCRIPT, status=lambda q: 500 if "<" in q else 200
    )
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "HTTP 500" in result.reason


def test_rate_limited_control_is_inconclusive():
    result, _ = run(lambda q: q, SCRIPT, status=lambda q: 429)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "control request got HTTP 429" in result.reason


def test_truncated_response_is_inconclusive():
    result, _ = run(lambda q: "<p>x</p>", SCRIPT, truncated=True)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "size limit" in result.reason


def test_strict_csp_downgrades_confirmed_to_inconclusive():
    csp = HTML + (("Content-Security-Policy", "default-src 'self'"),)
    result, _ = run(lambda q: f"<p>{q}</p>", SCRIPT, headers=csp)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "Content-Security-Policy" in result.reason


def test_csp_allowing_inline_script_stays_confirmed():
    csp = HTML + (("Content-Security-Policy", "script-src 'self' 'unsafe-inline'"),)
    result, _ = run(lambda q: f"<p>{q}</p>", SCRIPT, headers=csp)
    assert result.verdict is Verdict.CONFIRMED


def test_empty_payload_is_an_error():
    result, _ = run(lambda q: q, "")
    assert result.verdict is Verdict.ERROR
    assert "no payload" in result.reason


def test_no_parameter_and_payload_not_in_url_raises_baseline_error():
    engine = FakeEngine(lambda q: q)
    with pytest.raises(BaselineError):
        ReflectedXss().check(finding(SCRIPT, parameter=""), Context(engine))
