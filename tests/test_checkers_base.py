import pytest

from debunk.baseline import ProbeRequest
from debunk.checkers.base import (
    Checker,
    Context,
    Registry,
    Verdict,
    confirmed,
    unconfirmed,
)
from debunk.engine import Response


def page(text, url="https://e.com/s"):
    return Response(url, 200, (), text.encode(), text)


class FakeEngine:
    def __init__(self, text=""):
        self.text = text
        self.calls = []

    def request(self, method, url, headers=None, follow=None):
        self.calls.append((method, url, dict(headers or {}), follow))
        return page(self.text, url)


def make_checker(name="xss_reflected"):
    class Dummy(Checker):
        vuln_class = name

        def check(self, finding, ctx):
            return unconfirmed("nothing")

    return Dummy


def test_verdict_values():
    assert [v.value for v in Verdict] == [
        "CONFIRMED",
        "UNCONFIRMED",
        "INCONCLUSIVE",
        "ERROR",
    ]


def test_result_helpers_redact_and_truncate():
    result = confirmed("saw token=abc123", "x" * 500, "Cookie: a=b")
    assert result.verdict is Verdict.CONFIRMED
    assert result.reason == "saw token=[REDACTED]"
    assert len(result.evidence[0]) == 300
    assert result.evidence[1] == "Cookie: [REDACTED]"


def test_registry_register_get_names():
    reg = Registry()
    reg.register(make_checker("idor"))
    reg.register(make_checker("auth_bypass"))
    assert reg.get("idor").vuln_class == "idor"
    assert reg.get("sqli_boolean") is None
    assert reg.names() == ("auth_bypass", "idor")


def test_registry_rejects_duplicates():
    reg = Registry()
    reg.register(make_checker())
    with pytest.raises(ValueError, match="already registered"):
        reg.register(make_checker())


def test_registry_rejects_unknown_class():
    with pytest.raises(ValueError, match="unknown vulnerability class"):
        Registry().register(make_checker("rce"))


def test_checker_base_class_is_abstract():
    with pytest.raises(TypeError):
        Checker()


def test_send_refreshes_csrf_token_before_replay():
    engine = FakeEngine('<input name="csrf_token" value="fresh">')
    ctx = Context(engine, token_url="https://e.com/form")
    probe = ProbeRequest(
        "GET", "https://e.com/s?csrf_token=old&q=1", {"Cookie": "a=b"}
    )
    ctx.send(probe)
    assert engine.calls[0] == ("GET", "https://e.com/form", {"Cookie": "a=b"}, None)
    assert engine.calls[1][1] == "https://e.com/s?csrf_token=fresh&q=1"
    assert len(engine.calls) == 2


def test_send_makes_one_request_when_nothing_to_refresh():
    engine = FakeEngine()
    Context(engine, token_url="https://e.com/form").send(
        ProbeRequest("GET", "https://e.com/s?q=1")
    )
    assert len(engine.calls) == 1


def test_send_does_not_refresh_when_disabled():
    engine = FakeEngine('<input name="csrf_token" value="fresh">')
    ctx = Context(engine, token_url="https://e.com/form", refresh_tokens=False)
    ctx.send(ProbeRequest("GET", "https://e.com/s?csrf_token=old"))
    assert [c[1] for c in engine.calls] == ["https://e.com/s?csrf_token=old"]


def test_send_does_not_refresh_without_a_token_url():
    engine = FakeEngine('<input name="csrf_token" value="fresh">')
    Context(engine).send(ProbeRequest("GET", "https://e.com/s?csrf_token=old"))
    assert len(engine.calls) == 1


def test_send_keeps_request_when_page_has_no_tokens():
    engine = FakeEngine("<p>none</p>")
    ctx = Context(engine, token_url="https://e.com/form")
    ctx.send(ProbeRequest("GET", "https://e.com/s?csrf_token=old"))
    assert len(engine.calls) == 2
    assert engine.calls[1][1] == "https://e.com/s?csrf_token=old"


def test_send_passes_follow_through():
    engine = FakeEngine()
    Context(engine).send(ProbeRequest("GET", "https://e.com/s"), follow=False)
    assert engine.calls[-1][3] is False
