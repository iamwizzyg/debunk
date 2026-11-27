from debunk.baseline import ProbeRequest
from debunk.checkers.base import (
    Checker,
    Registry,
    Verdict,
    confirmed,
    unconfirmed,
)
from debunk.classifier import (
    CloudflareChallengeError,
    FindingReport,
    Report,
    _ChallengeDetectingEngine,
    classify_run,
    is_cloudflare_challenge,
)
from debunk.engine import Response
from debunk.schema import Finding, FindingError

HTML = (("Content-Type", "text/html; charset=utf-8"),)


def resp(status=200, body="", headers=HTML, url="https://e.com/"):
    return Response(url, status, headers, body.encode(), body, truncated=False)


def test_cloudflare_mitigated_header_with_403_is_flagged():
    r = resp(403, "<p>blocked</p>", (("cf-mitigated", "dynamic"),))
    assert is_cloudflare_challenge(r)


def test_cloudflare_body_markers_with_503_are_flagged():
    r = resp(503, "<title>Just a moment...</title>")
    assert is_cloudflare_challenge(r)
    r2 = resp(403, '<div class="cf-chl-widget">x</div>')
    assert is_cloudflare_challenge(r2)


def test_plain_server_error_is_not_flagged():
    r = resp(503, "<p>Service temporarily unavailable</p>")
    assert not is_cloudflare_challenge(r)


def test_normal_cloudflare_fronted_page_is_not_flagged():
    r = resp(200, "<p>hello</p>", (("cf-ray", "abc123"),))
    assert not is_cloudflare_challenge(r)


class FakeInner:
    def __init__(self, respond):
        self.respond = respond
        self.calls = 0

    def request(self, method, url, headers=None, follow=None):
        self.calls += 1
        return self.respond(url)


def test_wrapper_raises_on_a_challenge_page():
    import pytest

    inner = FakeInner(lambda url: resp(503, "Just a moment...", url=url))
    wrapped = _ChallengeDetectingEngine(inner)
    with pytest.raises(CloudflareChallengeError) as excinfo:
        wrapped.request("GET", "https://e.com/x")
    assert "Cloudflare challenge page" in str(excinfo.value)
    assert "https://e.com/x" in str(excinfo.value)


def test_wrapper_passes_through_normal_responses():
    normal = resp(200, "<p>hi</p>")
    inner = FakeInner(lambda url: normal)
    wrapped = _ChallengeDetectingEngine(inner)
    assert wrapped.request("GET", "https://e.com/x") == normal
    assert inner.calls == 1


def test_finding_report_from_result():
    f = Finding(id="f1", vuln_class="xss_reflected", target="https://e.com/s")
    result = confirmed("reason here", "evidence 1")
    report = FindingReport.from_result(f, result)
    assert report.id == "f1"
    assert report.vuln_class == "xss_reflected"
    assert report.target == "https://e.com/s"
    assert report.verdict is Verdict.CONFIRMED
    assert report.evidence == ("evidence 1",)


def test_finding_report_from_load_error():
    err = FindingError(index=3, finding_id="bad1", message="unknown class 'rce'")
    report = FindingReport.from_load_error(err)
    assert report.id == "bad1"
    assert report.verdict is Verdict.ERROR
    assert "unknown class 'rce'" in report.reason


def test_report_exit_code_prefers_confirmed_over_unconfirmed():
    confirmed_r = FindingReport("a", "xss_reflected", "t", Verdict.CONFIRMED, "x")
    unconfirmed_r = FindingReport("b", "xss_reflected", "t", Verdict.UNCONFIRMED, "x")
    assert Report((confirmed_r, unconfirmed_r)).exit_code == 2


def test_report_exit_code_unconfirmed_only():
    r = FindingReport("a", "xss_reflected", "t", Verdict.UNCONFIRMED, "x")
    assert Report((r,)).exit_code == 1


def test_report_exit_code_clean_with_inconclusive_and_errors():
    a = FindingReport("a", "xss_reflected", "t", Verdict.INCONCLUSIVE, "x")
    b = FindingReport("b", "xss_reflected", "t", Verdict.ERROR, "x")
    assert Report((a, b)).exit_code == 0
    assert Report(()).exit_code == 0


def test_report_counts_and_all_includes_unparsed():
    good = FindingReport("a", "xss_reflected", "t", Verdict.CONFIRMED, "x")
    bad = FindingReport.from_load_error(
        FindingError(index=1, finding_id="b", message="bad")
    )
    report = Report((good,), (bad,))
    assert report.confirmed == 1
    assert report.errors == 1
    assert len(report.all) == 2
    assert report.exit_code == 2


def make_registry(responder):
    reg = Registry()

    @reg.register
    class Dummy(Checker):
        vuln_class = "xss_reflected"

        def check(self, finding, ctx):
            r = ctx.send(ProbeRequest("GET", finding.target))
            return confirmed("saw it") if "ok" in r.text else unconfirmed("not seen")

    return reg


def test_classify_run_end_to_end_with_scripted_checker():
    f1 = Finding(id="a", vuln_class="xss_reflected", target="https://e.com/ok")
    f2 = Finding(id="b", vuln_class="xss_reflected", target="https://e.com/no")
    reg = make_registry(None)

    def respond(url):
        return resp(200, "ok" if "ok" in url else "nothing")

    engine = FakeInner(respond)
    load_errors = [FindingError(index=1, finding_id="c", message="bad class")]
    report = classify_run([f1, f2], engine, load_errors=load_errors, reg=reg)

    by_id = {r.id: r.verdict for r in report.findings}
    assert by_id == {"a": Verdict.CONFIRMED, "b": Verdict.UNCONFIRMED}
    assert len(report.unparsed) == 1
    assert report.unparsed[0].id == "c"
    assert report.exit_code == 2


def test_classify_run_marks_persistent_challenge_as_error():
    f = Finding(id="a", vuln_class="xss_reflected", target="https://e.com/s")
    reg = make_registry(None)
    engine = FakeInner(lambda url: resp(503, "Just a moment..."))
    report = classify_run([f], engine, reg=reg)
    assert report.findings[0].verdict is Verdict.ERROR
    assert "Cloudflare challenge page" in report.findings[0].reason


def test_classify_run_can_disable_cloudflare_detection():
    f = Finding(id="a", vuln_class="xss_reflected", target="https://e.com/s")
    reg = make_registry(None)
    engine = FakeInner(lambda url: resp(503, "Just a moment..."))
    report = classify_run([f], engine, reg=reg, detect_cloudflare=False)
    # Without detection, the checker just sees a normal 503 body as text.
    assert report.findings[0].verdict is Verdict.UNCONFIRMED
