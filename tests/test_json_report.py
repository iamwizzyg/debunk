import json

from debunk.checkers.base import Verdict
from debunk.classifier import FindingReport, Report
from debunk.reporters.base import registry
from debunk.reporters.json_report import JsonReporter


def finding(**kw):
    base = {
        "id": "f1",
        "vuln_class": "xss_reflected",
        "target": "https://example.com/search",
        "verdict": Verdict.CONFIRMED,
        "reason": "payload reflected unencoded",
        "evidence": ("new <script> element",),
        "runs": 3,
    }
    base.update(kw)
    return FindingReport(**base)


def test_reporter_is_registered():
    assert isinstance(registry.get("json"), JsonReporter)


def test_full_report_round_trips_through_json():
    report = Report((finding(),))
    out = JsonReporter().render(report)
    data = json.loads(out)
    assert data["findings"][0] == {
        "id": "f1",
        "class": "xss_reflected",
        "target": "https://example.com/search",
        "verdict": "CONFIRMED",
        "reason": "payload reflected unencoded",
        "evidence": ["new <script> element"],
        "runs": 3,
    }


def test_unparsed_finding_has_null_class_and_target():
    err_finding = FindingReport(
        id="bad1",
        vuln_class="",
        target="",
        verdict=Verdict.ERROR,
        reason="could not load finding: unknown class",
    )
    data = json.loads(JsonReporter().render(Report((), (err_finding,))))
    assert data["findings"][0]["class"] is None
    assert data["findings"][0]["target"] is None
    assert data["findings"][0]["evidence"] == []
    assert data["findings"][0]["runs"] == 1


def test_summary_has_counts_total_and_exit_code():
    report = Report(
        (finding(), finding(id="f2", verdict=Verdict.UNCONFIRMED))
    )
    data = json.loads(JsonReporter().render(report))
    assert data["summary"] == {
        "total": 2,
        "CONFIRMED": 1,
        "UNCONFIRMED": 1,
        "INCONCLUSIVE": 0,
        "ERROR": 0,
        "exit_code": 2,
    }


def test_quiet_mode_omits_findings_but_keeps_summary():
    report = Report((finding(),))
    data = json.loads(JsonReporter().render(report, quiet=True))
    assert "findings" not in data
    assert data["summary"]["total"] == 1


def test_empty_report():
    data = json.loads(JsonReporter().render(Report(())))
    assert data["findings"] == []
    assert data["summary"] == {
        "total": 0,
        "CONFIRMED": 0,
        "UNCONFIRMED": 0,
        "INCONCLUSIVE": 0,
        "ERROR": 0,
        "exit_code": 0,
    }


def test_verdicts_serialize_as_plain_strings_not_enum_repr():
    out = JsonReporter().render(Report((finding(),)))
    assert "Verdict." not in out
    assert '"verdict": "CONFIRMED"' in out


def test_reason_and_evidence_pass_through_unchanged():
    # Redaction already happened upstream (checkers/base.py); this reporter
    # must not alter the text further.
    f = finding(reason="token=[REDACTED] seen", evidence=("x" * 300,))
    data = json.loads(JsonReporter().render(Report((f,))))
    assert data["findings"][0]["reason"] == "token=[REDACTED] seen"
    assert data["findings"][0]["evidence"][0] == "x" * 300


def test_output_ends_with_a_single_trailing_newline():
    out = JsonReporter().render(Report(()))
    assert out.endswith("\n")
    assert not out.endswith("\n\n")
