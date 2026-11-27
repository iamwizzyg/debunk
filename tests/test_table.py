import re

from debunk.checkers.base import Verdict
from debunk.classifier import FindingReport, Report
from debunk.reporters.base import registry
from debunk.reporters.table import TableReporter, _host_and_path, _summary

ANSI = re.compile(r"\033\[[0-9;]*m")


def finding(**kw):
    base = {
        "id": "f1",
        "vuln_class": "xss_reflected",
        "target": "https://example.com/search",
        "verdict": Verdict.CONFIRMED,
        "reason": "short reason",
    }
    base.update(kw)
    return FindingReport(**base)


def test_reporter_is_registered():
    assert isinstance(registry.get("table"), TableReporter)


def test_color_forced_on_includes_ansi_codes():
    report = Report((finding(),))
    out = TableReporter().render(report, color=True)
    assert "\033[" in out
    assert "CONFIRMED" in out


def test_color_forced_off_has_no_ansi_codes():
    report = Report((finding(),))
    out = TableReporter().render(report, color=False)
    assert "\033[" not in out


def test_no_color_env_var_suppresses_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    report = Report((finding(),))
    out = TableReporter().render(report, color=None)
    assert "\033[" not in out


def test_every_verdict_has_a_symbol_and_a_word():
    cases = [
        (Verdict.CONFIRMED, "[+]"),
        (Verdict.UNCONFIRMED, "[-]"),
        (Verdict.INCONCLUSIVE, "[?]"),
        (Verdict.ERROR, "[!]"),
    ]
    for verdict, symbol in cases:
        report = Report((finding(verdict=verdict, reason="x"),))
        out = TableReporter().render(report, color=False)
        assert f"{symbol} {verdict.value}" in out


def test_host_and_path_formatting():
    assert _host_and_path("https://e.com/a/b?q=1") == "e.com/a/b"
    assert _host_and_path("https://e.com") == "e.com/"
    assert _host_and_path("") == "(no target: finding failed to load)"


def test_row_shows_class_and_host_path():
    report = Report((finding(target="https://e.com/search?q=1"),))
    out = TableReporter().render(report, color=False)
    assert "xss_reflected  e.com/search" in out


def test_unparsed_finding_has_no_class_or_target():
    err_finding = FindingReport(
        id="bad1",
        vuln_class="",
        target="",
        verdict=Verdict.ERROR,
        reason="could not load finding: unknown class",
    )
    report = Report((), (err_finding,))
    out = TableReporter().render(report, color=False)
    assert "(no target: finding failed to load)" in out
    assert "  e.com" not in out


def test_long_reason_wraps_within_80_columns_and_indents_continuation():
    long_reason = " ".join(["word"] * 30)
    report = Report((finding(reason=long_reason),))
    out = TableReporter().render(report, color=False)
    lines = out.splitlines()
    for line in lines:
        assert len(line) <= 80
    assert any(line.startswith(" ") and "word" in line for line in lines)


def test_quiet_mode_only_prints_the_summary():
    report = Report((finding(), finding(id="f2", verdict=Verdict.UNCONFIRMED)))
    out = TableReporter().render(report, quiet=True, color=False)
    assert "xss_reflected" not in out
    assert "2 finding(s)" in out
    assert "CONFIRMED: 1" in out
    assert "UNCONFIRMED: 1" in out


def test_summary_line_always_present_with_all_four_counts():
    report = Report(())
    out = TableReporter().render(report, color=False)
    assert "0 finding(s)" in out
    for verdict in Verdict:
        assert f"{verdict.value}: 0" in out


def test_empty_report_has_no_finding_rows():
    report = Report(())
    out = TableReporter().render(report, color=False)
    # With no findings, the rendered output is exactly the summary (which
    # may itself wrap across lines) -- there are no per-finding rows above it.
    assert out == _summary(report, color=False)
