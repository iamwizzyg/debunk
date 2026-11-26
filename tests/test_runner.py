import pytest

from debunk.baseline import BaselineError
from debunk.checkers.base import (
    Checker,
    Registry,
    Verdict,
    confirmed,
    inconclusive,
    unconfirmed,
)
from debunk.engine import BlockedError, HttpError, ReadOnlyError
from debunk.runner import combine, run_finding
from debunk.schema import Finding

FINDING = Finding(id="f1", vuln_class="xss_reflected", target="https://e.com/s")
C = confirmed("c")
U = unconfirmed("u")


def setup(outcomes):
    reg = Registry()

    @reg.register
    class Scripted(Checker):
        vuln_class = "xss_reflected"

        def __init__(self):
            self.calls = 0

        def check(self, finding, ctx):
            item = outcomes[self.calls]
            self.calls += 1
            if isinstance(item, Exception):
                raise item
            return item

    return reg, reg.get("xss_reflected")


def test_unanimous_confirmed_runs_three_times():
    reg, checker = setup([C, C, C])
    result = run_finding(FINDING, object(), reg=reg)
    assert result.verdict is Verdict.CONFIRMED
    assert result.runs == 3
    assert checker.calls == 3


def test_unanimous_unconfirmed():
    reg, _ = setup([U, U, U])
    assert run_finding(FINDING, object(), reg=reg).verdict is Verdict.UNCONFIRMED


def test_disagreement_is_inconclusive_never_confirmed():
    reg, _ = setup([C, U, C])
    result = run_finding(FINDING, object(), reg=reg)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.runs == 3
    assert "disagreed" in result.reason
    assert "CONFIRMED x2" in result.reason and "UNCONFIRMED x1" in result.reason
    assert len(result.evidence) == 3
    assert result.evidence[0].startswith("run 1: CONFIRMED")


def test_one_network_error_among_verdicts_is_inconclusive():
    reg, _ = setup([HttpError("down"), C, C])
    assert run_finding(FINDING, object(), reg=reg).verdict is Verdict.INCONCLUSIVE


def test_all_network_errors_is_error_and_redacted():
    reg, checker = setup([HttpError("down token=abc")] * 3)
    result = run_finding(FINDING, object(), reg=reg)
    assert result.verdict is Verdict.ERROR
    assert result.reason == "down token=[REDACTED]"
    assert result.runs == 3
    assert checker.calls == 3


@pytest.mark.parametrize(
    "exc",
    [BlockedError("out of scope"), BaselineError("cannot build"), ReadOnlyError("ro")],
)
def test_fatal_errors_stop_at_once(exc):
    reg, checker = setup([exc, C, C])
    result = run_finding(FINDING, object(), reg=reg)
    assert result.verdict is Verdict.ERROR
    assert str(exc) in result.reason
    assert checker.calls == 1


def test_unexpected_exception_becomes_error_without_repeating():
    reg, checker = setup([ValueError("boom"), C, C])
    result = run_finding(FINDING, object(), reg=reg)
    assert result.verdict is Verdict.ERROR
    assert "internal error" in result.reason and "ValueError" in result.reason
    assert checker.calls == 1


def test_missing_checker_is_error():
    result = run_finding(FINDING, object(), reg=Registry())
    assert result.verdict is Verdict.ERROR
    assert "no checker" in result.reason


def test_repeats_can_be_changed_and_never_drop_below_one():
    reg, checker = setup([C, C, C])
    run_finding(FINDING, object(), repeats=1, reg=reg)
    assert checker.calls == 1
    reg, checker = setup([C, C, C])
    run_finding(FINDING, object(), repeats=0, reg=reg)
    assert checker.calls == 1


def test_combine_agreeing_results_keeps_the_first_reason():
    result = combine([inconclusive("x"), inconclusive("y")])
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason == "x"
    assert result.runs == 2
