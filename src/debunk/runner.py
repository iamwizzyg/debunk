"""Run one finding through its checker, repeating to catch flaky results.

Rule: all repeats must agree. Any disagreement (including an error mixed with
a verdict) becomes INCONCLUSIVE, so a flaky result is never CONFIRMED.
Failures that repeating cannot fix (out of scope, no control request, a bug
in a checker) stop at once with ERROR.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace

from debunk.baseline import BaselineError
from debunk.checkers.base import (
    Context,
    Registry,
    Result,
    Verdict,
    error,
    make_result,
    registry,
)
from debunk.engine import BlockedError, Engine, HttpError, ReadOnlyError
from debunk.schema import Finding

DEFAULT_REPEATS = 3


def combine(results: list[Result]) -> Result:
    """Merge repeated results into one."""
    runs = len(results)
    counts = Counter(r.verdict for r in results)
    if len(counts) == 1:
        return replace(results[0], runs=runs)
    parts = ", ".join(
        f"{verdict.value} x{n}"
        for verdict, n in sorted(counts.items(), key=lambda item: item[0].value)
    )
    lines = [
        f"run {i}: {r.verdict.value}: {r.reason}" for i, r in enumerate(results, 1)
    ]
    merged = make_result(Verdict.INCONCLUSIVE, f"runs disagreed ({parts})", lines)
    return replace(merged, runs=runs)


def run_finding(
    finding: Finding,
    engine: Engine,
    repeats: int = DEFAULT_REPEATS,
    reg: Registry | None = None,
) -> Result:
    """Check one finding `repeats` times and return the combined result."""
    reg = registry if reg is None else reg
    checker = reg.get(finding.vuln_class)
    if checker is None:
        return error(f"no checker registered for class {finding.vuln_class}")
    results: list[Result] = []
    for _ in range(max(1, repeats)):
        ctx = Context(engine, token_url=finding.target)
        try:
            results.append(checker.check(finding, ctx))
        except (BlockedError, BaselineError, ReadOnlyError) as exc:
            return error(str(exc))
        except HttpError as exc:
            results.append(error(str(exc)))
        except Exception as exc:
            kind = type(exc).__name__
            where = f"{finding.vuln_class} checker"
            return error(f"internal error in {where}: {kind}: {exc}")
    return combine(results)
