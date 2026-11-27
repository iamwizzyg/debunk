"""Machine-readable JSON reporter.

One JSON object: {"findings": [...], "summary": {...}}. Each finding is
{id, class, target, verdict, reason, evidence, runs}. quiet=True omits
"findings" and keeps only "summary", matching the table reporter's -q
behaviour. Secrets are already redacted by the time a Result reaches this
reporter (see checkers/base.py); this reporter does not redact again.
"""

from __future__ import annotations

import json

from debunk.classifier import Report
from debunk.reporters.base import Reporter, register


def _finding_dict(finding) -> dict:
    return {
        "id": finding.id,
        "class": finding.vuln_class or None,
        "target": finding.target or None,
        "verdict": finding.verdict.value,
        "reason": finding.reason,
        "evidence": list(finding.evidence),
        "runs": finding.runs,
    }


@register
class JsonReporter(Reporter):
    name = "json"

    def render(self, report: Report, quiet: bool = False) -> str:
        from debunk.checkers.base import Verdict

        summary = {
            "total": len(report.all),
            **{v.value: report.count(v) for v in Verdict},
            "exit_code": report.exit_code,
        }
        data: dict = {"summary": summary}
        if not quiet:
            data["findings"] = [_finding_dict(f) for f in report.all]
        return json.dumps(data, indent=2, sort_keys=False) + "\n"
