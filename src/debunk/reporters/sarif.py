"""SARIF 2.1.0 reporter, for --sarif output consumed by GitHub code scanning.

One SARIF log with one run. Each FindingReport becomes one SARIF "result":
  - ruleId is the vulnerability class, or "debunk/load-error" for a finding
    that failed to load (see classifier.FindingReport.from_load_error).
  - level maps the verdict: CONFIRMED -> error, INCONCLUSIVE -> warning,
    UNCONFIRMED -> note, ERROR -> none.
  - the physicalLocation uri is the finding's target URL. SARIF accepts any
    URI reference here, not only repo-relative file paths; GitHub code
    scanning may not render a clickable source line for it, since debunk
    tests live URLs rather than source files, but the SARIF stays valid.
Evidence lines are carried in result.properties.evidence rather than in
the message, so the message stays a short, single-line summary.
"""

from __future__ import annotations

import json

from debunk import __version__
from debunk.checkers.base import Verdict
from debunk.classifier import Report
from debunk.reporters.base import Reporter, register
from debunk.schema import VULN_CLASSES

SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/"
    "sarif-schema-2.1.0.json"
)

LOAD_ERROR_RULE = "debunk/load-error"

_RULE_DESCRIPTIONS = {
    "xss_reflected": "Reflected cross-site scripting (XSS)",
    "sqli_boolean": "Boolean-based SQL injection",
    "open_redirect": "Open redirect",
    "idor": "Insecure direct object reference (IDOR)",
    "auth_bypass": "Authentication or authorization bypass",
    "file_exposure": "Sensitive file exposure",
}

_LEVEL = {
    Verdict.CONFIRMED: "error",
    Verdict.INCONCLUSIVE: "warning",
    Verdict.UNCONFIRMED: "note",
    Verdict.ERROR: "none",
}


def _rules() -> list[dict]:
    rules = [
        {
            "id": name,
            "name": name,
            "shortDescription": {"text": _RULE_DESCRIPTIONS[name]},
        }
        for name in VULN_CLASSES
    ]
    rules.append(
        {
            "id": LOAD_ERROR_RULE,
            "name": "load-error",
            "shortDescription": {
                "text": "A finding in the input file could not be loaded"
            },
        }
    )
    return rules


def _result(finding) -> dict:
    rule_id = finding.vuln_class or LOAD_ERROR_RULE
    result = {
        "ruleId": rule_id,
        "level": _LEVEL[finding.verdict],
        "message": {"text": finding.reason},
        "properties": {
            "debunkVerdict": finding.verdict.value,
            "debunkFindingId": finding.id,
            "debunkRuns": finding.runs,
            "evidence": list(finding.evidence),
        },
    }
    if finding.target:
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": finding.target}}}
        ]
    return result


@register
class SarifReporter(Reporter):
    name = "sarif"

    def render(self, report: Report, quiet: bool = False) -> str:
        log = {
            "$schema": SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "debunk",
                            "version": __version__,
                            "informationUri": "https://github.com/iamwizzyg/debunk",
                            "rules": _rules(),
                        }
                    },
                    "results": [_result(f) for f in report.all],
                }
            ],
        }
        return json.dumps(log, indent=2) + "\n"
