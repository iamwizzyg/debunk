"""Boolean-based SQL injection checker.

Builds a "false" twin of the agent's payload by flipping a boolean
comparison it contains (1=1 -> 1=2, '1'='1' -> '1'='2', TRUE -> FALSE),
then compares three responses: the original payload (the claimed "true"
condition), the false twin, and a harmless control value. CONFIRMED needs
the true and false responses to differ AND the false response to match the
normal baseline, which shows the parameter really toggles the query's
logic rather than just reacting to odd input.
"""

from __future__ import annotations

import re
from dataclasses import replace

from debunk.baseline import CONTROL_VALUE, control_request, replay_request
from debunk.checkers.base import (
    Checker,
    Context,
    Result,
    confirmed,
    error,
    inconclusive,
    register,
    unconfirmed,
)
from debunk.differ import compare, same_page
from debunk.engine import Response
from debunk.schema import Finding

_QUOTE_EQ = re.compile(r"(['\"])(\w+)\1\s*=\s*\1\2(\1)?")
_NUM_EQ = re.compile(r"\b(\d+)(\s*=\s*)\1\b")
_BOOL_TRUE = re.compile(r"\btrue\b", re.I)

_DB_ERRORS = (
    re.compile(r"sql syntax.{0,40}mysql", re.I),
    re.compile(r"warning:\s*mysql_", re.I),
    re.compile(r"valid mysql result", re.I),
    re.compile(r"postgresql.{0,20}error", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"sqlite_error", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"SQLSTATE\[\d+\]", re.I),
    re.compile(r"odbc sql server driver", re.I),
)


def _other(word: str) -> str:
    if word.isdigit():
        return str(int(word) + 1)
    return word + "_"


def _flip(payload: str) -> str | None:
    """Build a "false" twin of a boolean SQLi payload, or None if the
    payload has no boolean comparison this checker recognises. Only the
    first recognised pattern is flipped."""

    def quote_sub(match: re.Match) -> str:
        quote = match.group(1)
        word = match.group(2)
        trailing = match.group(3) or ""
        return f"{quote}{word}{quote}={quote}{_other(word)}{trailing}"

    new, count = _QUOTE_EQ.subn(quote_sub, payload, count=1)
    if count:
        return new

    def num_sub(match: re.Match) -> str:
        return f"{match.group(1)}{match.group(2)}{_other(match.group(1))}"

    new, count = _NUM_EQ.subn(num_sub, payload, count=1)
    if count:
        return new

    def bool_sub(match: re.Match) -> str:
        word = match.group(0)
        if word.isupper():
            return "FALSE"
        if word.istitle():
            return "False"
        return "false"

    new, count = _BOOL_TRUE.subn(bool_sub, payload, count=1)
    return new if count else None


def _db_error(text: str) -> str | None:
    for pattern in _DB_ERRORS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def _error_evidence(
    control: Response, true_resp: Response, false_resp: Response
) -> list[str]:
    baseline_err = _db_error(control.text)
    lines = []
    labelled = (("true-condition", true_resp), ("false-condition", false_resp))
    for label, resp in labelled:
        err = _db_error(resp.text)
        if err and err != baseline_err:
            lines.append(f"{label} response contains a database error: {err!r}")
    return lines


def _server_problem(
    control: Response, true_resp: Response, false_resp: Response
) -> Result | None:
    responses = (
        ("control", control),
        ("true-condition", true_resp),
        ("false-condition", false_resp),
    )
    for label, resp in responses:
        if resp.status == 429 or resp.status >= 500:
            return inconclusive(
                f"{label} request got HTTP {resp.status}: "
                "server unavailable or rate limiting"
            )
    blocked = [label for label, resp in responses[1:] if resp.status in (403, 406)]
    if blocked and control.status < 400:
        return inconclusive(
            f"{' and '.join(blocked)} request was blocked but the control "
            "was not; a firewall may be filtering the payload"
        )
    return None


@register
class BooleanSqli(Checker):
    vuln_class = "sqli_boolean"

    def check(self, finding: Finding, ctx: Context) -> Result:
        payload = finding.payload
        if not payload:
            return error("finding has no payload to replay")
        false_payload = _flip(payload)
        if false_payload is None:
            return error(
                "cannot build a false-condition variant of this payload: "
                "no recognised boolean pattern (such as 1=1 or '1'='1')"
            )
        control_probe = replace(control_request(finding), method="GET")
        true_probe = replace(replay_request(finding), method="GET")
        false_probe = replace(control_request(finding, false_payload), method="GET")
        control_resp = ctx.send(control_probe)
        true_resp = ctx.send(true_probe)
        false_resp = ctx.send(false_probe)

        problem = _server_problem(control_resp, true_resp, false_resp)
        if problem is not None:
            return problem
        if any(r.truncated for r in (control_resp, true_resp, false_resp)):
            return inconclusive(
                "a response was cut at the size limit before comparison "
                "was possible"
            )

        diff_tf = compare(true_resp, false_resp, payload, false_payload)
        extra = _error_evidence(control_resp, true_resp, false_resp)
        if same_page(diff_tf):
            return unconfirmed(
                "the true and false conditions produced the same "
                "response; this parameter does not appear to control "
                "query logic",
                diff_tf.summary(),
            )
        diff_fc = compare(control_resp, false_resp, CONTROL_VALUE, false_payload)
        if same_page(diff_fc):
            return confirmed(
                "the true and false conditions toggle the response, and "
                "the false condition matches the normal baseline",
                f"true vs false: {diff_tf.summary()}",
                f"false vs baseline: {diff_fc.summary()}",
                *extra,
            )
        return inconclusive(
            "the true and false conditions differ, but the false "
            "condition does not match the baseline either; this may be "
            "error-based SQLi or unrelated input handling rather than "
            "boolean logic",
            f"true vs false: {diff_tf.summary()}",
            f"false vs baseline: {diff_fc.summary()}",
            *extra,
        )
