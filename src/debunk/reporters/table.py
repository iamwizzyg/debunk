"""Human-readable table reporter: debunk's default output.

Theme: plain 16-colour ANSI only, honours NO_COLOR, and never signals a
verdict by colour alone -- every row carries an ASCII symbol and a word.
One row per finding, wrapped to 80 columns; -q prints only the summary.
"""

from __future__ import annotations

import os
import sys
import textwrap
from urllib.parse import urlsplit

from debunk.checkers.base import Verdict
from debunk.classifier import Report
from debunk.reporters.base import Reporter, register

WIDTH = 80

_STYLE: dict[Verdict, tuple[str, str]] = {
    Verdict.CONFIRMED: ("[+]", "31"),  # red: needs attention
    Verdict.UNCONFIRMED: ("[-]", "32"),  # green: nothing found
    Verdict.INCONCLUSIVE: ("[?]", "33"),  # yellow: needs a human
    Verdict.ERROR: ("[!]", "35"),  # magenta: debunk itself had trouble
}
_RESET = "\033[0m"


def _use_color(color: bool | None) -> bool:
    if color is not None:
        return color
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}{_RESET}" if color else text


def _host_and_path(target: str) -> str:
    if not target:
        return "(no target: finding failed to load)"
    parts = urlsplit(target)
    return f"{parts.hostname or target}{parts.path or '/'}"


def _row(finding, color: bool) -> str:
    symbol, code = _STYLE[finding.verdict]
    head = _paint(f"{symbol} {finding.verdict.value}", code, color)
    where = _host_and_path(finding.target)
    label = f"{finding.vuln_class or '?'}  {where}" if finding.vuln_class else where
    prefix = f"{head}  {label}  "
    plain_prefix = f"{symbol} {finding.verdict.value}  {label}  "
    indent = " " * len(plain_prefix)
    wrapped = textwrap.wrap(
        finding.reason,
        width=max(WIDTH - len(indent), 20),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    lines = [prefix + wrapped[0]]
    lines.extend(indent + line for line in wrapped[1:])
    return "\n".join(lines)


def _summary(report: Report, color: bool) -> str:
    total = len(report.all)
    lead = f"{total} finding(s) -- "
    plain_parts = [f"{_STYLE[v][0]} {v.value}: {report.count(v)}" for v in Verdict]
    wrapped = textwrap.wrap(
        ", ".join(plain_parts),
        width=max(WIDTH - len(lead), 20),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]
    if color:
        for v in Verdict:
            plain_label = f"{_STYLE[v][0]} {v.value}: {report.count(v)}"
            colored_label = _paint(plain_label, _STYLE[v][1], True)
            wrapped = [line.replace(plain_label, colored_label) for line in wrapped]
    indent = " " * len(lead)
    return lead + ("\n" + indent).join(wrapped)



@register
class TableReporter(Reporter):
    name = "table"

    def render(
        self, report: Report, quiet: bool = False, color: bool | None = None
    ) -> str:
        use_color = _use_color(color)
        lines: list[str] = []
        if not quiet:
            lines.extend(_row(finding, use_color) for finding in report.all)
            if report.all:
                lines.append("")
        lines.append(_summary(report, use_color))
        return "\n".join(lines)
