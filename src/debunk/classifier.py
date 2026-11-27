"""Classifies a full run of findings into one Report.

Builds on runner.run_finding (step 8), which already checks one finding
and repeats it. This module adds the layer above that: turning every
loaded finding, plus every finding that failed to *load* in the first
place (schema.FindingError / adapter errors), into one Report with
per-verdict counts and an exit code.

It also wraps the Engine each checker uses so a Cloudflare interstitial
(a JS challenge page, not the real target) is recognised rather than
treated as ordinary content. A caught challenge raises an HttpError
subclass, so it flows through the existing per-run retry logic from
step 8 unchanged: a site that serves the challenge on every repeat ends
up ERROR with a clear reason, the same bucket as any other network
failure -- not a new verdict.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from debunk.checkers.base import Registry, Verdict
from debunk.engine import Engine, HttpError, Response
from debunk.runner import DEFAULT_REPEATS, run_finding
from debunk.schema import Finding, FindingError

_CF_MITIGATED_HEADER = "cf-mitigated"
_CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser before accessing",
    "cdn-cgi/challenge-platform",
    "cf-chl-widget",
)


class CloudflareChallengeError(HttpError):
    """A response was a Cloudflare interstitial challenge page, not the
    real target content."""


def is_cloudflare_challenge(resp: Response) -> bool:
    """Best-effort detection of a Cloudflare JS challenge page. Limited to
    the English-language challenge text; other languages or other
    anti-bot vendors (Akamai, Incapsula...) are not recognised."""
    if resp.status not in (403, 503):
        return False
    if resp.header(_CF_MITIGATED_HEADER) is not None:
        return True
    text = resp.text.lower()
    return any(marker in text for marker in _CHALLENGE_MARKERS)


class _ChallengeDetectingEngine:
    """Wraps an Engine so a Cloudflare challenge page raises instead of
    being handed to a checker as if it were the real page."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def request(
        self, method: str, url: str, headers=None, follow: bool | None = None
    ) -> Response:
        resp = self._engine.request(method, url, headers, follow)
        if is_cloudflare_challenge(resp):
            raise CloudflareChallengeError(
                f"{resp.safe_url()} served a Cloudflare challenge page "
                f"(HTTP {resp.status}) instead of the real content"
            )
        return resp


@dataclass(frozen=True)
class FindingReport:
    id: str
    vuln_class: str
    target: str
    verdict: Verdict
    reason: str
    evidence: tuple[str, ...] = ()
    runs: int = 1

    @classmethod
    def from_result(cls, finding: Finding, result) -> FindingReport:
        return cls(
            finding.id,
            finding.vuln_class,
            finding.target,
            result.verdict,
            result.reason,
            result.evidence,
            result.runs,
        )

    @classmethod
    def from_load_error(cls, err: FindingError) -> FindingReport:
        return cls(
            id=err.finding_id,
            vuln_class="",
            target="",
            verdict=Verdict.ERROR,
            reason=f"could not load finding: {err.message}",
        )


@dataclass(frozen=True)
class Report:
    findings: tuple[FindingReport, ...]
    unparsed: tuple[FindingReport, ...] = ()

    @property
    def all(self) -> tuple[FindingReport, ...]:
        return self.findings + self.unparsed

    def count(self, verdict: Verdict) -> int:
        return sum(1 for f in self.all if f.verdict is verdict)

    @property
    def confirmed(self) -> int:
        return self.count(Verdict.CONFIRMED)

    @property
    def unconfirmed(self) -> int:
        return self.count(Verdict.UNCONFIRMED)

    @property
    def inconclusive(self) -> int:
        return self.count(Verdict.INCONCLUSIVE)

    @property
    def errors(self) -> int:
        return self.count(Verdict.ERROR)

    @property
    def exit_code(self) -> int:
        """0 clean, 1 only unconfirmed, 2 any confirmed. (Exit code 3,
        for a runtime crash rather than a run's results, is the CLI's
        concern in step 21, not this report.)"""
        if self.confirmed:
            return 2
        if self.unconfirmed:
            return 1
        return 0


def classify_run(
    findings: Iterable[Finding],
    engine: Engine,
    load_errors: Iterable[FindingError] = (),
    repeats: int = DEFAULT_REPEATS,
    reg: Registry | None = None,
    detect_cloudflare: bool = True,
) -> Report:
    """Check every finding and build the run's Report."""
    checking_engine = _ChallengeDetectingEngine(engine) if detect_cloudflare else engine
    reports = tuple(
        FindingReport.from_result(
            finding, run_finding(finding, checking_engine, repeats, reg)
        )
        for finding in findings
    )
    unparsed = tuple(FindingReport.from_load_error(err) for err in load_errors)
    return Report(reports, unparsed)
