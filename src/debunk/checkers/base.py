"""Checker interface, verdicts and the checker registry.

Every vulnerability class gets one Checker. A checker looks at one finding,
sends its own requests through the Context, and returns a Result. The runner
(runner.py) repeats each check and combines the repeats.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from debunk.baseline import ProbeRequest
from debunk.csrf import find_tokens, needs_refresh, refresh_probe
from debunk.engine import Engine, Response
from debunk.redact import redact_text
from debunk.schema import VULN_CLASSES, Finding

_MAX_LINE = 300


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Result:
    verdict: Verdict
    reason: str
    evidence: tuple[str, ...] = ()
    runs: int = 1


def _clean(text: str) -> str:
    return redact_text(text)[:_MAX_LINE]


def make_result(
    verdict: Verdict, reason: str, evidence: Iterable[str] = ()
) -> Result:
    """Build a Result with secrets redacted and every line length-limited."""
    return Result(verdict, _clean(reason), tuple(_clean(line) for line in evidence))


def confirmed(reason: str, *evidence: str) -> Result:
    return make_result(Verdict.CONFIRMED, reason, evidence)


def unconfirmed(reason: str, *evidence: str) -> Result:
    return make_result(Verdict.UNCONFIRMED, reason, evidence)


def inconclusive(reason: str, *evidence: str) -> Result:
    return make_result(Verdict.INCONCLUSIVE, reason, evidence)


def error(reason: str, *evidence: str) -> Result:
    return make_result(Verdict.ERROR, reason, evidence)


class Context:
    """What a checker may use to talk to the target.

    send() refreshes CSRF/nonce values first when the request carries them:
    it fetches `token_url` (with the same headers, so the session matches),
    reads the fresh tokens, and swaps them into the request.
    """

    def __init__(
        self,
        engine: Engine,
        token_url: str = "",
        refresh_tokens: bool = True,
    ) -> None:
        self.engine = engine
        self.token_url = token_url
        self.refresh_tokens = refresh_tokens

    def send(self, probe: ProbeRequest, follow: bool | None = None) -> Response:
        probe = self._fresh(probe)
        return self.engine.request(probe.method, probe.url, probe.headers, follow)

    def _fresh(self, probe: ProbeRequest) -> ProbeRequest:
        if not (self.refresh_tokens and self.token_url and needs_refresh(probe)):
            return probe
        page = self.engine.request("GET", self.token_url, probe.headers)
        tokens = find_tokens(page.text)
        return refresh_probe(probe, tokens) if tokens else probe


class Checker(ABC):
    """Base class for one vulnerability class. Set `vuln_class` and `check`."""

    vuln_class: str = ""

    @abstractmethod
    def check(self, finding: Finding, ctx: Context) -> Result:
        """Re-test one finding and return a Result."""


class Registry:
    def __init__(self) -> None:
        self._items: dict[str, Checker] = {}

    def register(self, cls: type[Checker]) -> type[Checker]:
        name = cls.vuln_class
        if name not in VULN_CLASSES:
            raise ValueError(f"unknown vulnerability class {name!r}")
        if name in self._items:
            raise ValueError(f"a checker for {name} is already registered")
        self._items[name] = cls()
        return cls

    def get(self, name: str) -> Checker | None:
        return self._items.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


registry = Registry()
register = registry.register  # use as @register on a Checker subclass
