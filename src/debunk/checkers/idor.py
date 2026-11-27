"""Insecure Direct Object Reference (IDOR) checker.

The finding's `payload` is the id of another user's object the agent claims
it could access. There is no "my own id" in the generic finding format to
compare against, so this checker compares the claimed id against a made-up
id in the same parameter instead:

  - if the made-up id is NOT denied either, the server may return the same
    content for any id at all, so nothing can be shown: INCONCLUSIVE.
  - if the made-up id IS denied and the payload id is denied too: UNCONFIRMED.
  - if the made-up id IS denied but the payload id returns a different,
    non-denied response: CONFIRMED.

CONFIRMED here means the parameter distinguishes valid ids from invalid
ones, and the claimed id passed. It does not prove the returned data
belongs to a different user -- see the limits note in PROGRESS.md.
"""

from __future__ import annotations

import re
from dataclasses import replace

from debunk.baseline import control_request, replay_request
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

_DENIED_STATUSES = frozenset({401, 403, 404})
_DENIAL_TEXT = re.compile(
    r"access denied|not authoriz|unauthoriz|forbidden|permission denied|"
    r"please (log|sign) in|you (do not|don't) have permission|"
    r"insufficient permission",
    re.I,
)


def _is_denied(resp: Response) -> bool:
    return resp.status in _DENIED_STATUSES or bool(_DENIAL_TEXT.search(resp.text))


def _server_problem(baseline: Response, replay: Response) -> Result | None:
    for label, resp in (("baseline", baseline), ("replay", replay)):
        if resp.status == 429 or resp.status >= 500:
            return inconclusive(
                f"{label} request got HTTP {resp.status}: "
                "server unavailable or rate limiting"
            )
    return None


@register
class Idor(Checker):
    vuln_class = "idor"

    def check(self, finding: Finding, ctx: Context) -> Result:
        if not finding.payload:
            return error("finding has no payload (the other user's id) to replay")
        baseline_probe = replace(control_request(finding), method="GET")
        replay_probe = replace(replay_request(finding), method="GET")
        baseline = ctx.send(baseline_probe)
        replay = ctx.send(replay_probe)

        problem = _server_problem(baseline, replay)
        if problem is not None:
            return problem
        if baseline.truncated or replay.truncated:
            return inconclusive(
                "a response was cut at the size limit before comparison "
                "was possible"
            )

        if not _is_denied(baseline):
            return inconclusive(
                "a made-up id was not denied either, so the server may "
                "return the same content for any id; this cannot show "
                "the payload id is actually someone else's data"
            )
        if _is_denied(replay):
            return unconfirmed(
                "the payload id was denied just like a made-up id; no "
                "sign this parameter exposes another user's data"
            )

        diff = compare(baseline, replay)
        if same_page(diff):
            return inconclusive(
                "the payload id's response is not a denial, but it is "
                "also identical to the made-up id's response; access "
                "could not be determined",
                diff.summary(),
            )
        return confirmed(
            "a made-up id was denied, but the payload id returned a "
            "different, non-denied response; this suggests access to a "
            "resource outside the agent's own authorization",
            f"baseline status {baseline.status}, replay status {replay.status}",
            diff.summary(),
        )
