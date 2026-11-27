"""Authentication/authorization bypass checker.

The finding's request carries whatever technique the agent used to reach
a protected resource (an extra header, a path trick, a different method)
with no valid credentials. This checker strips every credential
(Authorization, Cookie and similar headers, and token/session/key-style
query parameters) from both requests, then compares the stripped replay
against a bare, trick-free request to the same target. Both are sent with
follow=False, so a redirect to a login page is seen directly rather than
followed. CONFIRMED needs the bare request to be denied (showing the
resource is normally protected) and the agent's technique, still with no
credentials, to get through anyway.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from debunk.baseline import ProbeRequest, replay_request
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
from debunk.redact import SENSITIVE_HEADERS, SENSITIVE_PARAMS
from debunk.schema import Finding

_DENIED_STATUSES = frozenset({401, 403, 404})
_REDIRECT_CODES = (301, 302, 303, 307, 308)
_LOGIN_HINT = re.compile(r"login|sign[-_]?in|/auth/|sso", re.I)
_DENIAL_TEXT = re.compile(
    r"access denied|not authoriz|unauthoriz|forbidden|permission denied|"
    r"please (log|sign) in|you (do not|don't) have permission|"
    r"insufficient permission",
    re.I,
)


def _is_denied(resp: Response) -> bool:
    if resp.status in _DENIED_STATUSES:
        return True
    if resp.status in _REDIRECT_CODES:
        location = resp.header("location") or ""
        if _LOGIN_HINT.search(location):
            return True
    return bool(_DENIAL_TEXT.search(resp.text))


def _strip_params(url: str) -> str:
    """Remove any query parameter whose name looks like a credential."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in SENSITIVE_PARAMS
    ]
    query = urlencode(kept)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _strip_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in SENSITIVE_HEADERS}


def _server_problem(control: Response, replay: Response) -> Result | None:
    for label, resp in (("control", control), ("replay", replay)):
        if resp.status == 429 or resp.status >= 500:
            return inconclusive(
                f"{label} request got HTTP {resp.status}: "
                "server unavailable or rate limiting"
            )
    return None


@register
class AuthBypass(Checker):
    vuln_class = "auth_bypass"

    def check(self, finding: Finding, ctx: Context) -> Result:
        if finding.request is None:
            return error(
                "finding has no request data; an auth bypass needs the "
                "technique (headers, method or URL) the agent used"
            )
        raw = replay_request(finding)
        replay_probe = ProbeRequest(
            raw.method, _strip_params(raw.url), _strip_headers(raw.headers)
        )
        control_probe = ProbeRequest(raw.method, _strip_params(finding.target), {})

        control = ctx.send(control_probe, follow=False)
        replay = ctx.send(replay_probe, follow=False)

        problem = _server_problem(control, replay)
        if problem is not None:
            return problem
        if control.truncated or replay.truncated:
            return inconclusive(
                "a response was cut at the size limit before comparison "
                "was possible"
            )

        if not _is_denied(control):
            return inconclusive(
                "a plain request with no credentials and no special "
                "headers was not denied either; this resource may not "
                "require authorization at all"
            )
        if _is_denied(replay):
            return unconfirmed(
                "the agent's request, with credentials removed, was "
                "denied the same way as a plain request; no sign of a "
                "bypass"
            )

        diff = compare(control, replay)
        if same_page(diff):
            return inconclusive(
                "the agent's request is not denied, but its response is "
                "identical to the plain denied response; access could "
                "not be determined",
                diff.summary(),
            )
        return confirmed(
            "a plain, credential-free request was denied, but the "
            "agent's request -- with credentials removed the same way, "
            "using its own technique -- was not; this suggests an "
            "access control bypass",
            f"control status {control.status}, replay status {replay.status}",
            diff.summary(),
        )
