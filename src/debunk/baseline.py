"""Build the replay request and the control (baseline) request for a finding.

The replay is the agent's claimed proof of concept. The control is the same
request with the attack value swapped for a harmless one, so the two can be
compared. This module only builds requests; it never sends them.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from urllib.parse import quote, quote_plus, unquote_plus, urlsplit, urlunsplit

from debunk.schema import Finding

CONTROL_VALUE = "dbnkctl7391"
NOPE_PATH = "/debunk-no-such-path-7391"


class BaselineError(Exception):
    """A control request could not be built for this finding."""


@dataclass(frozen=True)
class ProbeRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)


def swap_param(url: str, name: str, value: str) -> str:
    """Set query parameter `name` to `value`, leaving the rest of the URL alone.

    Every existing copy of the parameter is replaced; if there is none, it is
    added at the end. The value is percent-encoded.
    """
    parts = urlsplit(url)
    encoded = quote(value, safe="")
    pieces = parts.query.split("&") if parts.query else []
    found = False
    for index, piece in enumerate(pieces):
        key, sep, _ = piece.partition("=")
        if sep and unquote_plus(key) == name:
            pieces[index] = f"{key}={encoded}"
            found = True
    if not found:
        pieces.append(f"{quote(name, safe='')}={encoded}")
    query = "&".join(pieces)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _swap_payload(url: str, payload: str, value: str) -> str | None:
    """Replace the payload text inside a URL (raw or percent-encoded)."""
    for candidate in (payload, quote(payload, safe=""), quote_plus(payload)):
        if candidate and candidate in url:
            return url.replace(candidate, quote(value, safe=""), 1)
    return None


def replay_request(finding: Finding) -> ProbeRequest:
    """The request that replays the agent's claim.

    Uses the finding's own request when it has one. If the request is missing
    but a parameter and payload are named, the payload is put into that
    parameter on the target URL. Otherwise it is a plain GET of the target.
    """
    req = finding.request
    if req is not None:
        return ProbeRequest(req.method, req.url, dict(req.headers))
    if finding.parameter and finding.payload:
        return ProbeRequest(
            "GET", swap_param(finding.target, finding.parameter, finding.payload)
        )
    return ProbeRequest("GET", finding.target)


def control_request(finding: Finding, value: str = CONTROL_VALUE) -> ProbeRequest:
    """The replay request with the attack value swapped for a harmless one."""
    replay = replay_request(finding)
    if finding.parameter:
        url = swap_param(replay.url, finding.parameter, value)
    else:
        url = _swap_payload(replay.url, finding.payload, value)
        if url is None:
            raise BaselineError(
                "cannot build a control request: the finding names no parameter "
                "and its payload is not in the request URL"
            )
    return replace(replay, url=url, headers=dict(replay.headers))


def nonexistent_url(url: str) -> str:
    """A sibling URL that should not exist, for spotting servers that say 200
    to everything. It sits in the same directory as the original path."""
    parts = urlsplit(url)
    directory = parts.path.rsplit("/", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc, directory + NOPE_PATH, "", ""))
