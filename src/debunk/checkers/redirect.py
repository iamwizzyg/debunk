"""Open redirect checker.

Replays the agent's payload (a URL meant to send victims off-site), with
follow=False so the 3xx itself can be inspected, and a harmless control.
CONFIRMED needs the replay to redirect -- by a 3xx Location header or a
<meta http-equiv="refresh"> tag -- to the external host the payload names,
while the control does not redirect there. A redirect back to the target's
own host, to a different host than the payload named, or a fixed redirect
the control also produces, is not treated as an open redirect.
"""

from __future__ import annotations

import re
from dataclasses import replace
from urllib.parse import urljoin, urlsplit

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
from debunk.engine import Response
from debunk.schema import Finding

_REDIRECT_CODES = (301, 302, 303, 307, 308)
_META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(
    r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))"""
)


def _attrs(tag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _ATTR.finditer(tag):
        value = next((g for g in match.groups()[1:] if g is not None), "")
        out.setdefault(match.group(1).lower(), value)
    return out


def _meta_refresh_url(text: str) -> str | None:
    """The URL in a <meta http-equiv="refresh" content="N;url=..."> tag,
    whatever order its attributes are in. None if there is no such tag."""
    for tag_match in _META_TAG.finditer(text):
        attrs = _attrs(tag_match.group(0))
        if attrs.get("http-equiv", "").strip().lower() != "refresh":
            continue
        _, _, rest = attrs.get("content", "").partition(";")
        rest = rest.strip()
        if rest.lower().startswith("url="):
            return rest[4:].strip().strip("\"'")
    return None


def _normalize(url: str) -> str:
    """Undo tricks that only matter to a browser's URL parser: backslashes
    treated as slashes, and leading whitespace."""
    return url.replace("\\", "/").strip()


def _explicit_host(url: str) -> str | None:
    """Hostname this URL explicitly names, or None if it has no scheme or
    leading // and so cannot point off-host."""
    normalized = _normalize(url)
    parts = urlsplit(normalized)
    if parts.scheme and parts.scheme not in ("http", "https"):
        return None
    if parts.scheme or normalized.startswith("//"):
        return parts.hostname
    return None


def _destination(resp: Response) -> tuple[str, str] | None:
    """Where the response points: (source, raw URL). None if nowhere."""
    location = resp.header("location")
    if resp.status in _REDIRECT_CODES and location:
        return "Location header", location
    found = _meta_refresh_url(resp.text)
    return ("meta refresh tag", found) if found else None


def _host_of(resp: Response, dest: tuple[str, str]) -> str | None:
    return urlsplit(urljoin(resp.url, _normalize(dest[1]))).hostname


def _server_problem(control: Response, replay: Response) -> Result | None:
    for label, resp in (("control", control), ("replay", replay)):
        if resp.status == 429 or resp.status >= 500:
            return inconclusive(
                f"{label} request got HTTP {resp.status}: "
                "server unavailable or rate limiting"
            )
    if replay.status in (403, 406) and control.status < 400:
        return inconclusive(
            f"replay was blocked (HTTP {replay.status}) but the control was "
            "not; a firewall may be filtering the payload"
        )
    return None


@register
class OpenRedirect(Checker):
    vuln_class = "open_redirect"

    def check(self, finding: Finding, ctx: Context) -> Result:
        payload = finding.payload
        if not payload:
            return error("finding has no payload to replay")
        target_host = urlsplit(finding.target).hostname
        attacker_host = _explicit_host(payload)
        if attacker_host is None:
            return error(
                "payload does not name an external host to redirect to "
                "(no scheme or leading //); cannot test for an open redirect"
            )
        if attacker_host == target_host:
            return error(
                "payload's host is the same as the target's host; this "
                "payload cannot demonstrate an off-site redirect"
            )

        control_probe = replace(control_request(finding), method="GET")
        replay_probe = replace(replay_request(finding), method="GET")
        control = ctx.send(control_probe, follow=False)
        replay = ctx.send(replay_probe, follow=False)

        problem = _server_problem(control, replay)
        if problem is not None:
            return problem

        dest = _destination(replay)
        if dest is None:
            if replay.truncated:
                return inconclusive(
                    "response was cut at the size limit before a redirect "
                    "could be found"
                )
            return unconfirmed(
                "replay does not redirect (no 3xx Location header or meta "
                "refresh tag); this parameter does not appear to control "
                "a redirect"
            )
        source, raw_location = dest
        host = _host_of(replay, dest)

        if host is None or host == target_host:
            return unconfirmed(
                f"replay redirects via its {source}, but to the target's "
                "own host, not off-site"
            )
        if host != attacker_host:
            return unconfirmed(
                f"replay redirects via its {source} to a different host "
                f"than the payload named ({attacker_host!r}); this "
                "parameter may not control the destination directly"
            )

        control_dest = _destination(control)
        if control_dest is not None and _host_of(control, control_dest) == host:
            return inconclusive(
                "the control request (a harmless value) also redirects to "
                "the same external host; the redirect may not be caused "
                "by the payload"
            )

        return confirmed(
            f"replay redirects off-site via its {source} to the host the "
            "payload named, and the control does not",
            f"{source}: {raw_location}",
        )
