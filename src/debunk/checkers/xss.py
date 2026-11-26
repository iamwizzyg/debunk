"""Reflected XSS checker.

Replays the agent's payload and a harmless control, then reads both pages
with the standard-library HTML parser. CONFIRMED needs the payload reflected
unencoded AND new executable markup in the replay that the control lacks:
a new <script>, a new on...= handler, or a javascript: URL. Contexts that
cannot be judged without a browser (inside an existing <script>, under a
Content-Security-Policy, blocked by a firewall) are INCONCLUSIVE.
This checker never runs JavaScript.
"""

from __future__ import annotations

import html
import re
from collections import Counter
from dataclasses import replace
from html.parser import HTMLParser

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
from debunk.engine import Response
from debunk.schema import Finding

# Elements whose contents are text, not markup, for a browser.
_INERT = frozenset(
    {"textarea", "title", "xmp", "noembed", "noframes", "iframe", "plaintext"}
)
_URL_ATTRS = frozenset({"href", "src", "action", "formaction", "data", "xlink:href"})
_HTML_TYPES = ("", "text/html", "application/xhtml+xml")


def _is_js_url(value: str) -> bool:
    return re.sub(r"[\x00-\x20]", "", value).lower().startswith("javascript:")


class _Page(HTMLParser):
    """Collects script elements and event-handler or javascript: attributes."""

    def __init__(self, mask: str) -> None:
        super().__init__(convert_charrefs=True)
        self.mask = mask  # reflected value, hidden so reflection is not "new"
        self.features: Counter[tuple[str, str, str]] = Counter()
        self.raw: dict[tuple[str, str, str], str] = {}
        self.scripts = 0
        self.script_data: list[str] = []
        self._inert = 0
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        if not self._inert:
            self._count(tag, attrs)
        if tag in _INERT:
            self._inert += 1

    def _count(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
            self._in_script = True
        for name, value in attrs:
            name = name.lower()
            value = value or ""
            handler = name.startswith("on") and len(name) > 2
            if handler or (name in _URL_ATTRS and _is_js_url(value)):
                key = (tag, name, value.replace(self.mask, "{PROBE}"))
                self.features[key] += 1
                self.raw[key] = value

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        if tag in _INERT and self._inert:
            self._inert -= 1

    def handle_data(self, data):
        if self._in_script and not self._inert:
            self.script_data.append(data)


def _scan(text: str, mask: str) -> _Page:
    page = _Page(mask)
    try:
        page.feed(text)
        page.close()
    except Exception:
        pass  # odd markup must never crash a check; keep what was parsed
    return page


def _related(payload: str, text: str) -> bool:
    """True when `text` shares a word with the payload (or it has none)."""
    words = re.findall(r"[a-z0-9_]{3,}", payload.lower())
    low = text.lower()
    return not words or any(word in low for word in words)


def _injected(replay: _Page, control: _Page, payload: str) -> list[str]:
    lines = []
    if replay.scripts > control.scripts and "<script" in payload.lower():
        lines.append("new <script> element in the response")
    for key in replay.features - control.features:
        raw = replay.raw[key]
        if _related(payload, f"{key[1]} {raw}"):
            lines.append(f'new <{key[0]} {key[1]}="{raw}">')
    return lines


def _content_type(resp: Response) -> str:
    return (resp.header("content-type") or "").split(";")[0].strip().lower()


def _csp_may_block(resp: Response) -> bool:
    policy = (resp.header("content-security-policy") or "").lower()
    return bool(policy) and "unsafe-inline" not in policy


def _server_problem(control: Response, replay: Response) -> Result | None:
    for label, resp in (("control", control), ("replay", replay)):
        if resp.status == 429 or resp.status >= 500:
            return inconclusive(
                f"{label} request got HTTP {resp.status}: "
                "server unavailable or rate limiting"
            )
    if replay.status in (403, 406) and control.status < 400:
        return inconclusive(
            f"replay was blocked (HTTP {replay.status}) but the control was not; "
            "a firewall may be filtering the payload"
        )
    return None


def _judge(payload: str, control: Response, replay: Response) -> Result:
    if payload in control.text:
        return unconfirmed(
            "payload text is already in the page without the attack value, "
            "so reflection proves nothing"
        )
    ctype = _content_type(replay)
    if ctype not in _HTML_TYPES:
        return unconfirmed(
            f"response is {ctype}, not HTML; browsers will not run script from it"
        )
    if payload not in replay.text:
        if replay.truncated:
            return inconclusive(
                "response was cut at the size limit before the payload was found"
            )
        if html.escape(payload) in replay.text or (
            html.escape(payload, quote=False) in replay.text
        ):
            return unconfirmed("payload is reflected but HTML-encoded")
        return unconfirmed("payload is not reflected in the response")

    page = _scan(replay.text, payload)
    found = _injected(page, _scan(control.text, CONTROL_VALUE), payload)
    if found:
        evidence = (f"replay url: {replay.safe_url()}", *found)
        if _csp_may_block(replay):
            return inconclusive(
                "payload creates executable markup, but the response's "
                "Content-Security-Policy may stop it; test in a browser",
                *evidence,
            )
        return confirmed(
            "payload is reflected unencoded and creates executable markup",
            *evidence,
        )
    if any(payload in data for data in page.script_data):
        return inconclusive(
            "payload lands inside an existing <script> block; "
            "a browser is needed to tell whether it breaks out"
        )
    return unconfirmed(
        "payload is reflected unencoded, but only where script will not run "
        "(comment, attribute value, text area or similar)"
    )


@register
class ReflectedXss(Checker):
    vuln_class = "xss_reflected"

    def check(self, finding: Finding, ctx: Context) -> Result:
        payload = finding.payload
        if not payload:
            return error("finding has no payload to replay")
        # GET only: a HEAD response has no body to inspect.
        control_probe = replace(control_request(finding), method="GET")
        replay_probe = replace(replay_request(finding), method="GET")
        control = ctx.send(control_probe)
        replay = ctx.send(replay_probe)
        return _server_problem(control, replay) or _judge(payload, control, replay)
