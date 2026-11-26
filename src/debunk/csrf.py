"""Find CSRF/nonce tokens in a page and put fresh ones into a replay request.

Only names that look like CSRF or nonce fields are touched. Ordinary auth
tokens are left alone on purpose: refreshing those could hide a real finding.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from dataclasses import replace
from urllib.parse import unquote_plus, urlsplit

from debunk.baseline import ProbeRequest, swap_param

_DYNAMIC = re.compile(r"csrf|xsrf|nonce|authenticity|verification", re.I)
_HEADER_TOKEN = re.compile(r"csrf|xsrf", re.I)
_HEADERS = frozenset({"x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken"})
_TAG = re.compile(r"<(input|meta)\b[^>]*>", re.I)
_ATTR = re.compile(
    r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))"""
)
_MAX_TOKEN = 512


def _attrs(tag: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _ATTR.finditer(tag):
        value = next((g for g in match.groups()[1:] if g is not None), "")
        out.setdefault(match.group(1).lower(), value)
    return out


def find_tokens(page: str) -> dict[str, str]:
    """Return {lowercase name: value} for CSRF/nonce inputs and meta tags.

    The first token seen for a name wins. Empty, oversized or multi-line
    values are skipped, so a hostile page cannot inject header lines.
    """
    tokens: dict[str, str] = {}
    for match in _TAG.finditer(page):
        attrs = _attrs(match.group(0))
        name = attrs.get("name", "")
        key = "value" if match.group(1).lower() == "input" else "content"
        value = html.unescape(attrs.get(key, ""))
        if not value or not _DYNAMIC.search(name):
            continue
        if len(value) > _MAX_TOKEN or "\r" in value or "\n" in value:
            continue
        tokens.setdefault(name.lower(), value)
    return tokens


def _query_names(url: str) -> list[str]:
    query = urlsplit(url).query
    return [unquote_plus(p.partition("=")[0]) for p in query.split("&") if "=" in p]


def needs_refresh(probe: ProbeRequest) -> bool:
    """True when the request carries a CSRF/nonce value that may be stale."""
    if any(_DYNAMIC.search(name) for name in _query_names(probe.url)):
        return True
    return any(key.lower() in _HEADERS for key in probe.headers)


def refresh_probe(probe: ProbeRequest, tokens: Mapping[str, str]) -> ProbeRequest:
    """Swap fresh token values into the query string and CSRF headers."""
    url = probe.url
    for name in _query_names(probe.url):
        fresh = tokens.get(name.lower())
        if fresh is not None:
            url = swap_param(url, name, fresh)
    header_token = next((v for k, v in tokens.items() if _HEADER_TOKEN.search(k)), None)
    headers = dict(probe.headers)
    if header_token is not None:
        for key in headers:
            if key.lower() in _HEADERS:
                headers[key] = header_token
    return replace(probe, url=url, headers=headers)
