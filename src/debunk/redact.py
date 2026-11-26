"""Remove secrets from anything debunk prints or saves."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from urllib.parse import unquote_plus

REDACTED = "[REDACTED]"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)

SENSITIVE_PARAMS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "key",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "pwd",
        "session",
        "sessionid",
        "sid",
        "auth",
        "jwt",
        "csrf",
        "csrf_token",
        "_csrf",
        "nonce",
        "signature",
        "sig",
    }
)

# Narrower than SENSITIVE_PARAMS: plain prose like "key: value" stays readable.
_TEXT_KEYS = (
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "session",
    "sessionid",
    "sid",
)

_URL_HEADERS = frozenset({"location", "content-location", "referer"})

_USERINFO = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/?#@]*@")
_HEADER_LINE = re.compile(
    r"(?im)^([ \t]*(?:" + "|".join(sorted(SENSITIVE_HEADERS)) + r")[ \t]*:[ \t]*).*$"
)
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic)[ \t]+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_ASSIGNMENT = re.compile(
    r"(?i)\b(" + "|".join(_TEXT_KEYS) + r")\b([ \t]*[=:][ \t]*)[\"']?[^\s\"'&;,]+"
)


def _scrub_pairs(text: str) -> str:
    out = []
    for part in text.split("&"):
        name, sep, _ = part.partition("=")
        if sep and unquote_plus(name).lower() in SENSITIVE_PARAMS:
            out.append(f"{name}={REDACTED}")
        else:
            out.append(part)
    return "&".join(out)


def redact_url(url: str) -> str:
    """Hide URL passwords and secret query or fragment values."""
    url = _USERINFO.sub(lambda m: m.group(1) + REDACTED + "@", url)
    rest, hash_mark, fragment = url.partition("#")
    base, query_mark, query = rest.partition("?")
    if query_mark:
        query = _scrub_pairs(query)
    if hash_mark:
        fragment = _scrub_pairs(fragment)
    return base + query_mark + query + hash_mark + fragment


def redact_headers(
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Return header pairs with secret values hidden."""
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    out = []
    for name, value in pairs:
        low = name.lower()
        if low in SENSITIVE_HEADERS:
            value = REDACTED
        elif low in _URL_HEADERS:
            value = redact_url(value)
        out.append((name, value))
    return out


def redact_text(text: str) -> str:
    """Best-effort scrub of free text (evidence, logs, response snippets)."""
    text = _HEADER_LINE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _JWT.sub(REDACTED, text)
    text = _AUTH_SCHEME.sub(lambda m: m.group(1) + " " + REDACTED, text)
    return _ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
