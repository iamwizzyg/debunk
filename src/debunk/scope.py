"""Scope enforcement for --scope FILE.

File format: one glob pattern per line, matched case-insensitively against
a request's hostname via fnmatch. Blank lines and lines starting with '#'
are ignored. A pattern with no wildcard matches that exact host; the
pattern '*.example.com' matches subdomains but not example.com itself --
list both lines if you want to allow both.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from urllib.parse import urlsplit


class ScopeError(Exception):
    """The scope file could not be read, or had no usable patterns."""


def load_scope(path: str) -> tuple[str, ...]:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise ScopeError(
            f"cannot read scope file {path}: {exc.strerror or exc}"
        ) from exc
    patterns = [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]
    if not patterns:
        raise ScopeError(
            f"scope file {path} has no patterns "
            "(every line is blank or a comment)"
        )
    return tuple(patterns)


def make_guard(patterns: tuple[str, ...]) -> Callable[[str], bool]:
    """Build a guard(url) -> bool for Engine(guard=...)."""
    lowered = tuple(p.lower() for p in patterns)

    def guard(url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(fnmatch.fnmatchcase(host, pattern) for pattern in lowered)

    return guard
