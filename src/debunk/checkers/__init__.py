"""Vulnerability checkers. Each checker module registers itself on import."""

from debunk.checkers import (
    idor,  # noqa: F401
    redirect,  # noqa: F401
    sqli,  # noqa: F401
    xss,  # noqa: F401
)
