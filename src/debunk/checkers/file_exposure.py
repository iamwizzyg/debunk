"""Sensitive file exposure checker.

Fetches the file the agent claims is exposed, plus a "page that cannot
exist" sibling (baseline.nonexistent_url) to catch servers that return 200
to everything. CONFIRMED needs a successful response whose content matches
a known signature for a sensitive file (a private key, a .git internal
file, a database dump, an htpasswd file, a PHP database config, AWS
credentials, or an .env-style file with a secret-looking variable), while
the catch-all sibling does not match the same way.
"""

from __future__ import annotations

import re
from dataclasses import replace

from debunk.baseline import nonexistent_url, replay_request
from debunk.checkers.base import (
    Checker,
    Context,
    Result,
    confirmed,
    inconclusive,
    register,
    unconfirmed,
)
from debunk.differ import compare, same_page
from debunk.engine import Response
from debunk.schema import Finding

_REDIRECT_CODES = (301, 302, 303, 307, 308)
_MIN_ENV_ASSIGNMENTS = 2

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
_GIT_CONFIG = re.compile(r"\[core\]|repositoryformatversion")
_GIT_HEAD = re.compile(r"^ref:\s*refs/", re.M)
_SQL_DUMP = re.compile(
    r"-- (MySQL dump|PostgreSQL database dump)|^CREATE TABLE\b", re.I | re.M
)
_HTPASSWD = re.compile(r":\{SHA\}|:\$apr1\$|:\$2[aby]\$")
_PHP_CONFIG = re.compile(r"define\(\s*['\"]DB_(HOST|NAME|USER|PASSWORD)", re.I)
_AWS_CREDS = re.compile(
    r"aws_access_key_id\s*=|aws_secret_access_key\s*=", re.I
)
_ENV_SECRET_NAME = re.compile(
    r"^(?:export\s+)?\w*"
    r"(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|DATABASE_URL)\w*\s*=",
    re.M | re.I,
)
_ENV_ASSIGNMENT = re.compile(r"^(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", re.M)

_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("a private key", _PRIVATE_KEY),
    ("a .git repository config", _GIT_CONFIG),
    ("a .git HEAD file", _GIT_HEAD),
    ("a database dump", _SQL_DUMP),
    ("an htpasswd credentials file", _HTPASSWD),
    ("a PHP database config", _PHP_CONFIG),
    ("AWS credentials", _AWS_CREDS),
    ("an .env file with a secret-looking variable", _ENV_SECRET_NAME),
)


def _signature(text: str) -> str | None:
    for label, pattern in _SIGNATURES:
        if pattern.search(text):
            return label
    if len(_ENV_ASSIGNMENT.findall(text)) >= _MIN_ENV_ASSIGNMENTS:
        return "an environment-style configuration file"
    return None


def _server_problem(replay: Response, catchall: Response) -> Result | None:
    for label, resp in (("replay", replay), ("catch-all probe", catchall)):
        if resp.status == 429 or resp.status >= 500:
            return inconclusive(
                f"{label} request got HTTP {resp.status}: "
                "server unavailable or rate limiting"
            )
    return None


@register
class FileExposure(Checker):
    vuln_class = "file_exposure"

    def check(self, finding: Finding, ctx: Context) -> Result:
        replay_probe = replace(replay_request(finding), method="GET")
        replay = ctx.send(replay_probe, follow=False)
        catchall_probe = replace(replay_probe, url=nonexistent_url(replay_probe.url))
        catchall = ctx.send(catchall_probe, follow=False)

        problem = _server_problem(replay, catchall)
        if problem is not None:
            return problem
        if replay.status in _REDIRECT_CODES or replay.status >= 400:
            return unconfirmed(
                f"replay returned HTTP {replay.status}, not a successful "
                "response; the file does not appear to be exposed"
            )
        if replay.truncated:
            return inconclusive(
                "response was cut at the size limit before a signature "
                "could be checked"
            )

        label = _signature(replay.text)
        if label is None:
            return unconfirmed(
                "response was successful, but its content does not match "
                "any known signature for a sensitive file"
            )

        if catchall.status == 200:
            catchall_label = _signature(catchall.text)
            diff = compare(replay, catchall)
            if catchall_label == label or same_page(diff):
                return inconclusive(
                    "a nonexistent sibling path also returned HTTP 200 "
                    "with a matching signature; this server may return "
                    "200 to everything (catch-all)",
                    f"catch-all status {catchall.status}",
                )

        return confirmed(
            f"response matches the signature of {label}, and a "
            "nonexistent sibling path does not",
            f"replay status {replay.status}, catch-all status {catchall.status}",
        )
