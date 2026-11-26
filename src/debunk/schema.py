"""Finding format (schema_version 1), dataclasses and strict validator.

A findings file is one JSON object:

    {
      "schema_version": 1,
      "findings": [
        {
          "id": "f1",
          "class": "xss_reflected",
          "target": "https://example.com/search",
          "title": "Reflected XSS in q",
          "parameter": "q",
          "payload": "<script>alert(1)</script>",
          "evidence": "free-text claim from the agent",
          "request": {
            "method": "GET",
            "url": "https://example.com/search?q=PAYLOAD",
            "headers": {"Cookie": "session=abc"}
          }
        }
      ]
    }

Required per finding: id, class, target. Everything else is optional.
Unknown fields are rejected on purpose, so format drift fails loudly.
v1 is read-only: request.method must be GET or HEAD.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1

VULN_CLASSES = (
    "xss_reflected",
    "sqli_boolean",
    "open_redirect",
    "idor",
    "auth_bypass",
    "file_exposure",
)
ALLOWED_METHODS = ("GET", "HEAD")

_TOP_FIELDS = {"schema_version", "findings"}
_REQUIRED = {"id", "class", "target"}
_OPTIONAL = {"title", "parameter", "payload", "evidence", "request"}
_REQUEST_FIELDS = {"method", "url", "headers"}
_MAX_TEXT = 10_000
_MAX_ID = 200


class SchemaError(Exception):
    """The whole file is unusable (not JSON, wrong shape, wrong version)."""


@dataclass(frozen=True)
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    id: str
    vuln_class: str
    target: str
    title: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: Request | None = None


@dataclass(frozen=True)
class FindingError:
    index: int
    finding_id: str
    message: str

    def __str__(self) -> str:
        return f"finding #{self.index} ({self.finding_id}): {self.message}"


@dataclass(frozen=True)
class LoadResult:
    findings: list[Finding]
    errors: list[FindingError]


def _reject_unknown(obj: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise ValueError(f"unknown field(s) in {where}: {', '.join(unknown)}")


def _text(obj: dict[str, Any], name: str) -> str:
    value = obj.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if len(value) > _MAX_TEXT:
        raise ValueError(f"{name} is too long (max {_MAX_TEXT} characters)")
    return value


def _check_url(value: str, name: str) -> str:
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError(
            f"{name} must be a URL without spaces or control characters"
        )
    try:
        parts = urlsplit(value)
        host = parts.hostname
        _ = parts.port  # raises ValueError if the port is invalid
    except ValueError as exc:
        raise ValueError(f"{name} is not a valid URL: {exc}") from exc
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError(f"{name} must be an http:// or https:// URL with a host")
    return value


def _parse_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("request.headers must be an object")
    headers: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(value, str):
            raise ValueError(f"header {key!r} must have a string value")
        bad_name = not key or any(
            c.isspace() or c == ":" or ord(c) < 32 for c in key
        )
        if bad_name or "\r" in value or "\n" in value:
            raise ValueError(f"header {key!r} has illegal characters")
        headers[key] = value
    return headers


def _parse_request(raw: Any) -> Request:
    if not isinstance(raw, dict):
        raise ValueError("request must be an object")
    _reject_unknown(raw, _REQUEST_FIELDS, "request")
    method = _text(raw, "method").upper() or "GET"
    if method not in ALLOWED_METHODS:
        raise ValueError(
            f"request.method {method} is not allowed: v1 is read-only (GET, HEAD)"
        )
    if "url" not in raw:
        raise ValueError("request.url is required")
    url = _check_url(_text(raw, "url"), "request.url")
    return Request(method, url, _parse_headers(raw.get("headers")))


def _parse_finding(raw: Any) -> Finding:
    if not isinstance(raw, dict):
        raise ValueError("finding must be a JSON object")
    _reject_unknown(raw, _REQUIRED | _OPTIONAL, "finding")
    missing = sorted(_REQUIRED - set(raw))
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")
    finding_id = _text(raw, "id").strip()
    if not finding_id or len(finding_id) > _MAX_ID:
        raise ValueError(f"id must be 1 to {_MAX_ID} characters")
    vuln_class = _text(raw, "class")
    if vuln_class not in VULN_CLASSES:
        raise ValueError(
            f"unknown class {vuln_class!r}; expected one of: "
            f"{', '.join(VULN_CLASSES)}"
        )
    target = _check_url(_text(raw, "target"), "target")
    request_raw = raw.get("request")
    request = None if request_raw is None else _parse_request(request_raw)
    return Finding(
        id=finding_id,
        vuln_class=vuln_class,
        target=target,
        title=_text(raw, "title"),
        parameter=_text(raw, "parameter"),
        payload=_text(raw, "payload"),
        evidence=_text(raw, "evidence"),
        request=request,
    )


def _label(raw: Any) -> str:
    if isinstance(raw, dict) and isinstance(raw.get("id"), str):
        return raw["id"]
    return "?"


def parse_document(data: Any) -> LoadResult:
    """Validate already-parsed JSON. Raises SchemaError if the file is unusable."""
    if not isinstance(data, dict):
        raise SchemaError(
            'top level must be a JSON object: {"schema_version": 1, "findings": []}'
        )
    unknown = sorted(set(data) - _TOP_FIELDS)
    if unknown:
        raise SchemaError(f"unknown top-level field(s): {', '.join(unknown)}")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION or isinstance(version, bool):
        raise SchemaError(
            f"unsupported schema_version {version!r}; "
            f"this debunk reads version {SCHEMA_VERSION}"
        )
    items = data.get("findings")
    if not isinstance(items, list):
        raise SchemaError('"findings" must be a list')

    findings: list[Finding] = []
    errors: list[FindingError] = []
    seen: set[str] = set()
    for index, raw in enumerate(items, start=1):
        try:
            finding = _parse_finding(raw)
            if finding.id in seen:
                raise ValueError(f"duplicate id {finding.id!r}")
        except ValueError as exc:
            errors.append(FindingError(index, _label(raw), str(exc)))
            continue
        seen.add(finding.id)
        findings.append(finding)
    return LoadResult(findings, errors)


def load_findings(text: str) -> LoadResult:
    """Parse JSON text, then validate it."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise SchemaError(f"not valid JSON: {exc}") from exc
    return parse_document(data)


def load_file(path: str) -> LoadResult:
    """Read a findings file from disk (UTF-8, with or without a BOM)."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise SchemaError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SchemaError(f"{path} is not valid UTF-8 text") from exc
    return load_findings(text)
