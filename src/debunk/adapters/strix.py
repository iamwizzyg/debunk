"""Strix v1.7.x adapter: reads a strix_runs/<run> directory.

PROVISIONAL FORMAT: Strix's real output layout is unconfirmed -- the
agent's JSON shape has reportedly changed across releases, and debunk has
not yet been run against a real Strix v1.7.1 export. This adapter targets
one specific, documented layout and vocabulary; anything else is rejected
loudly rather than guessed at, so format drift surfaces as a clear error
instead of silently wrong results (per the step 1 decision to fail loudly
on shape mismatch). Expected layout:

    strix_runs/<run>/
        manifest.json   {"strix_version": "1.7.1", ...}
        findings.json   {"findings": [ {...}, ... ]}

Each finding entry: required id, vulnerability_type, target_url; optional
title, parameter, payload, evidence, request {method, url, headers}.
vulnerability_type is translated through CLASS_MAP into debunk's own
vulnerability classes; an unrecognised value is reported as an error for
that one entry, not a crash.

If a real Strix v1.7.1 export does not match this layout, that is this
adapter doing its job: update CLASS_MAP, the expected filenames, or the
required fields below to match a real sample, rather than loosening the
checks to guess.
"""

from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from debunk.adapters.base import Adapter, AdapterError, register
from debunk.schema import ALLOWED_METHODS, Finding, FindingError, LoadResult, Request

SUPPORTED_PREFIX = "1.7."
MANIFEST_NAME = "manifest.json"
FINDINGS_NAME = "findings.json"

# Provisional mapping from Strix's vulnerability_type strings to debunk's
# own vulnerability classes. Update this once a real sample is available.
CLASS_MAP = {
    "reflected_xss": "xss_reflected",
    "xss": "xss_reflected",
    "sql_injection": "sqli_boolean",
    "sqli": "sqli_boolean",
    "boolean_sqli": "sqli_boolean",
    "open_redirect": "open_redirect",
    "idor": "idor",
    "broken_access_control": "idor",
    "auth_bypass": "auth_bypass",
    "authentication_bypass": "auth_bypass",
    "sensitive_file_exposure": "file_exposure",
    "information_disclosure": "file_exposure",
}

_REQUIRED = {"id", "vulnerability_type", "target_url"}
_OPTIONAL = {"title", "parameter", "payload", "evidence", "request"}
_REQUEST_FIELDS = {"method", "url", "headers"}
_MAX_TEXT = 10_000
_MAX_ID = 200


def _reject_unknown(obj: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        raise ValueError(f"unknown field(s) in {where}: {', '.join(unknown)}")


def _text(obj: dict, name: str) -> str:
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


def _parse_headers(raw: object) -> dict[str, str]:
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


def _parse_request(raw: object) -> Request:
    if not isinstance(raw, dict):
        raise ValueError("request must be an object")
    _reject_unknown(raw, _REQUEST_FIELDS, "request")
    method = _text(raw, "method").upper() or "GET"
    if method not in ALLOWED_METHODS:
        raise ValueError(
            f"request.method {method} is not allowed: debunk v1 is read-only"
        )
    if "url" not in raw:
        raise ValueError("request.url is required")
    url = _check_url(_text(raw, "url"), "request.url")
    return Request(method, url, _parse_headers(raw.get("headers")))


def _parse_entry(raw: object) -> Finding:
    if not isinstance(raw, dict):
        raise ValueError("finding entry must be a JSON object")
    _reject_unknown(raw, _REQUIRED | _OPTIONAL, "finding")
    missing = sorted(_REQUIRED - set(raw))
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")
    finding_id = _text(raw, "id").strip()
    if not finding_id or len(finding_id) > _MAX_ID:
        raise ValueError(f"id must be 1 to {_MAX_ID} characters")
    strix_type = _text(raw, "vulnerability_type")
    vuln_class = CLASS_MAP.get(strix_type)
    if vuln_class is None:
        raise ValueError(
            f"unrecognised vulnerability_type {strix_type!r}; this "
            f"adapter only maps: {', '.join(sorted(CLASS_MAP))}"
        )
    target = _check_url(_text(raw, "target_url"), "target_url")
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


def _label(raw: object) -> str:
    if isinstance(raw, dict) and isinstance(raw.get("id"), str):
        return raw["id"]
    return "?"


def _read_json(path: str) -> object:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise AdapterError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AdapterError(f"{path} is not valid UTF-8 text") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AdapterError(f"{path} is not valid JSON: {exc}") from exc


@register
class StrixAdapter(Adapter):
    name = "strix"

    def load(self, path: str) -> LoadResult:
        if not os.path.isdir(path):
            raise AdapterError(f"{path} is not a Strix run directory")

        manifest_path = os.path.join(path, MANIFEST_NAME)
        if not os.path.isfile(manifest_path):
            raise AdapterError(
                f"expected a Strix manifest at {manifest_path}, which was "
                "not found; this adapter targets a specific Strix v1.7.x "
                "layout and may need updating for a different version"
            )
        manifest = _read_json(manifest_path)
        if not isinstance(manifest, dict):
            raise AdapterError(f"{manifest_path} must contain a JSON object")
        version = manifest.get("strix_version")
        if not isinstance(version, str) or not version.startswith(SUPPORTED_PREFIX):
            raise AdapterError(
                f"unsupported strix_version {version!r} in {manifest_path}; "
                f"this adapter only supports Strix {SUPPORTED_PREFIX}x output"
            )

        findings_path = os.path.join(path, FINDINGS_NAME)
        if not os.path.isfile(findings_path):
            raise AdapterError(
                f"expected Strix findings at {findings_path}, which was not found"
            )
        data = _read_json(findings_path)
        if not isinstance(data, dict):
            raise AdapterError(f"{findings_path} must contain a JSON object")
        items = data.get("findings")
        if not isinstance(items, list):
            raise AdapterError(f'{findings_path} must have a "findings" list')
        unknown = sorted(set(data) - {"findings"})
        if unknown:
            raise AdapterError(
                f"unknown field(s) in {findings_path}: {', '.join(unknown)}"
            )

        findings: list[Finding] = []
        errors: list[FindingError] = []
        seen: set[str] = set()
        for index, raw in enumerate(items, start=1):
            try:
                finding = _parse_entry(raw)
                if finding.id in seen:
                    raise ValueError(f"duplicate id {finding.id!r}")
            except ValueError as exc:
                errors.append(FindingError(index, _label(raw), str(exc)))
                continue
            seen.add(finding.id)
            findings.append(finding)
        return LoadResult(findings, errors)
