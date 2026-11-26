"""Compare a control response with a replayed-PoC response.

Both bodies are cleaned first so harmless differences do not look like
findings: the probe value itself (it is reflected differently on purpose),
CSRF/nonce form values, and long hex ids or UUIDs. What is left is compared
as a bag of tokens (tags and words), which is fast, repeatable, and ignores
word order.
"""

from __future__ import annotations

import html
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from debunk.engine import Response
from debunk.redact import redact_text, redact_url

MAX_TOKENS = 20_000
_SAMPLE_COUNT = 5
_SAMPLE_CHARS = 80

_TOKEN = re.compile(r"<[^>]+>|[^<\s]+")
_INPUT = re.compile(r"<input\b[^>]*>", re.I)
_META = re.compile(r"<meta\b[^>]*>", re.I)
_DYNAMIC_NAME = re.compile(
    r"""name\s*=\s*["']?[^"'\s>]*"""
    r"(?:csrf|xsrf|nonce|authenticity|token|verification)",
    re.I,
)
_UUID = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
_ID = re.compile(rf"\b(?:{_UUID}|[0-9a-fA-F]{{32,}})\b")


def _mask_probe(text: str, probe: str) -> str:
    if not probe:
        return text
    variants = {
        probe,
        html.escape(probe, quote=True),
        html.escape(probe, quote=False),
        quote(probe, safe=""),
        quote_plus(probe),
    }
    for variant in sorted(variants, key=lambda v: (-len(v), v)):
        text = text.replace(variant, "{PROBE}")
    return text


def _fixer(attr: str):
    value = re.compile(rf"""({attr}\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.I)

    def repl(match: re.Match) -> str:
        tag = match.group(0)
        if not _DYNAMIC_NAME.search(tag):
            return tag
        return value.sub(lambda m: m.group(1) + '"{DYN}"', tag)

    return repl


def _mask_dynamic(text: str) -> str:
    text = _INPUT.sub(_fixer("value"), text)
    return _META.sub(_fixer("content"), text)


def _tokens(text: str, probe: str) -> tuple[list[str], bool]:
    cleaned = _ID.sub("{ID}", _mask_dynamic(_mask_probe(text, probe)))
    found = _TOKEN.findall(cleaned)
    return found[:MAX_TOKENS], len(found) > MAX_TOKENS


def _sample(ordered: list[str], wanted: Counter) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for token in ordered:
        if token in wanted and token not in seen:
            seen.add(token)
            out.append(redact_text(token[:_SAMPLE_CHARS]))
            if len(out) == _SAMPLE_COUNT:
                break
    return tuple(out)


def _content_type(resp: Response) -> str:
    return (resp.header("content-type") or "").split(";")[0].strip().lower()


@dataclass(frozen=True)
class Diff:
    control_status: int
    replay_status: int
    control_location: str  # redacted, for display
    replay_location: str  # redacted, for display
    location_changed: bool  # decided on the raw values
    control_type: str
    replay_type: str
    similarity: float  # 0.0 to 1.0
    body_same: bool
    added: tuple[str, ...]  # a few tokens only the replay has (redacted)
    removed: tuple[str, ...]  # a few tokens only the control has (redacted)
    added_count: int
    removed_count: int
    truncated: bool  # a body or token list was cut short; trust less

    @property
    def status_changed(self) -> bool:
        return self.control_status != self.replay_status

    @property
    def type_changed(self) -> bool:
        return self.control_type != self.replay_type

    @property
    def identical(self) -> bool:
        return not (
            self.status_changed
            or self.location_changed
            or self.type_changed
            or not self.body_same
        )

    def summary(self) -> str:
        return (
            f"status {self.control_status}->{self.replay_status}, "
            f"similarity {self.similarity:.2f}, "
            f"+{self.added_count}/-{self.removed_count} tokens"
        )


def compare(
    control: Response,
    replay: Response,
    control_probe: str = "",
    replay_probe: str = "",
) -> Diff:
    """Diff the replay against the control. Pass each side's probe value so
    its reflection is ignored."""
    c_list, c_cut = _tokens(control.text, control_probe)
    r_list, r_cut = _tokens(replay.text, replay_probe)
    c_bag, r_bag = Counter(c_list), Counter(r_list)
    more, less = r_bag - c_bag, c_bag - r_bag
    union = sum((c_bag | r_bag).values())
    similarity = 1.0 if union == 0 else round(sum((c_bag & r_bag).values()) / union, 4)
    c_loc = control.header("location") or ""
    r_loc = replay.header("location") or ""
    return Diff(
        control_status=control.status,
        replay_status=replay.status,
        control_location=redact_url(c_loc),
        replay_location=redact_url(r_loc),
        location_changed=c_loc != r_loc,
        control_type=_content_type(control),
        replay_type=_content_type(replay),
        similarity=similarity,
        body_same=not more and not less,
        added=_sample(r_list, more),
        removed=_sample(c_list, less),
        added_count=sum(more.values()),
        removed_count=sum(less.values()),
        truncated=control.truncated or replay.truncated or c_cut or r_cut,
    )


def same_page(diff: Diff, threshold: float = 0.9) -> bool:
    """True when two responses are the same page for practical purposes.
    Used to spot servers that return the same page for anything."""
    return not diff.status_changed and diff.similarity >= threshold
