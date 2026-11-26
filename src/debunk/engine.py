"""Polite, read-only HTTP client built on the standard library.

Rules baked in: GET/HEAD only, per-host concurrency cap, per-host delay,
timeouts, retries with fixed (non-random) backoff on 429/5xx and network
errors, a response size cap, gzip/deflate decoding, and manual redirect
following so every hop can be checked against the scope guard.
"""

from __future__ import annotations

import http.client
import ssl
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from urllib.parse import quote, urljoin, urlsplit

from debunk import __version__
from debunk.redact import SENSITIVE_HEADERS, redact_headers, redact_url
from debunk.schema import ALLOWED_METHODS

_REDIRECT_CODES = (301, 302, 303, 307, 308)
_PATH_SAFE = "/%:@!$&'()*+,;=-._~?[]"


class HttpError(Exception):
    """A request failed for a network or protocol reason."""


class ReadOnlyError(HttpError):
    """A non-GET/HEAD request was attempted."""


class BlockedError(HttpError):
    """The scope guard refused this URL."""


@dataclass(frozen=True)
class HttpConfig:
    timeout: float = 15.0  # seconds per socket operation
    delay: float = 0.25  # minimum gap between request starts, per host
    per_host: int = 4  # max simultaneous requests per host
    retries: int = 2  # extra attempts after the first
    backoff: float = 0.5  # wait backoff * 2**n seconds between attempts
    max_body: int = 1_048_576  # bytes kept per response
    max_redirects: int = 5
    follow_redirects: bool = True
    insecure: bool = False  # skip TLS certificate checks (self-signed targets)
    user_agent: str = f"debunk/{__version__}"


@dataclass(frozen=True)
class Response:
    url: str  # final URL after any redirects
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    text: str
    truncated: bool = False
    redirects: tuple[tuple[int, str], ...] = ()  # (status, url that redirected)
    attempts: int = 1

    def header(self, name: str) -> str | None:
        return _header(self.headers, name)

    def safe_headers(self) -> list[tuple[str, str]]:
        return redact_headers(self.headers)

    def safe_url(self) -> str:
        return redact_url(self.url)


def _header(pairs: tuple[tuple[str, str], ...], name: str) -> str | None:
    low = name.lower()
    for key, value in pairs:
        if key.lower() == low:
            return value
    return None


def _decompress(body: bytes, encoding: str, limit: int) -> bytes:
    enc = encoding.strip().lower()
    if enc in ("gzip", "x-gzip"):
        options = [16 + zlib.MAX_WBITS]
    elif enc == "deflate":
        options = [zlib.MAX_WBITS, -zlib.MAX_WBITS]
    else:
        return body
    for wbits in options:
        try:
            return zlib.decompressobj(wbits).decompress(body, limit + 1)
        except zlib.error:
            continue
    raise HttpError(f"could not decode {enc} response body")


def _decode_text(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    for piece in content_type.split(";")[1:]:
        name, _, value = piece.strip().partition("=")
        if name.lower() == "charset" and value:
            charset = value.strip().strip("\"'")
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


class Engine:
    def __init__(
        self,
        config: HttpConfig | None = None,
        guard: Callable[[str], bool] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config or HttpConfig()
        self._guard = guard  # returns True when a URL is allowed
        self._sleep = sleep
        self._clock = clock
        self._lock = threading.Lock()
        self._gates: dict[str, threading.BoundedSemaphore] = {}
        self._next_ok: dict[str, float] = {}
        self._ctx = ssl.create_default_context()
        if self.config.insecure:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        follow: bool | None = None,
    ) -> Response:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ReadOnlyError(f"{method} is not allowed: debunk v1 is read-only")
        follow = self.config.follow_redirects if follow is None else follow
        sent = dict(headers or {})
        hops: list[tuple[int, str]] = []
        current = url
        while True:
            self._check(current)
            resp = self._with_retries(method, current, sent)
            location = resp.header("location")
            if not follow or resp.status not in _REDIRECT_CODES or not location:
                return replace(resp, redirects=tuple(hops))
            hops.append((resp.status, current))
            if len(hops) > self.config.max_redirects:
                raise HttpError(f"more than {self.config.max_redirects} redirects")
            target = urljoin(current, location)
            if urlsplit(target).hostname != urlsplit(current).hostname:
                sent = {
                    k: v for k, v in sent.items() if k.lower() not in SENSITIVE_HEADERS
                }
            current = target

    def _check(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            host = parts.hostname
            _ = parts.port
        except ValueError as exc:
            raise HttpError(f"bad URL: {exc}") from exc
        if parts.scheme not in ("http", "https") or not host:
            raise HttpError(f"unsupported URL: {redact_url(url)}")
        if self._guard is not None and not self._guard(url):
            raise BlockedError(f"{host} is out of scope; refusing to connect")

    def _with_retries(
        self, method: str, url: str, headers: dict[str, str]
    ) -> Response:
        cfg = self.config
        last_resp: Response | None = None
        last_error: Exception | None = None
        for attempt in range(cfg.retries + 1):
            if attempt:
                self._sleep(cfg.backoff * 2 ** (attempt - 1))
            try:
                resp = self._send(method, url, headers)
            except ssl.SSLCertVerificationError as exc:
                raise HttpError(
                    f"TLS certificate check failed: {exc.verify_message} "
                    "(self-signed target? try --insecure)"
                ) from exc
            except UnicodeError as exc:
                raise HttpError(f"request has unsendable characters: {exc}") from exc
            except (OSError, http.client.HTTPException) as exc:
                last_error = exc
                continue
            if resp.status != 429 and resp.status < 500:
                return replace(resp, attempts=attempt + 1)
            last_resp = resp
        if last_resp is not None:
            return replace(last_resp, attempts=cfg.retries + 1)
        raise HttpError(
            f"{redact_url(url)} failed after {cfg.retries + 1} attempt(s): "
            f"{last_error}"
        )

    def _send(self, method: str, url: str, headers: dict[str, str]) -> Response:
        cfg = self.config
        parts = urlsplit(url)
        host = parts.hostname or ""
        target = quote(parts.path or "/", safe=_PATH_SAFE)
        if parts.query:
            target += "?" + quote(parts.query, safe=_PATH_SAFE)

        merged = {
            "user-agent": ("User-Agent", cfg.user_agent),
            "accept": ("Accept", "*/*"),
            "accept-encoding": ("Accept-Encoding", "gzip, deflate"),
        }
        for name, value in headers.items():
            merged[name.lower()] = (name, value)
        wire = dict(merged.values())

        if parts.scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                host, parts.port, timeout=cfg.timeout, context=self._ctx
            )
        else:
            conn = http.client.HTTPConnection(host, parts.port, timeout=cfg.timeout)

        gate = self._gate(host)
        gate.acquire()
        try:
            self._pace(host)
            conn.request(method, target, headers=wire)
            reply = conn.getresponse()
            raw = reply.read(cfg.max_body + 1)
            status = reply.status
            pairs = tuple(reply.getheaders())
        finally:
            conn.close()
            gate.release()

        truncated = len(raw) > cfg.max_body
        encoding = _header(pairs, "content-encoding") or ""
        body = _decompress(raw[: cfg.max_body], encoding, cfg.max_body)
        if len(body) > cfg.max_body:
            truncated = True
            body = body[: cfg.max_body]
        text = _decode_text(body, _header(pairs, "content-type") or "")
        return Response(url, status, pairs, body, text, truncated)

    def _gate(self, host: str) -> threading.BoundedSemaphore:
        with self._lock:
            gate = self._gates.get(host)
            if gate is None:
                gate = threading.BoundedSemaphore(self.config.per_host)
                self._gates[host] = gate
            return gate

    def _pace(self, host: str) -> None:
        with self._lock:
            now = self._clock()
            ready = max(now, self._next_ok.get(host, 0.0))
            self._next_ok[host] = ready + self.config.delay
        if ready > now:
            self._sleep(ready - now)
