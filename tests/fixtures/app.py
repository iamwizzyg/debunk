"""A small local app covering debunk's six v1 vulnerability classes.

Stdlib only (http.server), so it needs no extra dependency. Used by the
end-to-end tests in this file's siblings and reused by CI as a self-test
target (step 23). Can also run standalone for manual poking:

    python -m tests.fixtures.app [port]
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# Toy "database": id -> row owner and content. Only "42" is a real,
# accessible account; any other id is denied, proving IDOR.
_ACCOUNTS = {"42": "Invoice #42 for Example Corp, balance due $500"}

_ENV_FILE = "DB_PASSWORD=hunter2\nAPI_SECRET=s3cr3t_token_abc123\n"


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output quiet
        pass

    # -- helpers --------------------------------------------------------
    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "text/html; charset=utf-8")
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _query(self) -> dict[str, str]:
        parts = urlsplit(self.path)
        return {k: v[0] for k, v in parse_qs(parts.query).items()}

    # -- routes -----------------------------------------------------------
    def _xss(self, q: dict[str, str]) -> None:
        value = q.get("q", "")
        self._send(200, f"<html><body>You searched for: {value}</body></html>")

    def _sqli(self, q: dict[str, str]) -> None:
        condition = q.get("id", "")
        # A toy interpreter: only recognises simple ' OR '1'='1 style
        # boolean tautologies/falsities, enough for the SQLi checker.
        if "1'='1" in condition or "1=1" in condition:
            rows = "<li>Alice</li><li>Bob</li><li>Carol</li>"
        elif "1'='2" in condition or "1=2" in condition:
            rows = ""
        elif condition.isdigit():
            rows = "<li>Alice</li>" if condition == "1" else ""
        else:
            rows = ""
        self._send(200, f"<html><body><ul>{rows}</ul></body></html>")

    def _redirect(self, q: dict[str, str]) -> None:
        target = q.get("next", "/")
        self._send(302, "", {"Location": target})

    def _account(self, q: dict[str, str]) -> None:
        account_id = q.get("id", "")
        row = _ACCOUNTS.get(account_id)
        if row is None:
            self._send(404, "<html><body>Account not found</body></html>")
        else:
            self._send(200, f"<html><body>{row}</body></html>")

    def _admin(self) -> None:
        if self.headers.get("X-Debug") == "1":
            self._send(200, "<html><body>Welcome, admin panel</body></html>")
        else:
            self._send(403, "<html><body>Forbidden: admin only</body></html>")

    def _env_file(self) -> None:
        self._send(200, _ENV_FILE, {"Content-Type": "text/plain"})

    _ROUTES = {
        "/xss": lambda self, q: self._xss(q),
        "/sqli": lambda self, q: self._sqli(q),
        "/redirect": lambda self, q: self._redirect(q),
        "/account": lambda self, q: self._account(q),
    }
    _NO_QUERY_ROUTES = {
        "/admin": lambda self: self._admin(),
        "/.env": lambda self: self._env_file(),
    }

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in self._ROUTES:
            self._ROUTES[path](self, self._query())
        elif path in self._NO_QUERY_ROUTES:
            self._NO_QUERY_ROUTES[path](self)
        else:
            self._send(404, "<html><body>Not found</body></html>")

    do_HEAD = do_GET


def make_server(port: int = 0) -> ThreadingHTTPServer:
    """Build (but do not start) a fixture server on 127.0.0.1:port.
    port=0 picks a free port, available as server.server_address[1]."""
    return ThreadingHTTPServer(("127.0.0.1", port), FixtureHandler)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    port = int(argv[0]) if argv else 8765
    server = make_server(port)
    host, bound_port = server.server_address
    print(f"debunk fixture app listening on http://{host}:{bound_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
