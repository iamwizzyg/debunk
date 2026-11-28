"""Command-line entry point for debunk."""

from __future__ import annotations

import argparse
import sys

import debunk.adapters  # noqa: F401  (registers adapters on import)
import debunk.checkers  # noqa: F401  (registers checkers on import)
import debunk.reporters  # noqa: F401  (registers reporters on import)
from debunk import __version__
from debunk.adapters.base import AdapterError
from debunk.adapters.base import registry as adapter_registry
from debunk.classifier import Report, classify_run
from debunk.engine import Engine, HttpConfig
from debunk.reporters.base import registry as reporter_registry
from debunk.runner import DEFAULT_REPEATS
from debunk.schema import SchemaError
from debunk.scope import ScopeError, load_scope, make_guard

_D = HttpConfig()  # default values, shown in --help


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="debunk",
        description="Re-test AI pentest agent findings before you trust them.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help=(
            "findings file (--format generic) or run directory "
            "(--format strix)"
        ),
    )
    parser.add_argument(
        "--format",
        choices=sorted(adapter_registry.names()),
        default="generic",
        help="input format (default: generic)",
    )
    parser.add_argument(
        "--scope",
        metavar="FILE",
        help="only contact hosts listed in FILE (one glob pattern per line)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS certificate checks (self-signed targets)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=_D.per_host,
        metavar="N",
        help=f"max simultaneous requests per host (default: {_D.per_host})",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=_D.delay,
        metavar="SECONDS",
        help=f"delay between requests to one host (default: {_D.delay})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=_D.timeout,
        metavar="SECONDS",
        help=f"per-request timeout (default: {_D.timeout})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=_D.retries,
        metavar="N",
        help=f"extra attempts on 429/5xx/network errors (default: {_D.retries})",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=DEFAULT_REPEATS,
        metavar="N",
        help=f"times to re-run each finding (default: {DEFAULT_REPEATS})",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", help="output JSON instead of the table"
    )
    output.add_argument(
        "--sarif", action="store_true", help="output SARIF instead of the table"
    )
    parser.add_argument(
        "--fail-on",
        choices=["unconfirmed"],
        default=None,
        help="also exit 1 when only UNCONFIRMED findings are present",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="print only the summary line"
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="(not implemented yet) output is always redacted in this version",
    )
    parser.add_argument(
        "--version", action="version", version=f"debunk {__version__}"
    )
    return parser


def _select_reporter(args: argparse.Namespace):
    if args.sarif:
        return reporter_registry.get("sarif")
    if args.json:
        return reporter_registry.get("json")
    return reporter_registry.get("table")


def _run(args: argparse.Namespace) -> Report:
    guard = make_guard(load_scope(args.scope)) if args.scope else None
    adapter = adapter_registry.get(args.format)
    load_result = adapter.load(args.path)
    config = HttpConfig(
        timeout=args.timeout,
        delay=args.delay,
        per_host=args.concurrency,
        retries=args.retries,
        insecure=args.insecure,
    )
    engine = Engine(config, guard=guard)
    return classify_run(
        load_result.findings, engine, load_result.errors, repeats=args.repeats
    )


def _effective_exit_code(report: Report, fail_on: str | None) -> int:
    """CLI-level policy on top of Report.exit_code: by default, a run with
    only UNCONFIRMED findings exits 0 (nothing of note for a human to act
    on). --fail-on unconfirmed restores the stricter 0/1/2 scheme."""
    code = report.exit_code
    if code == 1 and fail_on != "unconfirmed":
        return 0
    return code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.path is None:
        parser.print_help()
        return 0
    if args.show_secrets:
        print(
            "debunk: --show-secrets is not implemented yet; output is "
            "always redacted in this version.",
            file=sys.stderr,
        )
    try:
        report = _run(args)
    except (SchemaError, AdapterError, ScopeError) as exc:
        print(f"debunk: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # last resort: never crash with a traceback
        kind = type(exc).__name__
        print(f"debunk: unexpected error: {kind}: {exc}", file=sys.stderr)
        return 3
    reporter = _select_reporter(args)
    output = reporter.render(report, quiet=args.quiet)
    print(output, end="")
    return _effective_exit_code(report, args.fail_on)
