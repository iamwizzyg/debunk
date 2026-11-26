"""Command-line entry point for debunk."""

from __future__ import annotations

import argparse

from debunk import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="debunk",
        description="Re-test AI pentest agent findings before you trust them.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"debunk {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
