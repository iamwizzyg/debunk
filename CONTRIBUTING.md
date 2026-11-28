# Contributing to debunk

## Setup

    git clone https://github.com/iamwizzyg/debunk
    cd debunk
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -e ".[dev]"

debunk has zero runtime dependencies -- please keep it that way; a new
runtime dependency needs a strong justification in the PR description.

## Running checks locally

    ruff check .
    pytest -q

Both must pass before a PR is merged.

## Project layout and conventions

- src/debunk/checkers/ -- one file per vulnerability class. Subclass
  Checker, set vuln_class, implement check(finding, ctx) -> Result,
  decorate with @register. Add the import to checkers/__init__.py
  alphabetically.
- src/debunk/adapters/ -- one file per input format, same @register
  pattern (Adapter, name, load(path) -> LoadResult).
- src/debunk/reporters/ -- one file per output format, same pattern
  (Reporter, name, render(report, quiet) -> str).
- A checker should fail toward INCONCLUSIVE or ERROR, never a guessed
  CONFIRMED, when evidence is ambiguous.
- Tests use the fixture app in tests/fixtures/app.py or a small fake
  server/engine -- no test should make a real network request.

## Pull requests

- Include tests for anything you add or fix.
- Keep files under 300 lines.
- Update PROGRESS.md's "Known limits" if your change affects one.

## Reporting a security issue

See SECURITY.md.
