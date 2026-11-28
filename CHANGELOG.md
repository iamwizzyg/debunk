# Changelog

All notable changes to this project are documented here.
Format follows Keep a Changelog (https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Finding schema (schema_version: 1) with a strict validator: unknown
  fields rejected, one bad finding reported without blocking the rest.
- Read-only HTTP engine: timeouts, retries with fixed backoff, per-host
  concurrency and delay limits, redirect handling, gzip/deflate decoding.
- Secret redaction applied to every checker result before it is shown.
- Baseline/control request builder and a response differ used across checkers.
- CSRF/nonce token refresh before replaying a request that carries one.
- Six vulnerability checkers: reflected XSS, boolean-based SQL injection,
  open redirect, IDOR, authentication/authorization bypass, and sensitive
  file exposure.
- Repeat-and-compare runner: a finding is checked multiple times, and any
  disagreement between runs becomes INCONCLUSIVE rather than CONFIRMED.
- Cloudflare challenge-page detection, so a JS interstitial is never
  mistaken for the real target response.
- Generic JSON input adapter and a provisional Strix run-directory adapter.
- Table (default), JSON, and SARIF 2.1.0 output reporters.
- Full CLI: --format, --scope, --insecure, --concurrency, --delay,
  --timeout, --retries, --repeats, --json, --sarif,
  --fail-on unconfirmed, -q.
- Scope enforcement via --scope FILE (one glob pattern per line).
- A local fixture app covering all six vulnerability classes, used in tests.
- GitHub Actions CI: lint (ruff) and test (pytest) on every push and PR.

### Known limits
See the "Known limits" section of PROGRESS.md for the full, current list.
