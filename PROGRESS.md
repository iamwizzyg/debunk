# PROGRESS

## Project
debunk: a CLI that re-tests AI pentest agent findings and labels each one
CONFIRMED, UNCONFIRMED, INCONCLUSIVE or ERROR.
Repo: https://github.com/iamwizzyg/debunk (public, MIT)

## Decisions
- Name: debunk (free on PyPI and GitHub, checked 2026-11-26)
- Users: bug bounty hunters and solo pentesters first, CI reviewers second
- Agent: Strix v1.7.1 (strix_runs/<run>); strict validator, version-gated,
  fails loudly on shape mismatch
- Zero runtime dependencies (Python stdlib only); dev-only: pytest, ruff
- Read-only in v1: GET/HEAD only, no --allow-writes (writes are v0.2)
- Exit codes: 0 clean, 1 only unconfirmed, 2 any confirmed, 3 runtime error
- --fail-on unconfirmed for stricter CI gating; -q for quiet output
- SARIF is step 20 behind --sarif; does not block release (ship in 0.2 if broken)
- Tested only in GitHub Codespaces. iSH (32-bit x86, musl) is read-only.
- Layout: src/debunk/ package, tests/ folder, setuptools build backend
- Generic format: one JSON object {"schema_version": 1, "findings": [...]};
  required id/class/target; unknown fields rejected; request optional;
  one bad finding is reported, the rest still load
- Classes: xss_reflected, sqli_boolean, open_redirect, idor, auth_bypass,
  file_exposure
- HTTP engine is engine.py (not http.py, to avoid shadowing the stdlib).
  Backoff is fixed, no jitter, so runs are repeatable.
- Redirects followed manually (default on); checkers pass follow=False when
  they need to see the 3xx. Sensitive headers dropped on cross-host redirects.
- Scope guard is a callable passed to Engine; wired to --scope in step 21.
- baseline.py only builds requests (ProbeRequest); it never sends them.
  Control value is the fixed string dbnkctl7391 (deterministic).
- Missing request data: replay is built from target + parameter + payload.
- differ.py compares token bags (order-insensitive). It masks the probe value
  (raw, HTML-escaped, URL-encoded), CSRF/nonce input and meta values, and long
  hex ids or UUIDs before comparing.

## Done
- Step 1: questions answered
- Step 2: name chosen
- Step 3: repo created, LICENSE, .gitignore, SECURITY.md, PROGRESS.md
- Step 4: pyproject.toml, ruff config, `debunk --version` entry point
- Step 5: schema.py (dataclasses + strict validator) and tests
- Step 6: redact.py, engine.py (timeouts, retries, per-host limits) and tests
- Step 7: baseline.py (control/replay builder) and differ.py, with tests

## Next
- Step 8: checker interface + registry (also the runner: refetch CSRF token
  before replay, repeat 3 times, disagreement becomes INCONCLUSIVE)

## Known broken
- Nothing yet

## Known limits
- Timeout is per socket operation, not a total deadline per request
- System proxy settings are ignored on purpose
- Retry-After header is not honoured yet (fixed backoff only)
- Brotli responses are not decoded (we only ask for gzip/deflate)
- CSRF values are masked in diffs, but refetching a fresh token before
  replay is not built yet (step 8)
- Class-specific controls (other id, no auth) arrive with those checkers
- Cloudflare challenge pages are handled later (classifier)
- Diff is order-insensitive: reordered but identical content counts as same
