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

## Done
- Step 1: questions answered
- Step 2: name chosen
- Step 3: repo created, LICENSE, .gitignore, SECURITY.md, PROGRESS.md
- Step 4: pyproject.toml, ruff config, `debunk --version` entry point
- Step 5: schema.py (dataclasses + strict validator) and tests

## Next
- Step 6: HTTP engine (timeouts, retries, limits, redaction)

## Known broken
- Nothing yet
