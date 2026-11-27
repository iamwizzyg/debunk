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
- Checkers live in src/debunk/checkers/. One subclass of Checker per class,
  registered with @register; each checker module is imported in
  checkers/__init__.py so it registers itself. Imports there are kept
  alphabetically sorted so ruff's import-order check (I001) never blocks.
- Context.send() refreshes CSRF/nonce values (query params and X-CSRF-style
  headers) by fetching the finding's target first, with the same headers.
  Only csrf/xsrf/nonce/authenticity/verification names; never auth tokens.
- Result helpers (confirmed/unconfirmed/inconclusive/error) redact secrets
  and cut every line to 300 characters.
- runner.py runs each check 3 times. All runs must agree; any disagreement,
  or an error mixed with a verdict, is INCONCLUSIVE. Out-of-scope, no-control
  and checker bugs stop at once with ERROR (no repeats).
- XSS checker (checkers/xss.py): sends GET only (HEAD has no body). CONFIRMED
  needs raw payload reflection plus NEW executable markup vs the control
  (a <script>, an on...= handler, or a javascript: URL) in an HTML response.
  Text-only contexts (comment, attribute value, textarea, title...) are
  UNCONFIRMED. Inside an existing <script>, firewall 403/406, 429/5xx,
  truncated body, or a CSP without 'unsafe-inline' are INCONCLUSIVE.
- Boolean SQLi checker (checkers/sqli.py): builds a "false" twin of the
  payload by flipping one recognised boolean pattern (quoted equality,
  numeric equality, or the TRUE keyword; only the first match is flipped).
  Sends true/false/control. CONFIRMED needs true != false AND false ~
  baseline. true == false is UNCONFIRMED. true != false but false !~
  baseline is INCONCLUSIVE (may be error-based SQLi or unrelated input
  handling). Known DB error text is extra evidence only, never decisive.
  A payload with no recognised pattern returns ERROR, not a guess.
- Open redirect checker (checkers/redirect.py): sends replay and control
  with follow=False. A redirect is a 3xx Location header or a meta refresh
  tag (attribute order independent). CONFIRMED needs the replay to redirect
  off-site to exactly the host the payload names, and the control not to
  redirect there. Payload with no explicit host, or naming the target's own
  host, is ERROR before any request is sent. Backslash-as-slash and
  protocol-relative (//host) tricks are recognised when reading the payload.
- IDOR checker (checkers/idor.py): compares the payload id against a
  made-up id in the same parameter (no "my own id" field exists in the
  generic schema). Made-up id not denied => INCONCLUSIVE (catch-all
  suspect). Made-up id denied, payload id also denied => UNCONFIRMED.
  Made-up id denied, payload id differs and is not denied => CONFIRMED.
  Denial = status in {401,403,404} or text like "access denied"/"forbidden"/
  "please log in". CONFIRMED here means access was granted to something
  that looked restricted -- it does not prove the data belongs to a
  different user (see Known limits).
- Auth bypass checker (checkers/auth.py): strips credentials (Authorization,
  Cookie, API-key headers, token/session/key-style query params) from the
  finding's own request, keeping its technique (extra header, path trick,
  method), and compares it against a bare request with no headers at all,
  both sent with follow=False. A redirect whose Location mentions
  login/signin/auth/sso also counts as denial. CONFIRMED needs the bare
  request denied and the stripped technique to get through. No request
  data on the finding is an ERROR; this checker has no parameter+payload
  fallback.
- File exposure checker (checkers/file_exposure.py): fetches the claimed
  file plus a nonexistent sibling path (catch-all probe). CONFIRMED needs a
  successful response matching a known sensitive-file signature (private
  key, .git internals, SQL dump, htpasswd, PHP DB config, AWS credentials,
  or an .env-style secret variable) while the catch-all probe does not
  match the same way. No payload/parameter needed; the target is the file
  itself. Non-2xx replay is UNCONFIRMED, not an error.
- Adapters live in src/debunk/adapters/. One subclass of Adapter per input
  format, registered with @register, same pattern as checkers (registry,
  alphabetical imports in adapters/__init__.py). Adapter.load(path) returns
  a schema.LoadResult. Adapters never send network requests; they only
  read from disk. Generic adapter (adapters/generic.py) is a thin wrapper
  around schema.load_file -- all parsing already happened in step 5.
- Strix adapter (adapters/strix.py): PROVISIONAL format, not yet confirmed
  against a real Strix v1.7.1 export (Strix's real shape is unconfirmed).
  Expects strix_runs/<run>/manifest.json with strix_version starting
  "1.7." and strix_runs/<run>/findings.json with {"findings": [...]}.
  CLASS_MAP translates Strix's vulnerability_type strings into debunk's
  classes; an unrecognised type is a per-entry error, not a crash. Any
  mismatch with real Strix output (wrong filenames, field names, or
  vocabulary) will raise a clear AdapterError naming what was expected --
  update CLASS_MAP/field names there once a real sample is available.
- Classifier (classifier.py): classify_run(findings, engine, load_errors,
  repeats, reg, detect_cloudflare) ties step-8's runner and step 5/16's
  FindingError together into one Report. FindingReport covers both a
  checked result and an unparsed (failed to load) finding, the latter
  always ERROR. Report.exit_code: 2 if any CONFIRMED, else 1 if any
  UNCONFIRMED, else 0 (exit code 3, a runtime crash, stays a CLI concern
  for step 21). Cloudflare challenge pages (cf-mitigated header, or
  403/503 with "Just a moment"/challenge-platform markers) are caught by
  wrapping the Engine each checker uses: a caught challenge raises
  CloudflareChallengeError (an HttpError), so it flows through the
  existing step-8 repeat logic unchanged -- a persistent challenge ends
  up ERROR with a clear reason, not a new verdict.
- Reporters live in src/debunk/reporters/. One subclass of Reporter per
  output format, registered with @register, same pattern as checkers and
  adapters. Reporter.render(report, quiet) -> str. Table reporter
  (reporters/table.py) is the default: one row per finding (verdict symbol
  + word, class, host/path, reason), wrapped to 80 columns including the
  summary line, 16-colour ANSI honouring NO_COLOR and non-TTY output, -q
  prints only the summary line (always shown, with per-verdict counts).
- JSON reporter (reporters/json_report.py): {"findings": [...], "summary":
  {...}}. Each finding is {id, class, target, verdict, reason, evidence,
  runs}; class/target are null for a finding that failed to load. Summary
  has per-verdict counts, total, and exit_code. quiet=True omits
  "findings". Verdicts serialize as plain strings. Output ends with one
  trailing newline; this reporter does not re-redact (that already
  happened in checkers/base.py).
- SARIF reporter (reporters/sarif.py): one run, one result per finding.
  ruleId is the vuln class or debunk/load-error (for a finding that
  failed to load). level: CONFIRMED->error, INCONCLUSIVE->warning,
  UNCONFIRMED->note, ERROR->none. locations.physicalLocation.uri is the
  target URL (SARIF allows any URI, not only repo-relative file paths;
  GitHub may not render a source line for a live URL). Evidence goes in
  properties.evidence, keeping message.text a short one-liner. Schema
  validation test (test_validates_against_the_official_sarif_schema)
  fetches the real SARIF 2.1.0 schema over HTTP and skips cleanly
  offline; it only proves conformance when run with network access
  (true in GitHub Actions and in a Codespace, not yet independently
  confirmed by me before handing this step over).
- CLI (cli.py): positional path is optional (nargs="?"); bare `debunk`
  prints help and exits 0. --format/--scope/--insecure/--concurrency/
  --delay/--timeout/--retries/--repeats wire straight into the adapter,
  scope guard, and HttpConfig built in earlier steps. --json/--sarif are
  mutually exclusive (argparse group); default output is the table.
  Exit-code policy: Report.exit_code (0/1/2) is unchanged from step 17;
  the CLI itself downgrades an unconfirmed-only run (code 1) to 0 unless
  --fail-on unconfirmed is passed, keeping that policy out of the
  classifier. SchemaError/AdapterError/ScopeError and any other
  exception are caught at the top level and reported as exit 3, never a
  raw traceback. scope.py: --scope FILE is one glob-per-line (# comments,
  blank lines ignored), matched against the request hostname via
  fnmatch; an out-of-scope request raises BlockedError in the engine
  (step 6), which the runner (step 8) already turns into ERROR.
- --show-secrets is accepted but not implemented: redaction happens
  unconditionally inside checkers/base.py (step 8) before a Result is
  ever built, so there is currently no unredacted path to reveal.
  Passing the flag prints one stderr notice and the run proceeds
  normally, redacted as always. Making this flag real would mean
  threading it through every checker; left for a later step.
- Fixture app (tests/fixtures/app.py): stdlib http.server, one route per
  vulnerability class -- /xss (reflects), /sqli (toy boolean-gated
  in-memory rows), /redirect (open redirect), /account?id=42 (IDOR:
  only id 42 exists), /admin (auth bypass: needs X-Debug: 1), /.env
  (static sensitive content). Runs standalone via `python -m
  tests.fixtures.app [port]` for manual poking. make_server(port=0)
  picks a free port; tests/test_fixture_app.py proves the fixture
  itself behaves correctly, independent of debunk.
- CI (.github/workflows/ci.yml): one job, Python 3.12, runs on every
  push and pull_request. Steps: checkout, setup-python, `pip install -e
  ".[dev]"`, `ruff check .`, `pytest -q`. The spec's "self-test against
  a local fixture server on every push" is satisfied by pytest itself,
  since tests/fixtures/app.py starts a real local server inside the
  test suite (test_fixture_app.py, and any future end-to-end test) --
  there is no separate CI step that starts the app and curls it by
  hand, since that would duplicate what the test suite already proves.
  ruff's known-first-party = ["debunk"] was added so it reliably tells
  `from debunk.x import y` apart from third-party imports, which is why
  nearly every I001 import-order fix earlier in this build needed a
  manual --fix. Because CI runs with normal internet access, the SARIF
  schema-validation test (step 20) that skips locally without network
  will actually run and assert in CI, not just pass vacuously.

## Done
- Step 1: questions answered
- Step 2: name chosen
- Step 3: repo created, LICENSE, .gitignore, SECURITY.md, PROGRESS.md
- Step 4: pyproject.toml, ruff config, `debunk --version` entry point
- Step 5: schema.py (dataclasses + strict validator) and tests
- Step 6: redact.py, engine.py (timeouts, retries, per-host limits) and tests
- Step 7: baseline.py (control/replay builder) and differ.py, with tests
- Step 8: csrf.py, checkers/base.py (verdicts, registry, Context), runner.py
- Step 9: checkers/xss.py (reflected XSS) and tests
- Step 10: checkers/sqli.py (boolean SQLi) and tests
- Step 11: checkers/redirect.py (open redirect) and tests
- Step 12: checkers/idor.py and tests
- Step 13: checkers/auth.py (auth bypass) and tests
- Step 14: checkers/file_exposure.py and tests -- all six v1 checkers done
- Step 15: adapters/base.py (Adapter, registry), adapters/generic.py, tests
- Step 16: adapters/strix.py (provisional format) and tests
- Step 17: classifier.py (Report, exit_code, Cloudflare detection) and tests
- Step 18: reporters/base.py, reporters/table.py (default output,
  summary line wraps too) and tests
- Step 19: reporters/json_report.py and tests
- Step 20: reporters/sarif.py (SARIF 2.1.0) and tests (dev dep:
  jsonschema, schema-validation test only)
- Step 21: cli.py rewritten (real adapter/engine/classifier/reporter
  wiring), scope.py, tests for both
- Step 22: tests/fixtures/app.py (one route per vulnerability class)
  and its own smoke tests
- Step 23: .github/workflows/ci.yml (ruff + pytest on push/PR;
  pytest already runs the fixture-app self-test since it's part of
  the suite); known-first-party added to ruff's isort config

## Next
- Step 24: README, CHANGELOG, CONTRIBUTING

## Known broken
- Nothing yet

## Known limits
- Timeout is per socket operation, not a total deadline per request
- System proxy settings are ignored on purpose
- Retry-After header is not honoured yet (fixed backoff only)
- Brotli responses are not decoded (we only ask for gzip/deflate)
- CSRF refresh costs one extra GET per request; Set-Cookie rotation during a
  refresh is not followed (the engine keeps no cookie jar)
- Catch-all detection (server says 200 to everything) is implemented per
  checker where needed (xss, redirect, idor, auth, file_exposure)
- Diff is order-insensitive: reordered but identical content counts as same
- XSS checker never runs JavaScript: CONFIRMED means executable markup was
  injected, not that a browser definitely ran it. DOM XSS, mutation XSS,
  stored XSS and payloads that break out of JS strings are out of scope
  (the last are INCONCLUSIVE).
- SQLi checker only recognises three boolean patterns and flips the first
  match; time-based, UNION-based and numeric-range payloads are not
  supported and return ERROR, not a false CONFIRMED or UNCONFIRMED.
- Open redirect checker compares hostname only (port and scheme ignored),
  and does not detect "scheme:host" bypasses with no slashes (e.g.
  https:evil.com) or JavaScript-driven redirects; these return ERROR or
  UNCONFIRMED rather than a false positive.
- IDOR checker cannot verify the returned content actually belongs to a
  different user, only that access to a seemingly restricted resource was
  granted. A WAF 403 on the payload id reads the same as a genuine
  authorization denial (UNCONFIRMED either way); the two are not
  distinguished.
- Auth bypass checker requires request data on the finding (no fallback);
  denial detection relies mostly on status for HEAD requests, since HEAD
  has no body to scan for denial text.
- File exposure checker relies on a fixed signature list; a sensitive file
  type not in the list (e.g. an unusual proprietary config format) returns
  UNCONFIRMED rather than CONFIRMED. Binary files (keystores, pickled data)
  are not checked for secrets, only text content.
- Strix adapter format (filenames, field names, vulnerability_type
  vocabulary) is a provisional best guess, UNCONFIRMED against a real
  Strix v1.7.1 export. A real sample's directory listing (file names, and
  one example finding with field names, with any secrets redacted) is the
  fastest way to correct this adapter if it rejects real Strix output.
- Cloudflare detection is a heuristic over English-language challenge
  text and one header; other anti-bot vendors (Akamai, Incapsula...) or a
  future Cloudflare page redesign are not recognised and would surface as
  an ordinary, less informative HttpError instead.
- Table reporter wraps on whitespace only; a reason with one very long
  unbreakable token (e.g. a long URL with no spaces) can still exceed 80
  columns on that line.
- --show-secrets has no effect yet (see Decisions); output is always
  redacted, with a one-line stderr notice when the flag is passed.
- argparse's own usage errors (bad flags, bad --format choice) exit with
  code 2, which is argparse's own convention and is unrelated to the
  report-based 0/1/2/3 exit-code scheme; a script checking $? should be
  aware the two 2's mean different things.
- The CLI always prints to stdout; there is no --output file flag yet
  (redirect the shell's stdout if you want a file).
- No progress indicator while a run is in flight; output only appears
  once the whole run finishes, which can feel slow on a large input.
