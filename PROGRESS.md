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

## Next
- Step 15: generic adapter

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
  checker where needed (xss, redirect, idor, auth, file_exposure);
  Cloudflare challenge pages are handled later (classifier)
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

## Next up, by design
All six v1 vulnerability classes now have a checker. Steps 15-17 give
debunk ways to load real findings (Strix adapter) and report the results
(table, JSON, SARIF); step 21 wires scope enforcement and --insecure into
the CLI and connects everything built so far into one working `debunk` run.
