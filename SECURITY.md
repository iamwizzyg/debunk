# Security Policy

## Reporting a vulnerability in debunk

Please report security problems privately, not in a public issue.

Use GitHub's private reporting:
https://github.com/iamwizzyg/debunk/security/advisories/new

Include what you found, how to reproduce it, and the debunk version
(`debunk --version`). You will get a reply within 7 days.

## Supported versions

Only the latest released version gets security fixes.

## Safe use

debunk sends real HTTP requests to the targets you give it.

- Only test targets you own or have written permission to test.
- Use `--scope` to restrict which hosts debunk may contact.
- v1 is read-only: it sends GET and HEAD requests only.
- Cookies, Authorization headers and tokens are redacted from output
  unless you pass `--show-secrets`. Treat saved reports as sensitive anyway.
