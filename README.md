# debunk

Re-test AI pentest agent findings before you trust them.

AI pentest agents hallucinate findings. debunk takes their output, independently
replays each claimed vulnerability against the real target, and classifies it
CONFIRMED, UNCONFIRMED, INCONCLUSIVE, or ERROR -- so you know which findings
are worth your time before you submit, fix, or ignore them.

## Install

    pipx install debunk

or, inside a virtual environment:

    pip install debunk

## Example

    $ debunk /tmp/f.json
    [-] UNCONFIRMED xss_reflected  example.com/search   payload is not reflected in the response

    1 finding(s) -- [+] CONFIRMED: 0, [-] UNCONFIRMED: 1, [?] INCONCLUSIVE: 0, [!] ERROR: 0

## Usage

    debunk PATH [options]

      PATH                   findings file (--format generic) or run
                              directory (--format strix)

      --format {generic,strix}   input format (default: generic)
      --scope FILE           only contact hosts listed in FILE
      --insecure             skip TLS certificate checks (self-signed targets)
      --concurrency N        max simultaneous requests per host (default: 4)
      --delay SECONDS        delay between requests to one host (default: 0.25)
      --timeout SECONDS      per-request timeout (default: 15)
      --retries N            extra attempts on 429/5xx/network errors (default: 2)
      --repeats N            times to re-run each finding (default: 3)
      --json                 output JSON instead of the table
      --sarif                output SARIF 2.1.0 instead of the table
      --fail-on unconfirmed  also exit 1 when only UNCONFIRMED findings are present
      -q, --quiet            print only the summary line

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Clean, or only UNCONFIRMED findings (unless --fail-on unconfirmed) |
| 1    | Only UNCONFIRMED findings, with --fail-on unconfirmed |
| 2    | At least one CONFIRMED finding |
| 3    | debunk itself failed to run (bad input, scope error, etc.) |

### Vulnerability classes checked in v1

xss_reflected - sqli_boolean - open_redirect - idor - auth_bypass - file_exposure

v1 is read-only: every request is GET or HEAD. See SECURITY.md for safe-use
guidance and how to report a security issue in debunk itself.

## License

MIT -- see LICENSE.
