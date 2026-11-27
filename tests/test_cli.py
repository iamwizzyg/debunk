import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from debunk.cli import main


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = b"<p>no reflection here</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def write_findings(tmp_path, target):
    data = {
        "schema_version": 1,
        "findings": [
            {
                "id": "f1",
                "class": "xss_reflected",
                "target": target,
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
            }
        ],
    }
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(data))
    return str(path)


def fast_args(*extra):
    # Keep the test suite quick: no delay, no retries, one repeat.
    return ["--delay", "0", "--retries", "0", "--repeats", "1", *extra]


def test_bare_invocation_prints_help_and_exits_zero(capsys):
    assert main([]) == 0
    assert "usage: debunk" in capsys.readouterr().out


def test_version_flag_still_works():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_missing_findings_file_is_a_runtime_error(capsys, tmp_path):
    missing = str(tmp_path / "nope.json")
    code = main(fast_args(missing))
    assert code == 3
    assert "debunk:" in capsys.readouterr().err


def test_unknown_format_is_rejected_by_argparse():
    with pytest.raises(SystemExit) as exc:
        main(["x", "--format", "bogus"])
    assert exc.value.code == 2


def test_table_output_by_default_is_lenient_on_unconfirmed(
    server, tmp_path, capsys
):
    findings = write_findings(tmp_path, f"{server.base}/search")
    code = main(fast_args(findings))
    out = capsys.readouterr().out
    assert code == 0
    assert "UNCONFIRMED" in out
    assert "xss_reflected" in out


def test_fail_on_unconfirmed_makes_the_same_run_exit_1(server, tmp_path):
    findings = write_findings(tmp_path, f"{server.base}/search")
    code = main(fast_args(findings, "--fail-on", "unconfirmed"))
    assert code == 1


def test_json_output_is_valid_and_has_a_summary(server, tmp_path, capsys):
    findings = write_findings(tmp_path, f"{server.base}/search")
    code = main(fast_args(findings, "--json"))
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["summary"]["UNCONFIRMED"] == 1
    assert data["findings"][0]["class"] == "xss_reflected"


def test_sarif_output_is_valid_json_with_schema_field(server, tmp_path, capsys):
    findings = write_findings(tmp_path, f"{server.base}/search")
    main(fast_args(findings, "--sarif"))
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "xss_reflected"


def test_quiet_flag_suppresses_the_finding_row(server, tmp_path, capsys):
    findings = write_findings(tmp_path, f"{server.base}/search")
    main(fast_args(findings, "-q"))
    out = capsys.readouterr().out
    assert "xss_reflected" not in out
    assert "finding(s)" in out


def test_scope_blocks_an_out_of_scope_host(tmp_path, capsys):
    findings = write_findings(tmp_path, "http://blocked.invalid/search")
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("allowed.example.com\n")
    code = main(fast_args(findings, "--scope", str(scope_file)))
    out = capsys.readouterr().out
    # Normalize whitespace: the table reporter wraps long reasons at 80
    # columns, so "out of scope" can be split by a line break + indent.
    collapsed = " ".join(out.split())
    assert code == 0  # ERROR alone does not fail the build
    assert "ERROR" in collapsed
    assert "out of scope" in collapsed


def test_missing_scope_file_is_a_runtime_error(tmp_path, capsys):
    findings = write_findings(tmp_path, "http://e.com/search")
    missing_scope = str(tmp_path / "no-scope.txt")
    code = main(fast_args(findings, "--scope", missing_scope))
    assert code == 3
    assert "cannot read" in capsys.readouterr().err


def test_show_secrets_prints_a_notice_but_still_runs(server, tmp_path, capsys):
    findings = write_findings(tmp_path, f"{server.base}/search")
    code = main(fast_args(findings, "--show-secrets"))
    captured = capsys.readouterr()
    assert code == 0
    assert "not implemented yet" in captured.err
    assert "UNCONFIRMED" in captured.out
