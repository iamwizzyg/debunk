import json

import pytest

from debunk.schema import SchemaError, load_file, load_findings


def good(**overrides):
    finding = {
        "id": "f1",
        "class": "xss_reflected",
        "target": "https://example.com/search",
    }
    finding.update(overrides)
    return finding


def doc(*findings, **top):
    data = {"schema_version": 1, "findings": list(findings)}
    data.update(top)
    return json.dumps(data)


def test_minimal_finding_loads():
    result = load_findings(doc(good()))
    assert result.errors == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.id == "f1"
    assert finding.vuln_class == "xss_reflected"
    assert finding.request is None


def test_full_finding_with_request_and_ipv6_target():
    full = good(
        target="http://[::1]:8080/s",
        title="t",
        parameter="q",
        payload="<b>",
        evidence="e",
        request={
            "method": "head",
            "url": "http://[::1]:8080/s?q=1",
            "headers": {"Cookie": "a=b"},
        },
    )
    result = load_findings(doc(full))
    assert result.errors == []
    request = result.findings[0].request
    assert request.method == "HEAD"
    assert request.headers == {"Cookie": "a=b"}


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"class": "rce"}, "unknown class"),
        ({"target": "ftp://example.com/x"}, "http:// or https://"),
        ({"target": "https://exa mple.com"}, "spaces"),
        ({"surprise": 1}, "unknown field"),
        ({"id": ""}, "id must be"),
        (
            {"request": {"method": "POST", "url": "https://example.com/"}},
            "read-only",
        ),
        (
            {
                "request": {
                    "url": "https://example.com/",
                    "headers": {"X": "a\r\nB: c"},
                }
            },
            "illegal",
        ),
        ({"request": "GET /"}, "must be an object"),
        ({"payload": 5}, "must be a string"),
    ],
)
def test_bad_finding_is_reported_not_raised(override, expected):
    result = load_findings(doc(good(**override)))
    assert result.findings == []
    assert len(result.errors) == 1
    assert expected in result.errors[0].message


def test_missing_required_fields_are_named():
    result = load_findings(doc({"id": "f1"}))
    assert "missing required" in result.errors[0].message
    assert "class" in result.errors[0].message


def test_one_bad_finding_does_not_block_the_good_ones():
    result = load_findings(
        doc(good(id="a"), good(id="b", **{"class": "nope"}), good(id="c"))
    )
    assert [f.id for f in result.findings] == ["a", "c"]
    assert result.errors[0].index == 2
    assert result.errors[0].finding_id == "b"
    assert "finding #2" in str(result.errors[0])


def test_duplicate_ids_are_reported():
    result = load_findings(doc(good(), good()))
    assert len(result.findings) == 1
    assert "duplicate" in result.errors[0].message


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("[]", "top level"),
        ("not json", "not valid JSON"),
        (doc(good(), schema_version=2), "unsupported schema_version"),
        (doc(good(), schema_version=True), "unsupported schema_version"),
        (doc(good(), extra=1), "unknown top-level"),
        (json.dumps({"schema_version": 1, "findings": {}}), "must be a list"),
    ],
)
def test_unusable_documents_raise_schema_error(text, expected):
    with pytest.raises(SchemaError, match=expected):
        load_findings(text)


def test_load_file_reads_utf8_with_bom(tmp_path):
    path = tmp_path / "f.json"
    path.write_bytes(b"\xef\xbb\xbf" + doc(good()).encode("utf-8"))
    assert len(load_file(str(path)).findings) == 1


def test_load_file_missing_file(tmp_path):
    with pytest.raises(SchemaError, match="cannot read"):
        load_file(str(tmp_path / "nope.json"))


def test_load_file_not_utf8(tmp_path):
    path = tmp_path / "f.json"
    path.write_bytes(b"\xff\xfe{}")
    with pytest.raises(SchemaError, match="not valid UTF-8"):
        load_file(str(path))
