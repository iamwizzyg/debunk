import json

import pytest

from debunk.adapters.base import AdapterError, registry
from debunk.adapters.strix import StrixAdapter


def write(path, name, data):
    (path / name).write_text(json.dumps(data))


def manifest(version="1.7.1"):
    return {"strix_version": version}


def entry(**overrides):
    base = {
        "id": "f1",
        "vulnerability_type": "reflected_xss",
        "target_url": "https://example.com/search",
    }
    base.update(overrides)
    return base


def make_run(tmp_path, items, version="1.7.1", findings_extra=None):
    write(tmp_path, "manifest.json", manifest(version))
    data = {"findings": items}
    if findings_extra:
        data.update(findings_extra)
    write(tmp_path, "findings.json", data)
    return tmp_path


def test_checker_is_registered():
    assert isinstance(registry.get("strix"), StrixAdapter)
    assert "strix" in registry.names()


def test_loads_a_valid_run_and_maps_vulnerability_types(tmp_path):
    items = [
        entry(id="a", vulnerability_type="reflected_xss"),
        entry(
            id="b", vulnerability_type="sql_injection", target_url="https://e.com/s"
        ),
        entry(
            id="c",
            vulnerability_type="idor",
            target_url="https://e.com/invoice",
            request={"method": "get", "url": "https://e.com/invoice?id=42"},
        ),
    ]
    run = make_run(tmp_path, items)
    result = StrixAdapter().load(str(run))
    assert result.errors == []
    classes = {f.id: f.vuln_class for f in result.findings}
    assert classes == {"a": "xss_reflected", "b": "sqli_boolean", "c": "idor"}
    assert result.findings[2].request.method == "GET"


def test_unsupported_version_raises(tmp_path):
    run = make_run(tmp_path, [entry()], version="2.0.0")
    with pytest.raises(AdapterError, match="unsupported strix_version"):
        StrixAdapter().load(str(run))


def test_missing_manifest_raises(tmp_path):
    write(tmp_path, "findings.json", {"findings": [entry()]})
    with pytest.raises(AdapterError, match="expected a Strix manifest"):
        StrixAdapter().load(str(tmp_path))


def test_missing_findings_file_raises(tmp_path):
    write(tmp_path, "manifest.json", manifest())
    with pytest.raises(AdapterError, match="expected Strix findings"):
        StrixAdapter().load(str(tmp_path))


def test_findings_file_missing_findings_key_raises(tmp_path):
    write(tmp_path, "manifest.json", manifest())
    write(tmp_path, "findings.json", {"notfindings": []})
    with pytest.raises(AdapterError, match='"findings" list'):
        StrixAdapter().load(str(tmp_path))


def test_findings_file_not_an_object_raises(tmp_path):
    write(tmp_path, "manifest.json", manifest())
    write(tmp_path, "findings.json", [entry()])
    with pytest.raises(AdapterError, match="must contain a JSON object"):
        StrixAdapter().load(str(tmp_path))


def test_unknown_top_level_field_in_findings_file_raises(tmp_path):
    run = make_run(tmp_path, [entry()], findings_extra={"extra": 1})
    with pytest.raises(AdapterError, match="unknown field"):
        StrixAdapter().load(str(run))


def test_path_not_a_directory_raises(tmp_path):
    missing = tmp_path / "nope"
    with pytest.raises(AdapterError, match="not a Strix run directory"):
        StrixAdapter().load(str(missing))


def test_bad_findings_are_reported_without_blocking_the_others(tmp_path):
    items = [
        entry(id="a"),
        entry(id="bad-type", vulnerability_type="time_based_sqli"),
        {"id": "missing-fields"},
        entry(id="c"),
    ]
    run = make_run(tmp_path, items)
    result = StrixAdapter().load(str(run))
    assert [f.id for f in result.findings] == ["a", "c"]
    assert len(result.errors) == 2
    assert result.errors[0].index == 2
    assert "unrecognised vulnerability_type" in result.errors[0].message
    assert result.errors[1].index == 3
    assert "missing required field" in result.errors[1].message


def test_duplicate_ids_are_reported(tmp_path):
    run = make_run(tmp_path, [entry(id="a"), entry(id="a")])
    result = StrixAdapter().load(str(run))
    assert len(result.findings) == 1
    assert "duplicate" in result.errors[0].message


def test_write_request_is_rejected(tmp_path):
    items = [
        entry(request={"method": "POST", "url": "https://example.com/search"})
    ]
    run = make_run(tmp_path, items)
    result = StrixAdapter().load(str(run))
    assert result.findings == []
    assert "read-only" in result.errors[0].message


def test_manifest_not_valid_json_raises(tmp_path):
    (tmp_path / "manifest.json").write_text("not json")
    write(tmp_path, "findings.json", {"findings": []})
    with pytest.raises(AdapterError, match="not valid JSON"):
        StrixAdapter().load(str(tmp_path))
