import json

import pytest

from debunk.checkers.base import Verdict
from debunk.classifier import FindingReport, Report
from debunk.reporters.base import registry
from debunk.reporters.sarif import LOAD_ERROR_RULE, SCHEMA_URI, SarifReporter


def finding(**kw):
    base = {
        "id": "f1",
        "vuln_class": "xss_reflected",
        "target": "https://example.com/search",
        "verdict": Verdict.CONFIRMED,
        "reason": "payload reflected unencoded",
        "evidence": ("new <script> element",),
        "runs": 3,
    }
    base.update(kw)
    return FindingReport(**base)


def render(report):
    return json.loads(SarifReporter().render(report))


def test_reporter_is_registered():
    assert isinstance(registry.get("sarif"), SarifReporter)


def test_top_level_shape():
    data = render(Report(()))
    assert data["$schema"] == SCHEMA_URI
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "debunk"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert "xss_reflected" in rule_ids
    assert LOAD_ERROR_RULE in rule_ids


@pytest.mark.parametrize(
    ("verdict", "level"),
    [
        (Verdict.CONFIRMED, "error"),
        (Verdict.INCONCLUSIVE, "warning"),
        (Verdict.UNCONFIRMED, "note"),
        (Verdict.ERROR, "none"),
    ],
)
def test_verdict_maps_to_sarif_level(verdict, level):
    data = render(Report((finding(verdict=verdict),)))
    assert data["runs"][0]["results"][0]["level"] == level


def test_result_has_rule_message_location_and_properties():
    data = render(Report((finding(),)))
    result = data["runs"][0]["results"][0]
    assert result["ruleId"] == "xss_reflected"
    assert result["message"]["text"] == "payload reflected unencoded"
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://example.com/search"
    assert result["properties"]["debunkVerdict"] == "CONFIRMED"
    assert result["properties"]["debunkFindingId"] == "f1"
    assert result["properties"]["debunkRuns"] == 3
    assert result["properties"]["evidence"] == ["new <script> element"]


def test_unparsed_finding_uses_load_error_rule_and_has_no_location():
    err_finding = FindingReport(
        id="bad1",
        vuln_class="",
        target="",
        verdict=Verdict.ERROR,
        reason="could not load finding: unknown class",
    )
    data = render(Report((), (err_finding,)))
    result = data["runs"][0]["results"][0]
    assert result["ruleId"] == LOAD_ERROR_RULE
    assert "locations" not in result
    assert result["level"] == "none"


def test_empty_report_has_no_results_but_keeps_rules():
    data = render(Report(()))
    assert data["runs"][0]["results"] == []
    assert len(data["runs"][0]["tool"]["driver"]["rules"]) >= 7


def test_output_is_valid_json_with_trailing_newline():
    out = SarifReporter().render(Report((finding(),)))
    assert out.endswith("\n")
    json.loads(out)  # must not raise


def test_validates_against_the_official_sarif_schema():
    jsonschema = pytest.importorskip("jsonschema")
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(SCHEMA_URI, timeout=10) as resp:
            schema = json.load(resp)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        pytest.skip(f"no network access to fetch the SARIF schema: {exc}")

    data = render(
        Report((finding(), finding(id="f2", verdict=Verdict.UNCONFIRMED)))
    )
    jsonschema.validate(instance=data, schema=schema)
