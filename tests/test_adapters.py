import json

import pytest

from debunk.adapters.base import Adapter, AdapterRegistry
from debunk.adapters.generic import GenericAdapter
from debunk.schema import SchemaError


def doc(*findings, **top):
    data = {"schema_version": 1, "findings": list(findings)}
    data.update(top)
    return json.dumps(data)


def finding(**overrides):
    base = {
        "id": "f1",
        "class": "xss_reflected",
        "target": "https://example.com/search",
    }
    base.update(overrides)
    return base


def test_generic_adapter_is_registered_by_name():
    from debunk.adapters.base import registry

    assert isinstance(registry.get("generic"), GenericAdapter)
    assert "generic" in registry.names()


def test_adapter_base_class_is_abstract():
    with pytest.raises(TypeError):
        Adapter()


def test_registry_rejects_duplicate_and_unnamed():
    class A(Adapter):
        name = "dup"

        def load(self, path):
            raise NotImplementedError

    class Unnamed(Adapter):
        def load(self, path):
            raise NotImplementedError

    reg = AdapterRegistry()
    reg.register(A)
    with pytest.raises(ValueError, match="already registered"):
        reg.register(A)
    with pytest.raises(ValueError, match="must set a non-empty name"):
        reg.register(Unnamed)


def test_generic_adapter_reads_a_real_file(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(doc(finding(id="a"), finding(id="b")))
    result = GenericAdapter().load(str(path))
    assert result.errors == []
    assert [f.id for f in result.findings] == ["a", "b"]


def test_generic_adapter_reports_one_bad_finding_without_losing_the_rest(tmp_path):
    path = tmp_path / "findings.json"
    bad = finding(id="bad", **{"class": "not-a-real-class"})
    path.write_text(doc(finding(id="a"), bad, finding(id="c")))
    result = GenericAdapter().load(str(path))
    assert [f.id for f in result.findings] == ["a", "c"]
    assert len(result.errors) == 1
    assert result.errors[0].finding_id == "bad"


def test_generic_adapter_raises_schema_error_for_malformed_file(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text("not json at all")
    with pytest.raises(SchemaError, match="not valid JSON"):
        GenericAdapter().load(str(path))


def test_generic_adapter_raises_schema_error_for_missing_file(tmp_path):
    with pytest.raises(SchemaError, match="cannot read"):
        GenericAdapter().load(str(tmp_path / "nope.json"))
