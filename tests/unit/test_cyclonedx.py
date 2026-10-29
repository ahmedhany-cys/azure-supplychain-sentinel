import json

from sentinel.core.models import Component
from sentinel.sbom import cyclonedx
from sentinel.sbom.builder import build_sbom, load_sbom

from ..conftest import EXAMPLES

BASELINE = EXAMPLES / "03-dependency-drift" / "baseline.cdx.json"


def _minimal(**extra):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
    doc.update(extra)
    return doc


def test_native_sbom_is_schema_valid_and_round_trips():
    comps = [
        Component(
            name="requests",
            version="2.25.1",
            ecosystem="PyPI",
            purl="pkg:pypi/requests@2.25.1",
            scope="direct",
        ),
        Component(
            name="urllib3",
            version="1.26.4",
            ecosystem="PyPI",
            purl="pkg:pypi/urllib3@1.26.4",
            scope="transitive",
            introduced_via=["requests"],
        ),
    ]
    doc = cyclonedx.build_native(comps, "svc")
    result = cyclonedx.validate(json.dumps(doc))
    assert result.valid and result.schema_valid, result.errors
    parsed = {c.name: c for c in cyclonedx.parse_components(doc)}
    assert parsed["requests"].scope == "direct"
    assert parsed["urllib3"].introduced_via == ["requests"]
    assert parsed["urllib3"].ecosystem == "PyPI"


def test_syft_generated_sbom_parses_with_ecosystems_and_scope():
    build = load_sbom(BASELINE.read_bytes())
    assert build.inventory.sbom.validation.valid
    assert build.inventory.sbom.generator == "syft"
    comps = {c.name: c for c in build.inventory.components}
    assert comps["debug"].ecosystem == "npm"
    assert comps["debug"].scope == "direct"
    assert comps["ms"].scope == "transitive"
    assert "notification-service" not in comps


def test_schema_violation_is_reported():
    doc = _minimal(components=[{"name": "x"}])  # 'type' is required
    result = cyclonedx.validate(json.dumps(doc))
    assert not result.valid
    assert result.schema_valid is False
    assert any("schema" in e for e in result.errors)


def test_not_cyclonedx_and_not_json():
    assert not cyclonedx.validate('{"spdxVersion": "SPDX-2.3"}').valid
    assert "not valid JSON" in cyclonedx.validate("{oops").errors[0]
    assert not cyclonedx.validate(json.dumps(_minimal(specVersion="0.9"))).valid


def test_semantic_checks_duplicate_refs_and_dangling_dependencies():
    doc = _minimal(
        components=[
            {"type": "library", "name": "a", "version": "1", "bom-ref": "r1"},
            {"type": "library", "name": "b", "version": "1", "bom-ref": "r1"},
        ],
        dependencies=[{"ref": "r1", "dependsOn": ["missing"]}],
    )
    errors = cyclonedx.validate(json.dumps(doc)).errors
    assert any("duplicate bom-ref" in e for e in errors)
    assert any("unknown bom-ref" in e for e in errors)


def test_missing_version_and_purl_are_warnings():
    doc = _minimal(components=[{"type": "library", "name": "a", "bom-ref": "a"}])
    result = cyclonedx.validate(json.dumps(doc))
    assert result.valid
    assert any("no version" in w for w in result.warnings)


def test_enrich_only_matches_exact_versions():
    doc = _minimal(
        components=[
            {
                "type": "library",
                "name": "requests",
                "version": "2.25.1",
                "purl": "pkg:pypi/requests@2.25.1",
            },
            {"type": "library", "name": "idna", "version": "3.0", "purl": "pkg:pypi/idna@3.0"},
        ]
    )
    native = [
        Component(name="requests", version="2.25.1", ecosystem="PyPI", scope="direct"),
        Component(name="idna", version="2.10", ecosystem="PyPI", scope="transitive"),
    ]
    assert cyclonedx.enrich(doc, native) == 1
    parsed = {c.name: c for c in cyclonedx.parse_components(doc)}
    assert parsed["requests"].scope == "direct"
    assert parsed["idna"].scope == "unknown"


def test_adopt_root_component_and_strip_paths():
    doc = _minimal(
        metadata={"component": {"type": "file", "name": "/home/user/src/app", "bom-ref": "x"}},
        components=[
            {"type": "library", "name": "app", "version": "1.0", "purl": "pkg:npm/app@1.0"},
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
            },
            {"type": "file", "name": "/home/user/src/app/package.json"},
        ],
    )
    doc = cyclonedx.strip_local_paths(doc, "/home/user/src/app")
    assert "/home/user" not in json.dumps(doc)
    adopted = cyclonedx.adopt_root_component(doc, {"npm:app"}, "app")
    assert adopted == "app 1.0"
    assert doc["metadata"]["component"]["name"] == "app"
    assert [c.name for c in cyclonedx.parse_components(doc)] == ["lodash"]


def test_build_sbom_native_mode_for_example(settings):
    build = build_sbom(EXAMPLES / "01-vulnerable-dependency" / "project", settings)
    sbom = build.inventory.sbom
    assert sbom.mode.value == "native"
    assert sbom.validation.valid
    assert len(build.inventory.components) == 8
    assert any("Syft" in w for w in build.inventory.discovery.warnings) is False


def test_load_sbom_rejects_garbage():
    build = load_sbom(b"\x00\x01 not json")
    assert build.document is None
    assert not build.inventory.sbom.validation.valid
