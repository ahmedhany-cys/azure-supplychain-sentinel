import json

import pytest
from pydantic import ValidationError

from sentinel.core.models import AnalysisRecord
from sentinel.core.release import load_release
from sentinel.core.security import SecurityError
from sentinel.core.service import gate_release
from sentinel.reporting.reports import to_json, to_markdown
from sentinel.storage.db import Store

from ..conftest import EXAMPLES

PEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49\n-----END PRIVATE KEY-----"


@pytest.fixture
def outcome(settings, policy):
    return gate_release(EXAMPLES / "01-vulnerable-dependency" / "release.yaml", settings, policy)


def test_store_round_trip(settings, outcome):
    store = Store(settings.db_path)
    store.save(outcome.record, outcome.evidence)
    rows = store.list()
    assert rows[0]["id"] == outcome.record.id and rows[0]["result"] == "FAIL"
    loaded = store.get(outcome.record.id)
    assert loaded.decision.result == outcome.record.decision.result
    names = {e["name"] for e in store.evidence_list(outcome.record.id)}
    assert {"sbom.cdx.json", "decision.json", "report.md", "report.json"} <= names
    content, media = store.evidence(outcome.record.id, "sbom.cdx.json")
    assert json.loads(content)["bomFormat"] == "CycloneDX"
    assert media == "application/vnd.cyclonedx+json"
    assert store.audit_entries()[0]["event"] == "analysis.saved"


def test_store_queries_are_parameterised(settings, outcome):
    store = Store(settings.db_path)
    store.save(outcome.record, outcome.evidence)
    assert store.get("x' OR '1'='1") is None
    assert store.evidence(outcome.record.id, "' OR 1=1 --") is None
    assert len(store.list(kind="release_gate' OR '1'='1")) == 0
    assert len(store.list(limit=10_000)) == 1  # limit is clamped, still returns data


def test_store_redacts_secrets(settings, outcome):
    store = Store(settings.db_path)
    outcome.record.log.append(f"tool leaked {PEM}")
    store.save(outcome.record, {})
    raw = store.get(outcome.record.id).model_dump_json()
    assert "MIGHAgEAMBMG" not in raw


def test_demo_data_can_be_cleared(settings, policy):
    store = Store(settings.db_path)
    gate_release(
        EXAMPLES / "02-clean-release" / "release.yaml",
        settings,
        policy,
        store=store,
        demo_scenario="02-clean-release",
    )
    assert store.list()[0]["demo"] == 1
    assert store.delete_demo_data() == 1
    assert store.list() == []


def test_markdown_report_content(outcome):
    md = to_markdown(outcome.record)
    assert "## Decision: **FAIL**" in md
    assert "CVE-2020-14343" in md
    assert "default-release-policy" in md
    assert "not proof that software is free of vulnerabilities" in md
    assert "recorded" in md


def test_demo_banner_in_reports(settings, policy):
    out = gate_release(
        EXAMPLES / "02-clean-release" / "release.yaml",
        settings,
        policy,
        demo_scenario="02-clean-release",
    )
    assert "Demonstration data" in to_markdown(out.record)


def test_reports_never_contain_key_material(outcome):
    outcome.record.log.append(PEM)
    outcome.record.inputs["note"] = "password=supersecret99"
    for text in (to_markdown(outcome.record), to_json(outcome.record)):
        assert "MIGHAgEAMBMG" not in text
    data = json.loads(to_json(outcome.record))
    assert "supersecret99" not in json.dumps(data)
    AnalysisRecord.model_validate(data)


def test_evidence_refs_have_digests(outcome):
    refs = {e.name: e for e in outcome.record.decision.evidence}
    assert "sbom.cdx.json" in refs and len(refs["sbom.cdx.json"].sha256) == 64


def test_release_record_path_escape_is_rejected(tmp_path):
    (tmp_path / "project").mkdir()
    rel = tmp_path / "release.yaml"
    rel.write_text(
        "apiVersion: sentinel.dev/v1\nkind: ReleaseCandidate\n"
        "metadata: {name: x, version: '1'}\nproject: project\n"
        "artifact: {path: ../../etc/passwd}\n"
    )
    with pytest.raises(SecurityError):
        load_release(rel)


def test_release_record_cannot_add_trust_anchors(tmp_path):
    (tmp_path / "project").mkdir()
    rel = tmp_path / "release.yaml"
    rel.write_text(
        "apiVersion: sentinel.dev/v1\nkind: ReleaseCandidate\n"
        "metadata: {name: x, version: '1'}\nproject: project\n"
        "trusted_keys: [{name: attacker, path: attacker.pub}]\n"
    )
    with pytest.raises(ValidationError):
        load_release(rel)


@pytest.mark.parametrize(
    "snippet,err",
    [
        ("source: {repository: r, revision: main}\n", ValidationError),
        ("artifact: {path: a, expected_sha256: xyz}\n", ValidationError),
        ("evidence: {vulnerability_scan: {mode: recorded}}\n", SecurityError),
    ],
)
def test_release_record_validation(tmp_path, snippet, err):
    (tmp_path / "project").mkdir()
    rel = tmp_path / "release.yaml"
    rel.write_text(
        "apiVersion: sentinel.dev/v1\nkind: ReleaseCandidate\n"
        "metadata: {name: x, version: '1'}\nproject: project\n" + snippet
    )
    with pytest.raises(err):
        load_release(rel)


def test_release_yaml_must_be_safe_yaml(tmp_path):
    rel = tmp_path / "release.yaml"
    rel.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises((SecurityError, ValidationError)):
        load_release(rel)
