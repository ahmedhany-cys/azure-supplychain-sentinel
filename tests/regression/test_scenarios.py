"""Regression tests: every demonstration scenario must keep producing its documented decision
and the specific evidence that explains it."""

import json
import shutil
from dataclasses import replace

import pytest

from sentinel.config import REPO_ROOT, Settings
from sentinel.core.models import (
    Action,
    ChangeType,
    CheckStatus,
    ProvenanceStatus,
    ScanStatus,
    SignatureStatus,
)
from sentinel.demo import load_scenarios, run_scenarios
from sentinel.policies.model import load_policy

from ..conftest import EXAMPLES


@pytest.fixture(scope="module", params=["native", "tools"])
def runs(request, tmp_path_factory):
    """Run every scenario once per module, with external tools off and (if installed) on."""
    tmp = tmp_path_factory.mktemp("regression")
    settings = replace(
        Settings(),
        data_dir=tmp / "data",
        use_syft="off",
        use_cosign="off",
        osv_bin=str(tmp / "no-such-osv-scanner"),
    )
    if request.param == "tools":
        if not (shutil.which("syft") and shutil.which("cosign")):
            pytest.skip("syft/cosign not installed")
        settings = replace(settings, use_syft="auto", use_cosign="auto")
    policy = load_policy(REPO_ROOT / "config" / "policy.default.yaml")
    return {r.scenario.id: r for r in run_scenarios(settings, policy=policy)}


def test_catalogue_is_complete():
    assert [s.id for s in load_scenarios()] == [
        "01-vulnerable-dependency",
        "02-clean-release",
        "03-dependency-drift",
        "04-tampered-artifact",
        "05-missing-provenance",
        "06-scanner-unavailable",
    ]


def test_every_scenario_matches_expected_decision(runs):
    mismatched = {
        k: r.outcome.record.decision.result.value for k, r in runs.items() if not r.matched
    }
    assert mismatched == {}


def _checks(run):
    return {c.name: c for c in run.outcome.record.decision.checks}


def test_01_blocking_vulnerability_evidence(runs):
    record = runs["01-vulnerable-dependency"].outcome.record
    blocking = [f for f in record.decision.findings if f.action == Action.BLOCK]
    assert blocking and all(f.check == "vulnerability_scan" for f in blocking)
    assert any("CVE-2020-14343" in f.title and "pyyaml" in f.title for f in blocking)
    checks = _checks(runs["01-vulnerable-dependency"])
    assert checks["artifact_signature"].status == CheckStatus.PASSED
    assert checks["provenance"].status == CheckStatus.PASSED


def test_02_clean_release_has_all_checks_passed(runs):
    checks = _checks(runs["02-clean-release"])
    for name in ("sbom", "vulnerability_scan", "artifact_signature", "provenance"):
        assert checks[name].status == CheckStatus.PASSED, (name, checks[name].summary)


def test_03_drift_details(runs):
    record = runs["03-dependency-drift"].outcome.record
    changes = {(c.change, c.name) for c in record.dependency_diff.changes}
    assert changes == {
        (ChangeType.ADDED, "left-pad"),
        (ChangeType.UPGRADED, "debug"),
        (ChangeType.UPGRADED, "ms"),
    }
    review = [f for f in record.decision.findings if f.action == Action.REVIEW]
    assert [f.package for f in review] == ["left-pad"]
    assert record.dependency_diff.vulnerability_comparison_available


def test_04_tamper_detected_by_signature_and_provenance(runs):
    record = runs["04-tampered-artifact"].outcome.record
    manifest = json.loads((EXAMPLES / "fixture-manifest.json").read_text())
    expected = manifest["scenarios"]["04-tampered-artifact"]
    assert record.signature.status == SignatureStatus.DIGEST_MISMATCH
    assert record.signature.actual_sha256 == expected["artifact_sha256"]
    assert record.signature.signed_sha256 == expected["signed_sha256"]
    assert record.provenance.status == ProvenanceStatus.INVALID


def test_05_missing_provenance_is_a_policy_violation(runs):
    run = runs["05-missing-provenance"]
    assert run.outcome.record.provenance.status == ProvenanceStatus.MISSING
    assert _checks(run)["provenance"].status == CheckStatus.FAILED
    assert _checks(run)["artifact_signature"].status == CheckStatus.PASSED


def test_06_scanner_timeout_is_not_clean(runs):
    run = runs["06-scanner-unavailable"]
    scan = run.outcome.record.vulnerability_scan
    assert scan.status == ScanStatus.TIMEOUT and scan.vulnerabilities == []
    assert _checks(run)["vulnerability_scan"].status == CheckStatus.ERROR
    assert any("did not complete" in r for r in run.outcome.record.decision.reasons)
