from datetime import date

import pytest
import yaml
from pydantic import ValidationError

from sentinel.core.models import (
    Action,
    ChangeType,
    CheckStatus,
    Component,
    DecisionResult,
    DependencyChange,
    DependencyDiff,
    EvidenceMode,
    Inventory,
    ProvenanceStatus,
    ProvenanceVerification,
    SBOMInfo,
    SBOMValidation,
    ScanStatus,
    Severity,
    SignatureStatus,
    SignatureVerification,
    Vulnerability,
    VulnerabilityScan,
)
from sentinel.policies.engine import evaluate
from sentinel.policies.model import load_policy

from ..conftest import REPO_ROOT

DEFAULT = REPO_ROOT / "config" / "policy.default.yaml"


def inv(n=3, valid=True):
    return Inventory(
        components=[Component(name=f"p{i}", version="1.0", ecosystem="PyPI") for i in range(n)],
        sbom=SBOMInfo(
            spec_version="1.6",
            generator="test",
            validation=SBOMValidation(valid=valid, errors=[] if valid else ["bad"]),
        ),
    )


def scan(status=ScanStatus.COMPLETED, vulns=()):
    return VulnerabilityScan(
        status=status, vulnerabilities=list(vulns), packages_scanned=3, mode=EvidenceMode.LIVE
    )


def vuln(severity, vid="GHSA-aaaa", score=None, pkg="p0"):
    return Vulnerability(
        id=vid, package=pkg, version="1.0", ecosystem="PyPI", severity=severity, cvss_score=score
    )


def sig(status=SignatureStatus.VERIFIED):
    return SignatureVerification(
        status=status,
        verified=status == SignatureStatus.VERIFIED,
        actual_sha256="ab" * 32,
        signer_name="k",
    )


def prov(status=ProvenanceStatus.VERIFIED):
    return ProvenanceVerification(
        status=status,
        verified=status == ProvenanceStatus.VERIFIED,
        trust_level="trusted" if status == "verified" else "present",
    )


def run(policy, **kw):
    args = {
        "release": "r",
        "inventory": inv(),
        "scan": scan(),
        "diff": None,
        "signature": sig(),
        "provenance": prov(),
    }
    args.update(kw)
    return evaluate(policy, **args)


def test_all_good_passes_with_honest_wording(policy):
    decision = run(policy)
    assert decision.result == DecisionResult.PASS
    assert "not proof" in decision.reasons[0]
    assert decision.policy_version == "1.0.0" and len(decision.policy_sha256) == 64
    assert set(decision.checks_performed) == {
        "sbom",
        "vulnerability_scan",
        "artifact_signature",
        "provenance",
    }


def test_blocking_vulnerability_fails(policy):
    decision = run(policy, scan=scan(vulns=[vuln(Severity.HIGH, score=7.5)]))
    assert decision.result == DecisionResult.FAIL
    finding = next(f for f in decision.findings if f.check == "vulnerability_scan")
    assert finding.action == Action.BLOCK and finding.kind.value == "confirmed_vulnerability"


def test_below_threshold_warns_but_passes(policy):
    decision = run(policy, scan=scan(vulns=[vuln(Severity.MEDIUM, score=5.0)]))
    assert decision.result == DecisionResult.PASS
    assert decision.findings[0].action == Action.WARN


def test_unknown_severity_requires_review(policy):
    decision = run(policy, scan=scan(vulns=[vuln(Severity.UNKNOWN)]))
    assert decision.result == DecisionResult.INDETERMINATE
    assert decision.findings[0].action == Action.REVIEW


@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.UNAVAILABLE,
        ScanStatus.ERROR,
        ScanStatus.TIMEOUT,
        ScanStatus.NO_PACKAGES,
        ScanStatus.SKIPPED,
    ],
)
def test_incomplete_scan_never_passes(policy, status):
    decision = run(policy, scan=scan(status=status))
    assert decision.result == DecisionResult.INDETERMINATE
    check = next(c for c in decision.checks if c.name == "vulnerability_scan")
    assert not check.status.completed
    assert "vulnerability_scan" in decision.checks_not_completed


def test_missing_scan_object_is_indeterminate(policy):
    assert run(policy, scan=None).result == DecisionResult.INDETERMINATE


def test_fail_takes_precedence_over_indeterminate(policy):
    decision = run(
        policy, scan=scan(status=ScanStatus.TIMEOUT), signature=sig(SignatureStatus.DIGEST_MISMATCH)
    )
    assert decision.result == DecisionResult.FAIL
    assert any("did not complete" in r for r in decision.reasons)


@pytest.mark.parametrize(
    "status",
    [
        SignatureStatus.DIGEST_MISMATCH,
        SignatureStatus.INVALID_SIGNATURE,
        SignatureStatus.UNTRUSTED_SIGNER,
        SignatureStatus.MALFORMED_BUNDLE,
    ],
)
def test_signature_failures_block(policy, status):
    assert run(policy, signature=sig(status)).result == DecisionResult.FAIL


@pytest.mark.parametrize(
    "status", [SignatureStatus.UNSUPPORTED, SignatureStatus.ERROR, SignatureStatus.NO_TRUSTED_KEYS]
)
def test_signature_errors_are_indeterminate(policy, status):
    assert run(policy, signature=sig(status)).result == DecisionResult.INDETERMINATE


def test_missing_signature_fails_by_default(policy):
    assert run(policy, signature=None).result == DecisionResult.FAIL
    assert run(policy, signature=sig(SignatureStatus.MISSING_SIGNATURE)).result == (
        DecisionResult.FAIL
    )


@pytest.mark.parametrize(
    "status",
    [
        ProvenanceStatus.INVALID,
        ProvenanceStatus.UNSIGNED,
        ProvenanceStatus.UNTRUSTED,
        ProvenanceStatus.MALFORMED,
    ],
)
def test_provenance_failures_block(policy, status):
    assert run(policy, provenance=prov(status)).result == DecisionResult.FAIL


def test_missing_provenance_outcome_is_configurable(make_policy):
    fail_policy = load_policy(make_policy())
    assert run(fail_policy, provenance=None).result == DecisionResult.FAIL
    soft = load_policy(make_policy(**{"decision.missing_required_evidence": "INDETERMINATE"}))
    decision = run(soft, provenance=None)
    assert decision.result == DecisionResult.INDETERMINATE
    assert next(c for c in decision.checks if c.name == "provenance").status == (
        CheckStatus.UNAVAILABLE
    )


def test_optional_checks_do_not_gate(make_policy):
    relaxed = load_policy(make_policy(required_checks=["sbom", "vulnerability_scan"]))
    decision = run(relaxed, signature=None, provenance=None)
    assert decision.result == DecisionResult.PASS
    assert {c.name: c.status for c in decision.checks}["provenance"] == CheckStatus.SKIPPED


def test_invalid_or_empty_sbom_blocks(policy):
    assert run(policy, inventory=inv(valid=False)).result == DecisionResult.FAIL
    decision = run(policy, inventory=inv(n=0))
    assert decision.result == DecisionResult.FAIL
    assert any("policy requires at least 1" in f.title for f in decision.findings)


def test_vulnerability_exceptions_active_and_expired(make_policy):
    exc = {
        "id": "CVE-2099-0001",
        "package": "p0",
        "reason": "not reachable",
        "approved_by": "security-lead",
        "expires": "2026-12-31",
    }
    policy = load_policy(make_policy(**{"vulnerabilities.exceptions": [exc]}))
    v = vuln(Severity.CRITICAL, vid="GHSA-zzzz")
    v.aliases = ["CVE-2099-0001"]
    active = evaluate(
        policy,
        release="r",
        inventory=inv(),
        scan=scan(vulns=[v]),
        diff=None,
        signature=sig(),
        provenance=prov(),
        today=date(2026, 10, 29),
    )
    assert active.result == DecisionResult.PASS
    assert active.findings[0].action == Action.INFO
    assert "Accepted risk" in active.findings[0].detail
    expired = evaluate(
        policy,
        release="r",
        inventory=inv(),
        scan=scan(vulns=[v]),
        diff=None,
        signature=sig(),
        provenance=prov(),
        today=date(2027, 1, 1),
    )
    assert expired.result == DecisionResult.FAIL
    assert any("expired" in f.title for f in expired.findings)


def _diff(*changes, label="baseline"):
    return DependencyDiff(baseline_label=label, candidate_label="c", changes=list(changes))


def test_new_dependency_review_and_allowlist(make_policy, policy):
    added = DependencyChange(
        change=ChangeType.ADDED,
        key="npm:left-pad",
        name="left-pad",
        ecosystem="npm",
        new_version="1.3.0",
        scope="direct",
    )
    decision = run(policy, diff=_diff(added))
    assert decision.result == DecisionResult.INDETERMINATE
    finding = next(f for f in decision.findings if f.check == "dependency_diff")
    assert finding.kind.value == "suspicious_indicator"
    assert "does not mean it is malicious" in finding.detail
    allowed = load_policy(
        make_policy(**{"dependency_changes.allowed_new_packages": ["npm:left-pad"]})
    )
    assert run(allowed, diff=_diff(added)).result == DecisionResult.PASS


def test_review_outcome_can_be_pass(make_policy):
    added = DependencyChange(
        change=ChangeType.ADDED, key="npm:x", name="x", ecosystem="npm", new_version="1"
    )
    lenient = load_policy(make_policy(**{"decision.review_outcome": "PASS"}))
    decision = run(lenient, diff=_diff(added))
    assert decision.result == DecisionResult.PASS
    assert any("require manual review" in r for r in decision.reasons)


def test_denied_package_blocks(policy):
    bad = DependencyChange(
        change=ChangeType.ADDED,
        key="npm:event-stream",
        name="event-stream",
        ecosystem="npm",
        new_version="3.3.6",
    )
    decision = run(policy, diff=_diff(bad))
    assert decision.result == DecisionResult.FAIL
    assert "deny list" in decision.findings[-1].detail or any(
        "deny list" in (f.detail or "") for f in decision.findings
    )


def test_upgrade_is_informational(policy):
    up = DependencyChange(
        change=ChangeType.UPGRADED,
        key="npm:debug",
        name="debug",
        ecosystem="npm",
        old_version="4.3.4",
        new_version="4.4.1",
    )
    assert run(policy, diff=_diff(up)).result == DecisionResult.PASS


def test_recorded_evidence_is_disclosed(policy):
    recorded = scan()
    recorded.mode = EvidenceMode.RECORDED
    decision = run(policy, scan=recorded)
    assert any("recorded fixture" in r for r in decision.reasons)


def test_policy_schema_is_strict(tmp_path):
    data = yaml.safe_load(DEFAULT.read_text())
    data["vulnerabilities"]["block_at_or_above"] = "UNKNOWN"
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(data))
    with pytest.raises(ValidationError):
        load_policy(bad)
    data = yaml.safe_load(DEFAULT.read_text())
    data["unexpected_key"] = True
    bad.write_text(yaml.safe_dump(data))
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_policy_default_loads_trust_anchor(policy):
    assert [k.name for k in policy.trusted_keys] == ["sentinel-demo-release"]
    assert policy.policy.required_checks == [
        "sbom",
        "vulnerability_scan",
        "artifact_signature",
        "provenance",
    ]
