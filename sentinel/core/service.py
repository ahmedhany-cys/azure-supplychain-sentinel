"""Orchestration shared by the CLI, the REST API and the dashboard."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from sentinel import __version__
from sentinel.config import Settings
from sentinel.core.models import (
    AnalysisRecord,
    DependencyDiff,
    EvidenceRef,
    Inventory,
    VulnerabilityScan,
)
from sentinel.core.release import ResolvedRelease, load_release
from sentinel.core.runner import tool_version, which
from sentinel.core.security import SecurityError, read_bounded, sha256_bytes
from sentinel.policies.engine import evaluate
from sentinel.policies.model import LoadedPolicy, load_policy
from sentinel.provenance.slsa import verify_provenance
from sentinel.reporting.reports import to_markdown
from sentinel.sbom.builder import build_sbom, load_sbom
from sentinel.sbom.diff import diff_inventories
from sentinel.scanners import osv
from sentinel.signing.verify import verify_artifact
from sentinel.storage.db import Store

MAX_SBOM_UPLOAD = 25 * 1024 * 1024


@dataclass
class Outcome:
    record: AnalysisRecord
    evidence: dict[str, tuple[bytes, str]]


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def tool_versions(settings: Settings) -> dict[str, str | None]:
    versions: dict[str, str | None] = {"sentinel": __version__}
    if settings.use_syft != "off" and which(settings.syft_bin):
        versions["syft"] = tool_version(settings.syft_bin, ["version"])
    if which(settings.osv_bin):
        versions["osv-scanner"] = tool_version(settings.osv_bin, ["--version"])
    if settings.use_cosign != "off" and which(settings.cosign_bin):
        versions["cosign"] = tool_version(settings.cosign_bin, ["version"])
    return versions


def _json(obj) -> bytes:
    if hasattr(obj, "model_dump_json"):
        return obj.model_dump_json(indent=2).encode()
    return json.dumps(obj, indent=2, default=str).encode()


def _finalize(
    record: AnalysisRecord, evidence: dict[str, tuple[bytes, str]], store: Store | None
) -> Outcome:
    if record.decision is not None:
        record.decision.evidence = [
            EvidenceRef(
                name=name, kind=name.split(".")[0], sha256=sha256_bytes(content), media_type=media
            )
            for name, (content, media) in sorted(evidence.items())
        ]
    evidence["report.md"] = (to_markdown(record).encode(), "text/markdown")
    evidence["report.json"] = (record.model_dump_json(indent=2).encode(), "application/json")
    if store is not None:
        store.save(record, evidence)
    return Outcome(record=record, evidence=evidence)


def _scan(
    project: Path, inventory: Inventory, settings: Settings, mode: str, recording: Path | None
) -> VulnerabilityScan:
    if mode == "recorded":
        if recording is None:
            scan = osv.skipped("recorded scanner evidence file not found")
            scan.status = osv.ScanStatus.UNAVAILABLE
            return scan
        return osv.load_recorded(recording, inventory)
    return osv.scan_live(project, inventory, settings)


def gate_release(
    release_path: Path,
    settings: Settings,
    policy: LoadedPolicy | None = None,
    *,
    store: Store | None = None,
    scan_mode: str | None = None,
    demo_scenario: str | None = None,
) -> Outcome:
    """Run every check for a release record and produce a policy decision."""
    policy = policy or load_policy(settings.policy_path)
    release: ResolvedRelease = load_release(release_path)
    rec = release.record
    record = AnalysisRecord(
        id=new_id("rel"),
        kind="release_gate",
        name=rec.label,
        sentinel_version=__version__,
        demo=demo_scenario is not None,
        demo_scenario=demo_scenario,
        inputs={
            "release_record": release_path.name,
            "project": rec.project,
            "policy": f"{policy.name}@{policy.version}",
        },
        tool_versions=tool_versions(settings),
    )
    evidence: dict[str, tuple[bytes, str]] = {}

    build = build_sbom(release.project, settings, project_name=rec.metadata.name)
    record.inventory = build.inventory
    if build.raw:
        evidence["sbom.cdx.json"] = (build.raw, "application/vnd.cyclonedx+json")

    mode = scan_mode or rec.evidence.vulnerability_scan.mode
    scan = _scan(release.project, build.inventory, settings, mode, release.scan_recording)
    record.vulnerability_scan = scan
    evidence["vulnerabilities.json"] = (_json(scan), "application/json")

    diff: DependencyDiff | None = None
    if rec.baseline_sbom:
        if release.baseline_sbom is None:
            record.log.append("baseline SBOM referenced but not found")
        else:
            baseline = load_sbom(
                read_bounded(release.baseline_sbom, MAX_SBOM_UPLOAD), label="baseline"
            )
            baseline_vulns = None
            if release.baseline_scan_recording:
                baseline_scan = osv.load_recorded(
                    release.baseline_scan_recording, baseline.inventory
                )
                if baseline_scan.status == osv.ScanStatus.COMPLETED:
                    baseline_vulns = baseline_scan.vulnerabilities
            completed = scan.status == osv.ScanStatus.COMPLETED
            diff = diff_inventories(
                baseline.inventory,
                build.inventory,
                baseline_label=f"baseline ({release.baseline_sbom.name})",
                candidate_label=rec.label,
                baseline_vulns=baseline_vulns,
                candidate_vulns=scan.vulnerabilities if completed else None,
            )
            record.dependency_diff = diff
            evidence["dependency-diff.json"] = (_json(diff), "application/json")

    signature = None
    if rec.artifact:
        signature = verify_artifact(
            release.artifact,
            release.signature_bundle,
            policy.trusted_keys,
            settings,
            expected_sha256=rec.artifact.expected_sha256,
        )
        record.signature = signature
        evidence["signature-verification.json"] = (_json(signature), "application/json")

    provenance = verify_provenance(
        release.provenance,
        artifact_sha256=signature.actual_sha256 if signature else None,
        trusted_keys=policy.trusted_keys,
        trusted_builders=policy.policy.provenance.trusted_builders,
        expected_source_uri=rec.source.repository
        if rec.source and policy.policy.provenance.require_source_match
        else None,
        expected_revision=rec.source.revision
        if rec.source and policy.policy.provenance.require_source_match
        else None,
        require_signature=policy.policy.provenance.require_signature,
    )
    record.provenance = provenance
    evidence["provenance-verification.json"] = (_json(provenance), "application/json")

    record.decision = evaluate(
        policy,
        release=rec.label,
        inventory=build.inventory,
        scan=scan,
        diff=diff,
        signature=signature,
        provenance=provenance,
    )
    evidence["decision.json"] = (_json(record.decision), "application/json")
    return _finalize(record, evidence, store)


def analyze_project(
    project: Path,
    settings: Settings,
    policy: LoadedPolicy | None = None,
    *,
    store: Store | None = None,
    scan_mode: str = "live",
    recording: Path | None = None,
) -> Outcome:
    """Source-only analysis: SBOM + vulnerabilities. Not a release decision."""
    policy = policy or load_policy(settings.policy_path)
    record = AnalysisRecord(
        id=new_id("prj"),
        kind="project_analysis",
        name=project.name,
        sentinel_version=__version__,
        inputs={"project": project.name, "scan_mode": scan_mode},
        tool_versions=tool_versions(settings),
    )
    build = build_sbom(project, settings)
    record.inventory = build.inventory
    evidence: dict[str, tuple[bytes, str]] = {}
    if build.raw:
        evidence["sbom.cdx.json"] = (build.raw, "application/vnd.cyclonedx+json")
    scan = _scan(project, build.inventory, settings, scan_mode, recording)
    record.vulnerability_scan = scan
    evidence["vulnerabilities.json"] = (_json(scan), "application/json")
    required = {c for c in policy.policy.required_checks if c in {"sbom", "vulnerability_scan"}}
    record.decision = evaluate(
        policy,
        release=f"{project.name} (source analysis)",
        inventory=build.inventory,
        scan=scan,
        diff=None,
        signature=None,
        provenance=None,
        required_override=required,
        only={"sbom", "vulnerability_scan"},
    )
    record.decision.reasons.append(
        "Source-only analysis: artifact signature and provenance were not evaluated, so this "
        "is not a release decision."
    )
    evidence["decision.json"] = (_json(record.decision), "application/json")
    return _finalize(record, evidence, store)


def compare_sboms(
    baseline_raw: bytes,
    candidate_raw: bytes,
    settings: Settings,
    policy: LoadedPolicy | None = None,
    *,
    store: Store | None = None,
    baseline_label: str = "baseline",
    candidate_label: str = "candidate",
) -> Outcome:
    policy = policy or load_policy(settings.policy_path)
    for raw, label in ((baseline_raw, baseline_label), (candidate_raw, candidate_label)):
        if len(raw) > MAX_SBOM_UPLOAD:
            raise SecurityError(f"{label} SBOM exceeds {MAX_SBOM_UPLOAD} bytes")
    baseline, candidate = (
        load_sbom(baseline_raw, baseline_label),
        load_sbom(candidate_raw, candidate_label),
    )
    for build, label in ((baseline, baseline_label), (candidate, candidate_label)):
        if build.document is None or not build.inventory.sbom.validation.valid:
            errors = build.inventory.sbom.validation.errors + build.inventory.sbom.errors
            raise SecurityError(f"{label} is not a valid CycloneDX SBOM: " + "; ".join(errors[:3]))
    diff = diff_inventories(
        baseline.inventory,
        candidate.inventory,
        baseline_label=baseline_label,
        candidate_label=candidate_label,
    )
    record = AnalysisRecord(
        id=new_id("dif"),
        kind="dependency_diff",
        name=f"{baseline_label} -> {candidate_label}",
        sentinel_version=__version__,
        inventory=candidate.inventory,
        dependency_diff=diff,
        inputs={"baseline": baseline_label, "candidate": candidate_label},
    )
    record.decision = evaluate(
        policy,
        release=record.name,
        inventory=candidate.inventory,
        scan=None,
        diff=diff,
        signature=None,
        provenance=None,
        required_override={"dependency_diff"},
        only={"sbom", "dependency_diff"},
    )
    evidence = {
        "dependency-diff.json": (_json(diff), "application/json"),
        "decision.json": (_json(record.decision), "application/json"),
    }
    return _finalize(record, evidence, store)


def verify_upload(
    artifact: Path,
    bundle: Path | None,
    settings: Settings,
    policy: LoadedPolicy | None = None,
    *,
    store: Store | None = None,
    expected_sha256: str | None = None,
    provenance: Path | None = None,
    display_name: str | None = None,
) -> Outcome:
    policy = policy or load_policy(settings.policy_path)
    signature = verify_artifact(
        artifact, bundle, policy.trusted_keys, settings, expected_sha256=expected_sha256
    )
    if display_name:
        signature.artifact = display_name
    prov = None
    required = {"artifact_signature"}
    if provenance is not None:
        prov = verify_provenance(
            provenance,
            artifact_sha256=signature.actual_sha256,
            trusted_keys=policy.trusted_keys,
            trusted_builders=policy.policy.provenance.trusted_builders,
            require_signature=policy.policy.provenance.require_signature,
        )
        required.add("provenance")
    record = AnalysisRecord(
        id=new_id("art"),
        kind="artifact_verification",
        name=display_name or artifact.name,
        sentinel_version=__version__,
        signature=signature,
        provenance=prov,
        inputs={
            "artifact": display_name or artifact.name,
            "bundle": bundle.name if bundle else None,
        },
        tool_versions=tool_versions(settings),
    )
    record.decision = evaluate(
        policy,
        release=record.name,
        inventory=None,
        scan=None,
        diff=None,
        signature=signature,
        provenance=prov,
        required_override=required,
        only={"artifact_signature", "provenance"},
    )
    evidence = {
        "signature-verification.json": (_json(signature), "application/json"),
        "decision.json": (_json(record.decision), "application/json"),
    }
    if prov:
        evidence["provenance-verification.json"] = (_json(prov), "application/json")
    return _finalize(record, evidence, store)


def settings_with(settings: Settings, **changes) -> Settings:
    return replace(settings, **changes)
