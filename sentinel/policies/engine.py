"""Policy evaluation: evidence in, auditable PASS / FAIL / INDETERMINATE out.

Decision procedure (documented in docs/policy-engine.md):

1. any finding whose action is ``block``                       -> FAIL
2. otherwise, any *required* check that did not complete       -> INDETERMINATE
3. otherwise, any ``review`` finding (and review_outcome is
   INDETERMINATE)                                              -> INDETERMINATE
4. otherwise                                                   -> PASS

A scanner error, timeout or missing tool can therefore never yield PASS for a
required check, and an indeterminate result is never reported as success.
"""

from __future__ import annotations

from datetime import date

from sentinel.core.models import (
    Action,
    ChangeType,
    CheckResult,
    CheckStatus,
    DecisionResult,
    DependencyDiff,
    EvidenceMode,
    EvidenceRef,
    Finding,
    FindingKind,
    Inventory,
    ProvenanceStatus,
    ProvenanceVerification,
    ReleaseDecision,
    ScanStatus,
    Severity,
    SignatureStatus,
    SignatureVerification,
    VulnerabilityScan,
)
from sentinel.policies.model import LoadedPolicy

TITLES = {
    "sbom": "SBOM generation & validation",
    "vulnerability_scan": "Known vulnerability scan",
    "dependency_diff": "Dependency change review",
    "artifact_signature": "Artifact signature verification",
    "provenance": "Build provenance verification",
}


class _Collector:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, check: str, kind: FindingKind, action: Action, title: str, **kw) -> Finding:
        finding = Finding(
            id=f"{check}-{len(self.findings) + 1:03d}",
            check=check,
            kind=kind,
            action=action,
            title=title,
            **kw,
        )
        self.findings.append(finding)
        return finding

    def for_check(self, check: str) -> list[Finding]:
        return [f for f in self.findings if f.check == check]


def _status_from_findings(findings: list[Finding]) -> CheckStatus:
    actions = {f.action for f in findings}
    if Action.BLOCK in actions:
        return CheckStatus.FAILED
    if actions & {Action.REVIEW, Action.WARN}:
        return CheckStatus.WARNING
    return CheckStatus.PASSED


def _missing_evidence(
    policy: LoadedPolicy, out: _Collector, check: str, required: bool, what: str
) -> CheckResult:
    if not required:
        return CheckResult(
            name=check,
            title=TITLES[check],
            required=False,
            status=CheckStatus.SKIPPED,
            summary=f"{what} not evaluated (check not required here)",
        )
    if policy.policy.decision.missing_required_evidence == DecisionResult.FAIL:
        out.add(
            check,
            FindingKind.POLICY_VIOLATION,
            Action.BLOCK,
            f"Required {what} is missing",
            rule=f"required_checks.{check}",
            detail="The policy requires this evidence for every release.",
        )
        return CheckResult(
            name=check,
            title=TITLES[check],
            required=True,
            status=CheckStatus.FAILED,
            summary=f"required {what} is missing",
        )
    out.add(
        check,
        FindingKind.DATA_UNAVAILABLE,
        Action.REVIEW,
        f"Required {what} is missing",
        rule=f"required_checks.{check}",
    )
    return CheckResult(
        name=check,
        title=TITLES[check],
        required=True,
        status=CheckStatus.UNAVAILABLE,
        summary=f"required {what} is missing",
    )


# --------------------------------------------------------------------------- checks


def _check_sbom(
    policy: LoadedPolicy, inv: Inventory | None, required: bool, out: _Collector
) -> CheckResult:
    name = "sbom"
    if inv is None or inv.sbom is None:
        out.add(name, FindingKind.SCAN_ERROR, Action.WARN, "SBOM was not generated")
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.ERROR,
            summary="SBOM generation did not run",
        )
    rules = policy.policy.sbom
    sbom = inv.sbom
    if rules.require_schema_valid and not sbom.validation.valid:
        out.add(
            name,
            FindingKind.POLICY_VIOLATION,
            Action.BLOCK,
            "SBOM failed validation",
            rule="sbom.require_schema_valid",
            detail="; ".join(sbom.validation.errors[:5]) or "validation failed",
        )
    count = len(inv.components)
    if count < rules.min_components:
        out.add(
            name,
            FindingKind.POLICY_VIOLATION,
            Action.BLOCK,
            f"SBOM lists {count} components; policy requires at least {rules.min_components}",
            rule="sbom.min_components",
            detail="Dependency discovery was empty or incomplete; the release cannot be assessed.",
        )
    for err in sbom.errors:
        out.add(name, FindingKind.SCAN_ERROR, Action.WARN, "SBOM generator problem", detail=err)
    if inv.discovery:
        for manifest in inv.discovery.unsupported:
            if manifest.covered_by or sbom.mode == EvidenceMode.LIVE:
                continue  # Syft may have catalogued it; reported as informational below
            out.add(
                name,
                FindingKind.DATA_UNAVAILABLE,
                Action.WARN,
                f"{manifest.path}: {manifest.kind} not inventoried",
                detail=manifest.note,
                evidence=[manifest.path],
            )
    status = _status_from_findings(out.for_check(name))
    gen = f"{sbom.generator or 'unknown'} {sbom.generator_version or ''}".strip()
    return CheckResult(
        name=name,
        title=TITLES[name],
        required=required,
        status=status,
        summary=f"{count} components, CycloneDX {sbom.spec_version}, generated by {gen}, "
        f"{'valid' if sbom.validation.valid else 'INVALID'}",
        evidence_mode=sbom.mode,
        evidence=["sbom.cdx.json"],
    )


def _check_vulns(
    policy: LoadedPolicy,
    scan: VulnerabilityScan | None,
    inv: Inventory | None,
    required: bool,
    out: _Collector,
    today: date,
) -> CheckResult:
    name = "vulnerability_scan"
    if scan is None or scan.status == ScanStatus.SKIPPED:
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.SKIPPED,
            summary="vulnerability scan was not run",
        )
    errors = "; ".join(scan.errors) or None
    if scan.status == ScanStatus.UNAVAILABLE:
        out.add(
            name,
            FindingKind.DATA_UNAVAILABLE,
            Action.WARN,
            "Vulnerability intelligence unavailable",
            detail=errors,
        )
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.UNAVAILABLE,
            evidence_mode=scan.mode,
            summary="scanner unavailable; vulnerability status is UNKNOWN, not clean",
        )
    if scan.status in {ScanStatus.ERROR, ScanStatus.TIMEOUT}:
        out.add(
            name,
            FindingKind.SCAN_ERROR,
            Action.WARN,
            f"Vulnerability scan {'timed out' if scan.status == ScanStatus.TIMEOUT else 'failed'}",
            detail=errors,
        )
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.ERROR,
            evidence_mode=scan.mode,
            summary=f"scan did not complete ({scan.status.value}); results unknown",
        )
    if scan.status == ScanStatus.NO_PACKAGES:
        out.add(
            name,
            FindingKind.DATA_UNAVAILABLE,
            Action.WARN,
            "Scanner found no packages to check",
            detail=errors,
        )
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.UNAVAILABLE,
            evidence_mode=scan.mode,
            summary="no scannable packages; vulnerability status is UNKNOWN",
        )

    rules = policy.policy.vulnerabilities
    for vuln in scan.vulnerabilities:
        exception = next(
            (
                e
                for e in rules.exceptions
                if e.id in vuln.identity
                and (e.package is None or e.package.lower() == vuln.package.lower())
            ),
            None,
        )
        if vuln.severity == Severity.UNKNOWN:
            action, rule = rules.unknown_severity, "vulnerabilities.unknown_severity"
        elif vuln.severity.rank >= rules.block_at_or_above.rank:
            action, rule = Action.BLOCK, "vulnerabilities.block_at_or_above"
        else:
            action, rule = rules.below_threshold, "vulnerabilities.below_threshold"
        detail_parts = [vuln.summary or "no summary provided by the advisory"]
        if exception and exception.expires >= today:
            detail_parts.append(
                f"Accepted risk: {exception.reason} (approved by "
                f"{exception.approved_by}, expires {exception.expires})."
            )
            action, rule = Action.INFO, "vulnerabilities.exceptions"
        elif exception:
            out.add(
                name,
                FindingKind.POLICY_VIOLATION,
                Action.WARN,
                f"Exception for {vuln.id} expired on {exception.expires}",
                rule="vulnerabilities.exceptions",
            )
        if vuln.remediation:
            detail_parts.append(vuln.remediation)
        sev = vuln.severity.value + (f" {vuln.cvss_score}" if vuln.cvss_score is not None else "")
        cves = ", ".join(vuln.cve_ids)
        out.add(
            name,
            FindingKind.CONFIRMED_VULNERABILITY,
            action,
            f"{vuln.id}{f' ({cves})' if cves else ''} in {vuln.package} {vuln.version} "
            f"[{sev}, {vuln.dependency_scope}]",
            severity=vuln.severity,
            rule=rule,
            package=vuln.package,
            version=vuln.version,
            detail=" ".join(detail_parts),
            evidence=vuln.references,
        )
    for limitation in scan.limitations:
        if "coverage is partial" in limitation:
            out.add(
                name,
                FindingKind.DATA_UNAVAILABLE,
                Action.WARN,
                "Partial scan coverage",
                detail=limitation,
            )
    status = _status_from_findings(out.for_check(name))
    blocking = sum(1 for f in out.for_check(name) if f.action == Action.BLOCK)
    label = "recorded" if scan.mode == EvidenceMode.RECORDED else "live"
    return CheckResult(
        name=name,
        title=TITLES[name],
        required=required,
        status=status,
        evidence_mode=scan.mode,
        summary=f"{scan.packages_scanned} package entries checked ({label} {scan.scanner} "
        f"{scan.scanner_version or ''}); {len(scan.vulnerabilities)} known vulnerabilities, "
        f"{blocking} at or above {rules.block_at_or_above.value}",
        evidence=["vulnerabilities.json"],
    )


def _check_diff(
    policy: LoadedPolicy, diff: DependencyDiff | None, required: bool, out: _Collector
) -> CheckResult:
    name = "dependency_diff"
    if diff is None:
        if required:
            return _missing_evidence(policy, out, name, True, "baseline SBOM")
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=False,
            status=CheckStatus.NOT_APPLICABLE,
            summary="no baseline supplied",
        )
    rules = policy.policy.dependency_changes
    denied = {(d.ecosystem.lower(), d.name.lower()): d for d in rules.denied_packages}
    allowed = {a.lower() for a in rules.allowed_new_packages}
    for change in diff.changes:
        eco = (change.ecosystem or "unknown").lower()
        deny = denied.get((eco, change.name.lower()))
        version_txt = {
            ChangeType.ADDED: f"{change.new_version}",
            ChangeType.REMOVED: f"{change.old_version}",
        }.get(change.change, f"{change.old_version} -> {change.new_version}")
        title = f"{change.change.value}: {change.name} {version_txt} ({change.scope})"
        via = (
            f" Introduced via: {', '.join(change.introduced_via)}." if change.introduced_via else ""
        )
        if deny and change.change != ChangeType.REMOVED:
            out.add(
                name,
                FindingKind.POLICY_VIOLATION,
                Action.BLOCK,
                title,
                package=change.name,
                version=change.new_version,
                rule="dependency_changes.denied_packages",
                detail=f"Package is on the deny list: {deny.reason}",
            )
            continue
        action: Action = getattr(rules, change.change.value)
        rule = f"dependency_changes.{change.change.value}"
        detail = None
        if change.change == ChangeType.ADDED:
            if change.key in allowed:
                action, rule = Action.INFO, "dependency_changes.allowed_new_packages"
                detail = "Pre-approved new dependency."
            else:
                detail = (
                    "New dependency not in the approved list. This does not mean it is "
                    "malicious: confirm it is expected, maintained and needed." + via
                )
        elif change.change == ChangeType.DOWNGRADED:
            detail = "Version moved backwards; downgrades can reintroduce fixed vulnerabilities."
        elif change.change == ChangeType.IDENTIFIER_CHANGED:
            detail = (
                f"Package URL changed from {change.old_purl} to {change.new_purl} for the "
                "same version; confirm the package source/registry is expected."
            )
        kind = (
            FindingKind.SUSPICIOUS_INDICATOR
            if action in {Action.REVIEW, Action.BLOCK}
            else (FindingKind.INFORMATIONAL)
        )
        out.add(
            name,
            kind,
            action,
            title,
            package=change.name,
            version=change.new_version,
            rule=rule,
            detail=detail or change.note,
        )
    for vuln in diff.new_vulnerabilities:
        out.add(
            name,
            FindingKind.INFORMATIONAL,
            Action.INFO,
            f"{vuln.id} is newly introduced in {vuln.package} {vuln.version}",
            severity=vuln.severity,
            package=vuln.package,
            version=vuln.version,
            detail="Gated by the vulnerability rules; listed here for change attribution.",
        )
    if not diff.vulnerability_comparison_available:
        out.add(
            name,
            FindingKind.INFORMATIONAL,
            Action.INFO,
            "Vulnerability comparison with the baseline not available",
            detail="The baseline has no comparable scan result.",
        )
    counts = {t: len(diff.of(t)) for t in ChangeType}
    status = _status_from_findings(out.for_check(name))
    return CheckResult(
        name=name,
        title=TITLES[name],
        required=required,
        status=status,
        summary=(
            f"{counts[ChangeType.ADDED]} added, {counts[ChangeType.REMOVED]} removed, "
            f"{
                counts[ChangeType.UPGRADED]
                + counts[ChangeType.DOWNGRADED]
                + counts[ChangeType.VERSION_CHANGED]
            } version changes, "
            f"{counts[ChangeType.IDENTIFIER_CHANGED]} identifier changes vs "
            f"{diff.baseline_label}"
        ),
        evidence=["dependency-diff.json"],
    )


_SIG_FAILURES = {
    SignatureStatus.DIGEST_MISMATCH,
    SignatureStatus.INVALID_SIGNATURE,
    SignatureStatus.UNTRUSTED_SIGNER,
    SignatureStatus.MALFORMED_BUNDLE,
}


def _check_signature(
    policy: LoadedPolicy, sig: SignatureVerification | None, required: bool, out: _Collector
) -> CheckResult:
    name = "artifact_signature"
    if sig is None or sig.status in {
        SignatureStatus.MISSING_SIGNATURE,
        SignatureStatus.MISSING_ARTIFACT,
    }:
        what = (
            "artifact"
            if sig and sig.status == SignatureStatus.MISSING_ARTIFACT
            else ("artifact signature")
        )
        return _missing_evidence(policy, out, name, required, what)
    detail = " ".join(sig.details)
    if sig.status == SignatureStatus.VERIFIED and sig.verified:
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.PASSED,
            summary=f"verified with trusted key '{sig.signer_name}' ({', '.join(sig.methods)})",
            evidence=["signature-verification.json"],
        )
    if sig.status in _SIG_FAILURES:
        titles = {
            SignatureStatus.DIGEST_MISMATCH: "Artifact digest does not match the signed digest",
            SignatureStatus.INVALID_SIGNATURE: "Signature is invalid",
            SignatureStatus.UNTRUSTED_SIGNER: "Artifact signed by an untrusted key",
            SignatureStatus.MALFORMED_BUNDLE: "Signature bundle is malformed",
        }
        out.add(
            name,
            FindingKind.POLICY_VIOLATION,
            Action.BLOCK,
            titles[sig.status],
            rule="signing.trusted_keys",
            detail=detail,
            evidence=[f"actual sha256:{sig.actual_sha256}", f"signed sha256:{sig.signed_sha256}"],
        )
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.FAILED,
            summary=f"rejected: {sig.status.value}",
            evidence=["signature-verification.json"],
        )
    out.add(
        name, FindingKind.SCAN_ERROR, Action.WARN, "Signature could not be verified", detail=detail
    )
    return CheckResult(
        name=name,
        title=TITLES[name],
        required=required,
        status=CheckStatus.ERROR,
        summary=f"verification did not complete: {sig.status.value}",
        evidence=["signature-verification.json"],
    )


def _check_provenance(
    policy: LoadedPolicy, prov: ProvenanceVerification | None, required: bool, out: _Collector
) -> CheckResult:
    name = "provenance"
    if prov is None or prov.status == ProvenanceStatus.MISSING:
        return _missing_evidence(policy, out, name, required, "build provenance")
    failed = [c for c in prov.checks if c.passed is False]
    if prov.status == ProvenanceStatus.VERIFIED:
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.PASSED,
            summary=f"trust level '{prov.trust_level}', builder {prov.builder_id}",
            evidence=["provenance-verification.json"],
        )
    if prov.status == ProvenanceStatus.ERROR:
        out.add(
            name,
            FindingKind.SCAN_ERROR,
            Action.WARN,
            "Provenance could not be evaluated",
            detail=" ".join(prov.details),
        )
        return CheckResult(
            name=name,
            title=TITLES[name],
            required=required,
            status=CheckStatus.ERROR,
            summary="provenance evaluation incomplete",
        )
    for check in failed or [None]:
        out.add(
            name,
            FindingKind.POLICY_VIOLATION,
            Action.BLOCK,
            (
                f"Provenance check failed: {check.name}"
                if check
                else f"Provenance {prov.status.value}"
            ),
            rule="provenance",
            detail=check.detail if check else " ".join(prov.details),
        )
    return CheckResult(
        name=name,
        title=TITLES[name],
        required=required,
        status=CheckStatus.FAILED,
        summary=f"rejected: {prov.status.value} (trust level '{prov.trust_level}')",
        evidence=["provenance-verification.json"],
    )


# --------------------------------------------------------------------------- decision


def evaluate(
    policy: LoadedPolicy,
    *,
    release: str | None,
    inventory: Inventory | None,
    scan: VulnerabilityScan | None,
    diff: DependencyDiff | None,
    signature: SignatureVerification | None,
    provenance: ProvenanceVerification | None,
    evidence: list[EvidenceRef] | None = None,
    today: date | None = None,
    required_override: set[str] | None = None,
    only: set[str] | None = None,
) -> ReleaseDecision:
    required = (
        set(required_override)
        if required_override is not None
        else set(policy.policy.required_checks)
    )
    out = _Collector()
    today = today or date.today()
    runners = {
        "sbom": lambda: _check_sbom(policy, inventory, "sbom" in required, out),
        "vulnerability_scan": lambda: _check_vulns(
            policy, scan, inventory, "vulnerability_scan" in required, out, today
        ),
        "dependency_diff": lambda: _check_diff(policy, diff, "dependency_diff" in required, out),
        "artifact_signature": lambda: _check_signature(
            policy, signature, "artifact_signature" in required, out
        ),
        "provenance": lambda: _check_provenance(policy, provenance, "provenance" in required, out),
    }
    checks = [run() for name, run in runners.items() if only is None or name in only]
    blocking = [f for f in out.findings if f.action == Action.BLOCK]
    incomplete = [c for c in checks if c.required and not c.status.completed]
    review = [f for f in out.findings if f.action == Action.REVIEW]
    warnings = [f for f in out.findings if f.action == Action.WARN]

    reasons: list[str] = []
    if blocking:
        result = DecisionResult.FAIL
        reasons.append(f"{len(blocking)} blocking finding(s):")
        reasons.extend(f"  - [{f.check}] {f.title}" for f in blocking[:20])
    elif incomplete or (
        review and policy.policy.decision.review_outcome == DecisionResult.INDETERMINATE
    ):
        result = DecisionResult.INDETERMINATE
    else:
        result = DecisionResult.PASS
    if incomplete:
        reasons.append(
            "Required checks that did not complete (their outcome is unknown, not successful):"
        )
        reasons.extend(f"  - {c.title}: {c.status.value} - {c.summary}" for c in incomplete)
    if review:
        reasons.append(f"{len(review)} finding(s) require manual review:")
        reasons.extend(f"  - [{f.check}] {f.title}" for f in review[:20])
    if warnings:
        reasons.append(f"{len(warnings)} warning(s) recorded (non-blocking).")
    if result == DecisionResult.PASS:
        reasons.insert(
            0,
            f"All {len(required)} required checks completed with no blocking "
            "findings under this policy. This is a policy decision, not proof "
            "that the software is free of vulnerabilities.",
        )
    recorded = [c.title for c in checks if c.evidence_mode == EvidenceMode.RECORDED]
    if recorded:
        reasons.append(
            "Evidence for " + ", ".join(recorded) + " was replayed from a recorded "
            "fixture, not produced live."
        )

    artifact_digest = signature.actual_sha256 if signature else None
    return ReleaseDecision(
        result=result,
        policy_name=policy.name,
        policy_version=policy.version,
        policy_sha256=policy.sha256,
        release=release,
        artifact_sha256=artifact_digest,
        checks=checks,
        findings=out.findings,
        reasons=reasons,
        evidence=evidence or [],
    )
