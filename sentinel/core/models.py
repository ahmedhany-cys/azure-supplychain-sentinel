"""Shared data models.

The models deliberately separate three ideas that are easy to conflate:

* what a tool *reported* (a confirmed scanner finding, a parsed SBOM component),
* what is merely *suspicious* or *unknown* (a new dependency, missing data), and
* what the *policy decided* (block / review / warn / info) about either of them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_cvss_score(cls, score: float) -> Severity:
        """Qualitative rating per the CVSS v3.x/v4.0 specification table."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        if not value:
            return cls.UNKNOWN
        normalized = value.strip().upper()
        if normalized == "MODERATE":  # GitHub Advisory Database wording
            return cls.MEDIUM
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN


# UNKNOWN is ranked separately; it is never treated as "below LOW".
_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.NONE: 0,
    Severity.UNKNOWN: -1,
}


class Action(StrEnum):
    """What the policy says should happen because of a finding."""

    BLOCK = "block"
    REVIEW = "review"
    WARN = "warn"
    INFO = "info"


class FindingKind(StrEnum):
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"  # reported by a scanner
    SUSPICIOUS_INDICATOR = "suspicious_indicator"  # needs a human to look
    POLICY_VIOLATION = "policy_violation"  # evidence contradicts a policy requirement
    DATA_UNAVAILABLE = "data_unavailable"  # we could not obtain the evidence
    SCAN_ERROR = "scan_error"  # a tool ran and failed
    INFORMATIONAL = "informational"


class CheckStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"  # completed, with review/warn findings
    ERROR = "ERROR"  # attempted, did not complete
    UNAVAILABLE = "UNAVAILABLE"  # could not be attempted (tool/data missing)
    SKIPPED = "SKIPPED"  # not requested for this run
    NOT_APPLICABLE = "NOT_APPLICABLE"

    @property
    def completed(self) -> bool:
        return self in {CheckStatus.PASSED, CheckStatus.FAILED, CheckStatus.WARNING}


class DecisionResult(StrEnum):
    PASS = "PASS"  # noqa: S105 - enum value, not a credential
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"


class EvidenceMode(StrEnum):
    LIVE = "live"  # produced by running the tool during this analysis
    RECORDED = "recorded"  # replayed tool output captured earlier (deterministic fixture)
    NATIVE = "native"  # produced by Sentinel's built-in implementation


# ---------------------------------------------------------------------------
# Inventory / SBOM
# ---------------------------------------------------------------------------


class Component(BaseModel):
    name: str
    version: str | None = None
    ecosystem: str | None = None  # OSV ecosystem naming: PyPI, npm, Go, ...
    purl: str | None = None
    bom_ref: str | None = None
    scope: Literal["direct", "transitive", "unknown"] = "unknown"
    introduced_via: list[str] = Field(default_factory=list)  # parent packages, when known
    licenses: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    found_by: str | None = None

    @property
    def key(self) -> str:
        from sentinel.sbom.identity import component_key

        return component_key(self.ecosystem, self.name)


class ManifestInfo(BaseModel):
    path: str  # relative to the analysed project root
    ecosystem: str | None
    kind: str
    supported: bool
    note: str | None = None
    covered_by: str | None = None  # a supported lockfile in the same directory resolves it


class DiscoveryResult(BaseModel):
    root: str
    manifests: list[ManifestInfo] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def supported(self) -> list[ManifestInfo]:
        return [m for m in self.manifests if m.supported]

    @property
    def unsupported(self) -> list[ManifestInfo]:
        return [m for m in self.manifests if not m.supported]


class SBOMValidation(BaseModel):
    valid: bool
    schema_valid: bool | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SBOMInfo(BaseModel):
    format: str = "CycloneDX"
    spec_version: str | None = None
    serial_number: str | None = None
    generator: str | None = None
    generator_version: str | None = None
    generated_at: str | None = None
    mode: EvidenceMode = EvidenceMode.NATIVE
    component_count: int = 0
    sha256: str | None = None
    validation: SBOMValidation = Field(default_factory=lambda: SBOMValidation(valid=False))
    errors: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    components: list[Component] = Field(default_factory=list)
    sbom: SBOMInfo | None = None
    discovery: DiscoveryResult | None = None

    def by_key(self) -> dict[str, list[Component]]:
        out: dict[str, list[Component]] = {}
        for comp in self.components:
            out.setdefault(comp.key, []).append(comp)
        return out


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


class Vulnerability(BaseModel):
    id: str
    aliases: list[str] = Field(default_factory=list)
    package: str
    version: str | None
    ecosystem: str | None
    purl: str | None = None
    summary: str | None = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    severity_source: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    dependency_scope: Literal["direct", "transitive", "unknown"] = "unknown"
    introduced_via: list[str] = Field(default_factory=list)
    source_file: str | None = None

    @property
    def cve_ids(self) -> list[str]:
        return sorted({a for a in [self.id, *self.aliases] if a.startswith("CVE-")})

    @property
    def identity(self) -> frozenset[str]:
        return frozenset([self.id, *self.aliases])


class ScanStatus(StrEnum):
    COMPLETED = "completed"
    NO_PACKAGES = "no_packages"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


class VulnerabilityScan(BaseModel):
    scanner: str = "osv-scanner"
    scanner_version: str | None = None
    status: ScanStatus
    mode: EvidenceMode = EvidenceMode.LIVE
    started_at: datetime | None = None
    finished_at: datetime | None = None
    recorded_at: str | None = None
    data_source: str = "OSV.dev (https://osv.dev) via osv-scanner"
    data_source_available: bool | None = None
    targets: list[str] = Field(default_factory=list)
    packages_scanned: int = 0
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    raw_output_sha256: str | None = None


# ---------------------------------------------------------------------------
# Dependency diff
# ---------------------------------------------------------------------------


class ChangeType(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"
    VERSION_CHANGED = "version_changed"  # versions not comparable
    IDENTIFIER_CHANGED = "identifier_changed"
    SCOPE_CHANGED = "scope_changed"


class DependencyChange(BaseModel):
    change: ChangeType
    key: str
    name: str
    ecosystem: str | None
    old_version: str | None = None
    new_version: str | None = None
    old_purl: str | None = None
    new_purl: str | None = None
    scope: str = "unknown"
    introduced_via: list[str] = Field(default_factory=list)
    note: str | None = None


class DependencyDiff(BaseModel):
    baseline_label: str
    candidate_label: str
    changes: list[DependencyChange] = Field(default_factory=list)
    new_vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    resolved_vulnerabilities: list[str] = Field(default_factory=list)
    vulnerability_comparison_available: bool = False
    baseline_count: int = 0
    candidate_count: int = 0

    def of(self, change: ChangeType) -> list[DependencyChange]:
        return [c for c in self.changes if c.change == change]


# ---------------------------------------------------------------------------
# Artifact signature and provenance
# ---------------------------------------------------------------------------


class SignatureStatus(StrEnum):
    VERIFIED = "verified"
    DIGEST_MISMATCH = "digest_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    UNTRUSTED_SIGNER = "untrusted_signer"
    MISSING_SIGNATURE = "missing_signature"
    MISSING_ARTIFACT = "missing_artifact"
    MALFORMED_BUNDLE = "malformed_bundle"
    UNSUPPORTED = "unsupported"
    NO_TRUSTED_KEYS = "no_trusted_keys"
    ERROR = "error"


class TrustedKeyInfo(BaseModel):
    name: str
    key_id: str  # base64(sha256(DER SubjectPublicKeyInfo)), same as cosign's bundle hint
    path: str | None = None


class SignatureVerification(BaseModel):
    status: SignatureStatus
    verified: bool = False
    artifact: str | None = None
    actual_sha256: str | None = None
    signed_sha256: str | None = None  # digest claimed inside the signature bundle
    expected_sha256: str | None = None  # digest pinned in the release record
    signer_key_id: str | None = None
    signer_name: str | None = None
    claimed_key_hint: str | None = None
    trusted_keys: list[TrustedKeyInfo] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    cosign_version: str | None = None
    cosign_verified: bool | None = None
    transparency_log_verified: bool = False
    details: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=utcnow)


class ProvenanceStatus(StrEnum):
    VERIFIED = "verified"
    MISSING = "missing"
    MALFORMED = "malformed"
    INVALID = "invalid"  # fields missing or inconsistent with the artifact
    UNSIGNED = "unsigned"
    UNTRUSTED = "untrusted"  # signature valid but signer/builder is not trusted
    ERROR = "error"


class ProvenanceCheck(BaseModel):
    name: str
    passed: bool | None  # None = could not be evaluated
    detail: str


class ProvenanceVerification(BaseModel):
    status: ProvenanceStatus
    verified: bool = False
    path: str | None = None
    format: str | None = None
    predicate_type: str | None = None
    statement_type: str | None = None
    builder_id: str | None = None
    build_type: str | None = None
    source_uri: str | None = None
    source_revision: str | None = None
    subject_digests: list[str] = Field(default_factory=list)
    signer_key_id: str | None = None
    checks: list[ProvenanceCheck] = Field(default_factory=list)
    trust_level: Literal[
        "none", "present", "well-formed", "subject-bound", "authenticated", "trusted"
    ] = "none"
    details: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Policy decision
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    id: str
    check: str
    kind: FindingKind
    action: Action
    severity: Severity = Severity.UNKNOWN
    title: str
    detail: str | None = None
    rule: str | None = None
    package: str | None = None
    version: str | None = None
    evidence: list[str] = Field(default_factory=list)


class CheckResult(BaseModel):
    name: str
    title: str
    required: bool
    status: CheckStatus
    summary: str
    evidence_mode: EvidenceMode | None = None
    evidence: list[str] = Field(default_factory=list)


class EvidenceRef(BaseModel):
    name: str
    kind: str
    sha256: str | None = None
    media_type: str = "application/json"
    note: str | None = None


class ReleaseDecision(BaseModel):
    result: DecisionResult
    policy_name: str
    policy_version: str
    policy_sha256: str
    evaluated_at: datetime = Field(default_factory=utcnow)
    release: str | None = None
    artifact_sha256: str | None = None
    checks: list[CheckResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)

    @property
    def checks_performed(self) -> list[str]:
        return [c.name for c in self.checks if c.status.completed]

    @property
    def checks_not_completed(self) -> list[str]:
        """Required checks whose outcome is unknown (optional/not-applicable ones excluded)."""
        return [c.name for c in self.checks if c.required and not c.status.completed]


class AnalysisRecord(BaseModel):
    """Everything produced by one gate run; persisted and exported as a report."""

    id: str
    kind: Literal["release_gate", "project_analysis", "dependency_diff", "artifact_verification"]
    name: str
    created_at: datetime = Field(default_factory=utcnow)
    sentinel_version: str
    demo: bool = False
    demo_scenario: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    inventory: Inventory | None = None
    vulnerability_scan: VulnerabilityScan | None = None
    dependency_diff: DependencyDiff | None = None
    signature: SignatureVerification | None = None
    provenance: ProvenanceVerification | None = None
    decision: ReleaseDecision | None = None
    tool_versions: dict[str, str | None] = Field(default_factory=dict)
    log: list[str] = Field(default_factory=list)
