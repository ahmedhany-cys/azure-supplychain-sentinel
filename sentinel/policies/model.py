"""Release policy schema (YAML) and loader.

Trust anchors (signing keys, trusted builders) come *only* from the policy file,
which is operator-controlled configuration. Release records and uploads are
untrusted input and can never add a key or a builder.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.core.models import Action, DecisionResult, Severity
from sentinel.core.security import SecurityError, read_bounded, sha256_bytes
from sentinel.signing.keys import TrustedKey, load_public_key

CHECK_NAMES = ("sbom", "vulnerability_scan", "dependency_diff", "artifact_signature", "provenance")
CheckName = Literal[
    "sbom", "vulnerability_scan", "dependency_diff", "artifact_signature", "provenance"
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Metadata(_Strict):
    name: str
    version: str
    description: str | None = None
    owner: str | None = None


class SBOMRules(_Strict):
    require_schema_valid: bool = True
    min_components: int = Field(default=1, ge=0)


class VulnerabilityException(_Strict):
    id: str
    package: str | None = None
    reason: str
    approved_by: str
    expires: date


class VulnerabilityRules(_Strict):
    block_at_or_above: Severity = Severity.HIGH
    below_threshold: Action = Action.WARN
    unknown_severity: Action = Action.REVIEW
    exceptions: list[VulnerabilityException] = Field(default_factory=list)

    @field_validator("block_at_or_above")
    @classmethod
    def _known(cls, value: Severity) -> Severity:
        if value in {Severity.UNKNOWN, Severity.NONE}:
            raise ValueError("block_at_or_above must be LOW, MEDIUM, HIGH or CRITICAL")
        return value


class DeniedPackage(_Strict):
    ecosystem: str
    name: str
    reason: str


class DependencyChangeRules(_Strict):
    added: Action = Action.REVIEW
    removed: Action = Action.INFO
    upgraded: Action = Action.INFO
    downgraded: Action = Action.REVIEW
    version_changed: Action = Action.REVIEW
    identifier_changed: Action = Action.REVIEW
    scope_changed: Action = Action.INFO
    allowed_new_packages: list[str] = Field(default_factory=list)  # "pypi:requests"
    denied_packages: list[DeniedPackage] = Field(default_factory=list)


class TrustedKeyRef(_Strict):
    name: str
    path: str


class SigningRules(_Strict):
    trusted_keys: list[TrustedKeyRef] = Field(default_factory=list)


class ProvenanceRules(_Strict):
    require_signature: bool = True
    trusted_builders: list[str] = Field(default_factory=list)
    require_source_match: bool = True


class DecisionRules(_Strict):
    # Outcome when findings need human review and nothing blocks.
    review_outcome: Literal[DecisionResult.INDETERMINATE, DecisionResult.PASS] = (
        DecisionResult.INDETERMINATE
    )
    # Outcome when evidence a required check needs (signature, provenance) is absent.
    missing_required_evidence: Literal[DecisionResult.FAIL, DecisionResult.INDETERMINATE] = (
        DecisionResult.FAIL
    )


class Policy(_Strict):
    apiVersion: Literal["sentinel.dev/v1"]
    kind: Literal["ReleasePolicy"]
    metadata: Metadata
    required_checks: list[CheckName]
    sbom: SBOMRules = Field(default_factory=SBOMRules)
    vulnerabilities: VulnerabilityRules = Field(default_factory=VulnerabilityRules)
    dependency_changes: DependencyChangeRules = Field(default_factory=DependencyChangeRules)
    signing: SigningRules = Field(default_factory=SigningRules)
    provenance: ProvenanceRules = Field(default_factory=ProvenanceRules)
    decision: DecisionRules = Field(default_factory=DecisionRules)


class LoadedPolicy(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    policy: Policy
    path: Path
    sha256: str
    trusted_keys: list[TrustedKey]

    @property
    def name(self) -> str:
        return self.policy.metadata.name

    @property
    def version(self) -> str:
        return self.policy.metadata.version


def load_policy(path: Path) -> LoadedPolicy:
    raw = read_bounded(path, 256 * 1024)
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise SecurityError(f"policy is not valid YAML: {exc}") from exc
    policy = Policy.model_validate(data)
    keys = [
        load_public_key((path.parent / ref.path).resolve(), ref.name)
        for ref in policy.signing.trusted_keys
    ]
    return LoadedPolicy(policy=policy, path=path, sha256=sha256_bytes(raw), trusted_keys=keys)
