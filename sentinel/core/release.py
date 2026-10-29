"""Release record (``release.yaml``): the untrusted description of a release candidate.

Every path it contains is resolved relative to the record's own directory and must
stay inside it. A release record can point at evidence, but it can never extend the
policy's trust anchors.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.core.security import SecurityError, read_bounded, resolve_within

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReleaseMeta(_Strict):
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=64)
    description: str | None = None


class ArtifactRef(_Strict):
    path: str
    signature_bundle: str | None = None
    expected_sha256: str | None = None

    @field_validator("expected_sha256")
    @classmethod
    def _hex(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256.match(value.lower()):
            raise ValueError("expected_sha256 must be 64 hex characters")
        return value.lower() if value else None


class SourceRef(_Strict):
    repository: str
    revision: str

    @field_validator("revision")
    @classmethod
    def _sha(cls, value: str) -> str:
        if not _GIT_SHA.match(value):
            raise ValueError("revision must be a full 40-character git commit SHA")
        return value


class ScanEvidence(_Strict):
    mode: Literal["live", "recorded"] = "live"
    path: str | None = None  # required for recorded mode


class EvidenceConfig(_Strict):
    vulnerability_scan: ScanEvidence = Field(default_factory=ScanEvidence)
    baseline_vulnerability_scan: ScanEvidence | None = None


class ReleaseRecord(_Strict):
    apiVersion: Literal["sentinel.dev/v1"]
    kind: Literal["ReleaseCandidate"]
    metadata: ReleaseMeta
    project: str
    baseline_sbom: str | None = None
    artifact: ArtifactRef | None = None
    provenance: str | None = None
    source: SourceRef | None = None
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)

    @property
    def label(self) -> str:
        return f"{self.metadata.name} {self.metadata.version}"


class ResolvedRelease(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    record: ReleaseRecord
    base_dir: Path
    project: Path
    baseline_sbom: Path | None
    artifact: Path | None
    signature_bundle: Path | None
    provenance: Path | None
    scan_recording: Path | None
    baseline_scan_recording: Path | None


def _opt(base: Path, value: str | None) -> Path | None:
    """Resolve an optional path. Missing files are allowed (they become 'missing evidence')."""
    if not value:
        return None
    path = resolve_within(base, value, must_exist=False)
    return path if path.exists() else None


def load_release(path: Path) -> ResolvedRelease:
    path = path.resolve()
    try:
        data = yaml.safe_load(read_bounded(path, 64 * 1024))
    except yaml.YAMLError as exc:
        raise SecurityError(f"release record is not valid YAML: {exc}") from exc
    record = ReleaseRecord.model_validate(data)
    base = path.parent
    project = resolve_within(base, record.project)
    if not project.is_dir():
        raise SecurityError("release record 'project' must be a directory")
    scan_cfg = record.evidence.vulnerability_scan
    if scan_cfg.mode == "recorded" and not scan_cfg.path:
        raise SecurityError("recorded vulnerability evidence requires 'path'")
    baseline_scan = record.evidence.baseline_vulnerability_scan
    return ResolvedRelease(
        record=record,
        base_dir=base,
        project=project,
        baseline_sbom=_opt(base, record.baseline_sbom),
        artifact=_opt(base, record.artifact.path) if record.artifact else None,
        signature_bundle=_opt(base, record.artifact.signature_bundle) if record.artifact else None,
        provenance=_opt(base, record.provenance),
        scan_recording=_opt(base, scan_cfg.path) if scan_cfg.mode == "recorded" else None,
        baseline_scan_recording=_opt(base, baseline_scan.path) if baseline_scan else None,
    )
