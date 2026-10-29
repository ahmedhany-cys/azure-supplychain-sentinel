"""Validation of in-toto statements carrying SLSA v1 build provenance.

Trust is built up in ordered levels, and each level is reported separately:

``present``        a provenance document was supplied
``well-formed``    it parses as an in-toto statement with a SLSA v1 predicate and required fields
``subject-bound``  one of its subjects carries the artifact's actual SHA-256
``authenticated``  its DSSE signature verifies under a trusted key
``trusted``        the builder is on the policy's trusted-builder list and the declared
                   source matches the release record

A provenance document that *exists* is not evidence of anything until it is
authenticated and its claims are checked against the artifact and the policy.
Sentinel does not claim to establish a SLSA Build Level: it cannot attest to the
isolation or hardening of the build platform that produced the document.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.core.models import ProvenanceCheck, ProvenanceStatus, ProvenanceVerification, utcnow
from sentinel.core.security import (
    MAX_SMALL_JSON_BYTES,
    SecurityError,
    load_json_bounded,
    parse_json_bytes,
)
from sentinel.provenance.dsse import decode_envelope, sign_statement, verify_envelope
from sentinel.signing.bundle import BUNDLE_MEDIA_TYPES
from sentinel.signing.keys import TrustedKey

STATEMENT_TYPES = {"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"}
SLSA_V1 = "https://slsa.dev/provenance/v1"


def _get(data: Any, *path: str) -> Any:
    for part in path:
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_source_uri(uri: str | None) -> str:
    """``git+https://github.com/o/r.git@refs/heads/main`` -> ``github.com/o/r``."""
    value = (uri or "").strip().lower().removeprefix("git+").split("://")[-1]
    value = value.split("@", 1)[0] if "/" in value.split("@", 1)[0] else value
    return value.rstrip("/").removesuffix(".git")


def _load(path: Path) -> tuple[str, dict[str, Any] | None, dict[str, Any]]:
    """Return (format, envelope-or-None, statement)."""
    doc = load_json_bounded(path, MAX_SMALL_JSON_BYTES)
    if not isinstance(doc, dict):
        raise SecurityError("provenance document is not a JSON object")
    envelope = None
    fmt = "in-toto statement (unsigned)"
    if doc.get("mediaType") in BUNDLE_MEDIA_TYPES and isinstance(doc.get("dsseEnvelope"), dict):
        envelope, fmt = doc["dsseEnvelope"], "Sigstore bundle (DSSE)"
    elif "payloadType" in doc and "payload" in doc:
        envelope, fmt = doc, "DSSE envelope"
    if envelope is not None:
        _, payload, _ = decode_envelope(envelope)
        statement = parse_json_bytes(payload, MAX_SMALL_JSON_BYTES)
    else:
        statement = doc
    if not isinstance(statement, dict):
        raise SecurityError("in-toto statement is not a JSON object")
    return fmt, envelope, statement


def verify_provenance(
    path: Path | None,
    *,
    artifact_sha256: str | None,
    trusted_keys: list[TrustedKey],
    trusted_builders: list[str],
    expected_source_uri: str | None = None,
    expected_revision: str | None = None,
    require_signature: bool = True,
) -> ProvenanceVerification:
    if path is None or not path.is_file():
        return ProvenanceVerification(
            status=ProvenanceStatus.MISSING,
            details=["no build provenance was supplied for this release"],
        )
    result = ProvenanceVerification(
        status=ProvenanceStatus.ERROR, path=path.name, trust_level="present"
    )
    checks = result.checks
    try:
        fmt, envelope, statement = _load(path)
    except SecurityError as exc:
        result.status = ProvenanceStatus.MALFORMED
        result.details.append(f"provenance could not be parsed: {exc}")
        return result
    result.format = fmt
    result.statement_type = statement.get("_type")
    result.predicate_type = statement.get("predicateType")
    predicate = statement.get("predicate") or {}

    # --- structure -------------------------------------------------------------------------
    checks.append(
        ProvenanceCheck(
            name="statement type",
            passed=result.statement_type in STATEMENT_TYPES,
            detail=str(result.statement_type),
        )
    )
    checks.append(
        ProvenanceCheck(
            name="predicate type is SLSA v1",
            passed=result.predicate_type == SLSA_V1,
            detail=str(result.predicate_type),
        )
    )
    result.builder_id = _get(predicate, "runDetails", "builder", "id")
    result.build_type = _get(predicate, "buildDefinition", "buildType")
    required = {
        "buildDefinition.buildType": result.build_type,
        "buildDefinition.externalParameters": _get(
            predicate, "buildDefinition", "externalParameters"
        ),
        "runDetails.builder.id": result.builder_id,
    }
    missing = [name for name, value in required.items() if value in (None, "")]
    checks.append(
        ProvenanceCheck(
            name="required SLSA fields",
            passed=not missing,
            detail="all present" if not missing else "missing: " + ", ".join(missing),
        )
    )
    deps = _get(predicate, "buildDefinition", "resolvedDependencies") or []
    source = next(
        (
            d
            for d in deps
            if isinstance(d, dict)
            and isinstance(d.get("digest"), dict)
            and (d["digest"].get("gitCommit") or d["digest"].get("sha1"))
        ),
        None,
    )
    if source:
        result.source_uri = source.get("uri")
        result.source_revision = source["digest"].get("gitCommit") or source["digest"].get("sha1")
    checks.append(
        ProvenanceCheck(
            name="source revision recorded",
            passed=source is not None,
            detail=f"{result.source_uri}@{result.source_revision}"
            if source
            else "no resolvedDependencies entry with a git digest",
        )
    )
    started = _parse_time(_get(predicate, "runDetails", "metadata", "startedOn"))
    finished = _parse_time(_get(predicate, "runDetails", "metadata", "finishedOn"))
    if started and finished:
        consistent = started <= finished <= utcnow()
        checks.append(
            ProvenanceCheck(
                name="build timestamps consistent",
                passed=consistent,
                detail=f"{started.isoformat()} -> {finished.isoformat()}",
            )
        )
    structure_ok = all(c.passed for c in checks)
    if structure_ok:
        result.trust_level = "well-formed"

    # --- subject binding -------------------------------------------------------------------
    subjects = statement.get("subject") if isinstance(statement.get("subject"), list) else []
    result.subject_digests = [
        str(_get(s, "digest", "sha256")) for s in subjects if _get(s, "digest", "sha256")
    ]
    if artifact_sha256 is None:
        bound = None
        detail = "artifact digest unavailable; subject binding not evaluated"
    else:
        bound = artifact_sha256 in result.subject_digests
        detail = (
            "artifact sha256 matches a provenance subject"
            if bound
            else "no provenance subject matches the artifact sha256 "
            f"({artifact_sha256[:12]}...); provenance describes a different artifact"
        )
    checks.append(
        ProvenanceCheck(name="subject matches artifact digest", passed=bound, detail=detail)
    )
    if structure_ok and bound:
        result.trust_level = "subject-bound"

    # --- authenticity ----------------------------------------------------------------------
    signer = None
    if envelope is None:
        checks.append(
            ProvenanceCheck(
                name="signature verifies under trusted key",
                passed=False,
                detail="provenance is not signed",
            )
        )
    else:
        try:
            signer = verify_envelope(envelope, trusted_keys)
        except SecurityError as exc:
            checks.append(
                ProvenanceCheck(
                    name="signature verifies under trusted key", passed=False, detail=str(exc)
                )
            )
        else:
            checks.append(
                ProvenanceCheck(
                    name="signature verifies under trusted key",
                    passed=signer is not None,
                    detail=f"verified with '{signer.name}'"
                    if signer
                    else "DSSE signature does not verify under any trusted key",
                )
            )
    if signer:
        result.signer_key_id = signer.key_id
        if result.trust_level == "subject-bound":
            result.trust_level = "authenticated"

    # --- policy trust ----------------------------------------------------------------------
    builder_trusted = bool(result.builder_id) and result.builder_id in trusted_builders
    checks.append(
        ProvenanceCheck(
            name="builder is trusted by policy",
            passed=builder_trusted,
            detail=f"{result.builder_id}"
            + ("" if builder_trusted else " is not in trusted_builders"),
        )
    )
    if expected_revision or expected_source_uri:
        rev_ok = not expected_revision or result.source_revision == expected_revision
        uri_ok = not expected_source_uri or normalize_source_uri(
            result.source_uri
        ) == normalize_source_uri(expected_source_uri)
        checks.append(
            ProvenanceCheck(
                name="source matches release record",
                passed=rev_ok and uri_ok,
                detail=f"expected {expected_source_uri}@{expected_revision}, "
                f"provenance says {result.source_uri}@{result.source_revision}",
            )
        )
    if result.trust_level == "authenticated" and all(c.passed is not False for c in checks):
        result.trust_level = "trusted"

    # --- overall status --------------------------------------------------------------------
    if not structure_ok or bound is False:
        result.status = ProvenanceStatus.INVALID
    elif envelope is None:
        result.status = (
            ProvenanceStatus.UNSIGNED
            if require_signature
            else (ProvenanceStatus.VERIFIED if builder_trusted else ProvenanceStatus.UNTRUSTED)
        )
    elif signer is None or not builder_trusted:
        result.status = ProvenanceStatus.UNTRUSTED
    elif any(c.passed is False for c in checks):
        result.status = ProvenanceStatus.INVALID
    elif bound is None:
        result.status = ProvenanceStatus.ERROR
        result.details.append("artifact digest unavailable, provenance cannot be bound")
    else:
        result.status = ProvenanceStatus.VERIFIED
    result.verified = result.status == ProvenanceStatus.VERIFIED
    failed = [c.name for c in checks if c.passed is False]
    if failed:
        result.details.append("failed checks: " + "; ".join(failed))
    return result


def build_statement(
    *,
    artifact_name: str,
    artifact_sha256: str,
    builder_id: str,
    build_type: str,
    source_uri: str,
    source_revision: str,
    invocation_id: str,
    started_on: str,
    finished_on: str,
    external_parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": artifact_name, "digest": {"sha256": artifact_sha256}}],
        "predicateType": SLSA_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": external_parameters or {"source": source_uri},
                "resolvedDependencies": [
                    {"uri": source_uri, "digest": {"gitCommit": source_revision}}
                ],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started_on,
                    "finishedOn": finished_on,
                },
            },
        },
    }


__all__ = ["build_statement", "sign_statement", "verify_provenance"]
