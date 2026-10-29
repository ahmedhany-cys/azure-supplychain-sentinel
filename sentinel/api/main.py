"""REST API.

Security posture:
* binds to 127.0.0.1 by default (see ``sentinel.api.__main__``);
* optional bearer token (``SENTINEL_API_TOKEN``), compared in constant time;
* project/release paths must sit under ``SENTINEL_ALLOWED_ROOTS``;
* uploads are size-limited, written to a private temp dir under a sanitised name,
  hashed and verified - never unpacked or executed;
* errors return generic messages; internal details stay in the server log.
"""

from __future__ import annotations

import hmac
import logging
import re
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field, ValidationError

from sentinel import __version__
from sentinel.config import Settings, get_settings
from sentinel.core.models import AnalysisRecord
from sentinel.core.security import (
    SecurityError,
    ensure_allowed_root,
    private_tempdir,
    redact,
    safe_filename,
)
from sentinel.core.service import (
    Outcome,
    analyze_project,
    compare_sboms,
    gate_release,
    tool_versions,
    verify_upload,
)
from sentinel.demo import load_scenarios, scenario_settings
from sentinel.policies.model import LoadedPolicy, load_policy
from sentinel.storage.db import Store

log = logging.getLogger("sentinel.api")
ANALYSIS_ID = re.compile(r"^(rel|prj|dif|art)-[0-9a-f]{12}$")
EVIDENCE_NAME = re.compile(r"^[a-z0-9.-]{1,64}$")
CHUNK = 1024 * 1024

app = FastAPI(
    title="Azure SupplyChain Sentinel API",
    version=__version__,
    description="Release-gate API: SBOMs, vulnerability evidence, dependency drift, "
    "artifact signatures, build provenance and policy decisions.",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(SecurityError)
async def _security_error(_: Request, exc: SecurityError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": redact(str(exc))})


@app.exception_handler(ValidationError)
async def _validation_error(_: Request, exc: ValidationError) -> JSONResponse:
    errors = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:10]]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(Exception)
async def _unexpected(_: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
    log.exception("unhandled error")
    return JSONResponse(status_code=500, content={"detail": "internal error"})


# --------------------------------------------------------------------------- dependencies


def settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(settings_dep)]


def require_token(request: Request, settings: SettingsDep) -> None:
    if not settings.api_token:
        return
    header = request.headers.get("authorization", "")
    supplied = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
    if not hmac.compare_digest(supplied.encode(), settings.api_token.encode()):
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")


def store_dep(settings: SettingsDep) -> Store:
    return Store(settings.db_path)


def policy_dep(settings: SettingsDep) -> LoadedPolicy:
    return load_policy(settings.policy_path)


Auth = Depends(require_token)
StoreDep = Annotated[Store, Depends(store_dep)]
PolicyDep = Annotated[LoadedPolicy, Depends(policy_dep)]


def _summary(outcome: Outcome) -> dict:
    record = outcome.record
    decision = record.decision
    return {
        "id": record.id,
        "kind": record.kind,
        "name": record.name,
        "result": decision.result.value if decision else None,
        "reasons": decision.reasons if decision else [],
        "links": {
            "self": f"/api/v1/analyses/{record.id}",
            "report_md": f"/api/v1/analyses/{record.id}/report.md",
            "evidence": f"/api/v1/analyses/{record.id}/evidence",
        },
    }


def _record_or_404(store: Store, analysis_id: str) -> AnalysisRecord:
    if not ANALYSIS_ID.match(analysis_id):
        raise HTTPException(status_code=404, detail="analysis not found")
    record = store.get(analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return record


async def _save_upload(upload: UploadFile, directory: Path, limit: int, name: str) -> Path:
    target = directory / safe_filename(upload.filename or name, default=name)
    if target.exists():
        target = directory / f"{name}-{target.name}"
    size = 0
    with target.open("wb") as handle:
        while chunk := await upload.read(CHUNK):
            size += len(chunk)
            if size > limit:
                raise HTTPException(status_code=413, detail=f"{name} exceeds {limit} bytes")
            handle.write(chunk)
    return target


# --------------------------------------------------------------------------- routes


@app.get("/health")
def health(settings: SettingsDep) -> dict:
    return {"status": "ok", "version": __version__, "tools": tool_versions(settings)}


@app.get("/api/v1/policy", dependencies=[Auth])
def get_policy(policy: PolicyDep) -> dict:
    return {
        "name": policy.name,
        "version": policy.version,
        "sha256": policy.sha256,
        "required_checks": policy.policy.required_checks,
        "rules": policy.policy.model_dump(mode="json", exclude={"signing"}),
        "trusted_keys": [k.info().model_dump() for k in policy.trusted_keys],
    }


class ProjectRequest(BaseModel):
    project_path: str = Field(min_length=1, max_length=1024)
    scan_mode: Literal["live", "recorded"] = "live"
    recording_path: str | None = Field(default=None, max_length=1024)


@app.post("/api/v1/analyses/project", dependencies=[Auth], status_code=201)
def run_project_analysis(
    req: ProjectRequest, settings: SettingsDep, store: StoreDep, policy: PolicyDep
) -> dict:
    project = ensure_allowed_root(req.project_path, settings.allowed_roots)
    if not project.is_dir():
        raise SecurityError("project_path must be a directory")
    recording = None
    if req.scan_mode == "recorded":
        if not req.recording_path:
            raise SecurityError("recording_path is required for recorded mode")
        recording = ensure_allowed_root(req.recording_path, settings.allowed_roots)
    outcome = analyze_project(
        project, settings, policy, store=store, scan_mode=req.scan_mode, recording=recording
    )
    return _summary(outcome)


class GateRequest(BaseModel):
    release_path: str = Field(min_length=1, max_length=1024)
    scan_mode: Literal["live", "recorded"] | None = None


@app.post("/api/v1/releases/gate", dependencies=[Auth], status_code=201)
def run_gate(req: GateRequest, settings: SettingsDep, store: StoreDep, policy: PolicyDep) -> dict:
    release = ensure_allowed_root(req.release_path, settings.allowed_roots)
    outcome = gate_release(release, settings, policy, store=store, scan_mode=req.scan_mode)
    return _summary(outcome)


@app.get("/api/v1/scenarios", dependencies=[Auth])
def list_scenarios() -> list[dict]:
    return [
        {
            "id": s.id,
            "title": s.title,
            "expected": s.expected,
            "explanation": s.explanation,
            "fault_injection": s.fault,
        }
        for s in load_scenarios()
    ]


@app.post("/api/v1/scenarios/{scenario_id}/run", dependencies=[Auth], status_code=201)
def run_scenario(
    scenario_id: str, settings: SettingsDep, store: StoreDep, policy: PolicyDep
) -> dict:
    scenario = next((s for s in load_scenarios() if s.id == scenario_id), None)
    if scenario is None:
        raise HTTPException(status_code=404, detail="scenario not found")
    outcome = gate_release(
        scenario.release,
        scenario_settings(settings, scenario.fault),
        policy,
        store=store,
        demo_scenario=scenario.id,
    )
    body = _summary(outcome)
    body["expected"] = scenario.expected
    body["matched_expected"] = body["result"] == scenario.expected
    return body


@app.post("/api/v1/diff", dependencies=[Auth], status_code=201)
async def run_diff(
    settings: SettingsDep,
    store: StoreDep,
    policy: PolicyDep,
    baseline: Annotated[UploadFile, File()],
    candidate: Annotated[UploadFile, File()],
) -> dict:
    with private_tempdir() as tmp:
        base_path = await _save_upload(baseline, tmp, settings.max_upload_bytes, "baseline")
        cand_path = await _save_upload(candidate, tmp, settings.max_upload_bytes, "candidate")
        outcome = compare_sboms(
            base_path.read_bytes(),
            cand_path.read_bytes(),
            settings,
            policy,
            store=store,
            baseline_label=base_path.name,
            candidate_label=cand_path.name,
        )
    return _summary(outcome)


@app.post("/api/v1/verify", dependencies=[Auth], status_code=201)
async def run_verify(
    settings: SettingsDep,
    store: StoreDep,
    policy: PolicyDep,
    artifact: Annotated[UploadFile, File()],
    bundle: Annotated[UploadFile | None, File()] = None,
    provenance: Annotated[UploadFile | None, File()] = None,
    expected_sha256: Annotated[str | None, Form()] = None,
) -> dict:
    if expected_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise SecurityError("expected_sha256 must be 64 hex characters")
    with private_tempdir() as tmp:
        art = await _save_upload(artifact, tmp, settings.max_upload_bytes, "artifact")
        bun = await _save_upload(bundle, tmp, 1024 * 1024, "bundle") if bundle else None
        prov = (
            await _save_upload(provenance, tmp, 2 * 1024 * 1024, "provenance")
            if provenance
            else None
        )
        outcome = verify_upload(
            art,
            bun,
            settings,
            policy,
            store=store,
            expected_sha256=expected_sha256,
            provenance=prov,
            display_name=art.name,
        )
    body = _summary(outcome)
    sig = outcome.record.signature
    body["signature"] = sig.model_dump(mode="json") if sig else None
    return body


@app.get("/api/v1/analyses", dependencies=[Auth])
def list_analyses(
    store: StoreDep,
    limit: int = 50,
    kind: Literal["release_gate", "project_analysis", "dependency_diff", "artifact_verification"]
    | None = None,
) -> list[dict]:
    return store.list(limit=limit, kind=kind)


@app.get("/api/v1/analyses/{analysis_id}", dependencies=[Auth])
def get_analysis(analysis_id: str, store: StoreDep) -> dict:
    return _record_or_404(store, analysis_id).model_dump(mode="json")


@app.get("/api/v1/analyses/{analysis_id}/decision", dependencies=[Auth])
def get_decision(analysis_id: str, store: StoreDep) -> dict:
    record = _record_or_404(store, analysis_id)
    if record.decision is None:
        raise HTTPException(status_code=404, detail="no decision for this analysis")
    return record.decision.model_dump(mode="json")


@app.get("/api/v1/analyses/{analysis_id}/evidence", dependencies=[Auth])
def list_evidence(analysis_id: str, store: StoreDep) -> list[dict]:
    _record_or_404(store, analysis_id)
    return store.evidence_list(analysis_id)


@app.get("/api/v1/analyses/{analysis_id}/evidence/{name}", dependencies=[Auth])
def get_evidence(analysis_id: str, name: str, store: StoreDep) -> Response:
    _record_or_404(store, analysis_id)
    if not EVIDENCE_NAME.match(name):
        raise HTTPException(status_code=404, detail="evidence not found")
    found = store.evidence(analysis_id, name)
    if found is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    content, media = found
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}-{name}"'},
    )


@app.get(
    "/api/v1/analyses/{analysis_id}/report.md",
    dependencies=[Auth],
    response_class=PlainTextResponse,
)
def get_report_md(analysis_id: str, store: StoreDep) -> PlainTextResponse:
    from sentinel.reporting.reports import to_markdown

    return PlainTextResponse(
        to_markdown(_record_or_404(store, analysis_id)), media_type="text/markdown"
    )


@app.get("/api/v1/audit", dependencies=[Auth])
def audit(store: StoreDep, limit: int = 100) -> list[dict]:
    return store.audit_entries(limit=limit)
