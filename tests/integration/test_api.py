from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from sentinel.api.main import app, settings_dep

from ..conftest import EXAMPLES, FIXTURES

SCEN02 = EXAMPLES / "02-clean-release"
DIST02 = SCEN02 / "dist"


@pytest.fixture
def client(settings):
    app.dependency_overrides[settings_dep] = lambda: settings
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def token_client(settings):
    secured = replace(settings, api_token="t0ken-for-tests")
    app.dependency_overrides[settings_dep] = lambda: secured
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health_and_security_headers(client):
    res = client.get("/health")
    assert res.status_code == 200 and res.json()["status"] == "ok"
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"


def test_policy_endpoint(client):
    body = client.get("/api/v1/policy").json()
    assert body["name"] == "default-release-policy"
    assert body["trusted_keys"][0]["name"] == "sentinel-demo-release"


def test_gate_then_fetch_record_evidence_and_report(client):
    res = client.post(
        "/api/v1/releases/gate",
        json={"release_path": str(EXAMPLES / "01-vulnerable-dependency" / "release.yaml")},
    )
    assert res.status_code == 201, res.text
    summary = res.json()
    assert summary["result"] == "FAIL"
    aid = summary["id"]
    record = client.get(f"/api/v1/analyses/{aid}").json()
    assert record["vulnerability_scan"]["mode"] == "recorded"
    assert client.get(f"/api/v1/analyses/{aid}/decision").json()["result"] == "FAIL"
    names = {e["name"] for e in client.get(f"/api/v1/analyses/{aid}/evidence").json()}
    assert "sbom.cdx.json" in names
    sbom = client.get(f"/api/v1/analyses/{aid}/evidence/sbom.cdx.json")
    assert sbom.status_code == 200 and sbom.json()["bomFormat"] == "CycloneDX"
    assert "attachment" in sbom.headers["content-disposition"]
    report = client.get(f"/api/v1/analyses/{aid}/report.md")
    assert report.status_code == 200 and "Decision: **FAIL**" in report.text
    listing = client.get("/api/v1/analyses").json()
    assert listing[0]["id"] == aid
    assert client.get("/api/v1/audit").json()[0]["analysis_id"] == aid


def test_paths_outside_allowed_roots_are_rejected(client):
    for path in ["/etc", "/etc/passwd", str(EXAMPLES / ".." / "sentinel")]:
        res = client.post("/api/v1/analyses/project", json={"project_path": path})
        assert res.status_code == 400
        assert "allowed analysis root" in res.json()["detail"]


def test_project_analysis_with_unavailable_scanner_is_indeterminate(client):
    res = client.post(
        "/api/v1/analyses/project",
        json={"project_path": str(SCEN02 / "project"), "scan_mode": "live"},
    )
    assert res.status_code == 201
    assert res.json()["result"] == "INDETERMINATE"
    assert any("Source-only analysis" in r for r in res.json()["reasons"])


def test_recorded_project_analysis(client):
    res = client.post(
        "/api/v1/analyses/project",
        json={
            "project_path": str(SCEN02 / "project"),
            "scan_mode": "recorded",
            "recording_path": str(SCEN02 / "evidence" / "osv-scanner.recorded.json"),
        },
    )
    assert res.json()["result"] == "PASS"


def test_verify_upload_valid_and_tampered(client):
    art = DIST02 / "billing-api-1.8.0.tar.gz"
    bundle = DIST02 / f"{art.name}.sigstore.json"
    ok = client.post(
        "/api/v1/verify",
        files={
            "artifact": (art.name, art.read_bytes()),
            "bundle": (bundle.name, bundle.read_bytes()),
        },
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["result"] == "PASS"
    assert ok.json()["signature"]["status"] == "verified"
    bad = client.post(
        "/api/v1/verify",
        files={
            "artifact": (art.name, art.read_bytes() + b"x"),
            "bundle": (bundle.name, bundle.read_bytes()),
        },
    )
    assert bad.json()["result"] == "FAIL"
    assert bad.json()["signature"]["status"] == "digest_mismatch"


def test_verify_untrusted_signer(client):
    art = FIXTURES / "signing" / "release-signed-by-untrusted-key.tar.gz"
    bundle = FIXTURES / "signing" / f"{art.name}.sigstore.json"
    res = client.post(
        "/api/v1/verify",
        files={
            "artifact": (art.name, art.read_bytes()),
            "bundle": (bundle.name, bundle.read_bytes()),
        },
    )
    assert res.json()["signature"]["status"] == "untrusted_signer"


def test_verify_rejects_bad_expected_digest_and_traversal_filename(client):
    art = DIST02 / "billing-api-1.8.0.tar.gz"
    res = client.post(
        "/api/v1/verify",
        data={"expected_sha256": "nothex"},
        files={"artifact": ("x", art.read_bytes())},
    )
    assert res.status_code == 400
    res = client.post(
        "/api/v1/verify", files={"artifact": ("../../../../tmp/evil.sh", b"#!/bin/sh\necho hi\n")}
    )
    assert res.status_code == 201
    record = client.get(f"/api/v1/analyses/{res.json()['id']}").json()
    assert record["signature"]["artifact"] == "evil.sh"
    assert record["signature"]["status"] == "missing_signature"
    assert res.json()["result"] == "FAIL"


def test_upload_size_limit(client, settings):
    small = replace(settings, max_upload_bytes=10)
    app.dependency_overrides[settings_dep] = lambda: small
    res = client.post("/api/v1/verify", files={"artifact": ("a.bin", b"x" * 100)})
    assert res.status_code == 413


def test_diff_upload(client):
    base = EXAMPLES / "03-dependency-drift" / "baseline.cdx.json"
    res = client.post(
        "/api/v1/diff",
        files={
            "baseline": ("baseline.cdx.json", base.read_bytes()),
            "candidate": ("candidate.cdx.json", base.read_bytes()),
        },
    )
    assert res.status_code == 201 and res.json()["result"] == "PASS"
    bad = client.post(
        "/api/v1/diff",
        files={"baseline": ("b.json", b"{}"), "candidate": ("c.json", base.read_bytes())},
    )
    assert bad.status_code == 400 and "not a valid CycloneDX" in bad.json()["detail"]


def test_scenarios_endpoint(client):
    scenarios = client.get("/api/v1/scenarios").json()
    assert len(scenarios) == 6
    res = client.post("/api/v1/scenarios/04-tampered-artifact/run")
    assert res.json()["matched_expected"] is True
    assert client.post("/api/v1/scenarios/nope/run").status_code == 404


def test_unknown_or_malformed_ids(client):
    assert client.get("/api/v1/analyses/rel-000000000000").status_code == 404
    assert client.get("/api/v1/analyses/..%2F..%2Fetc").status_code == 404
    assert client.get("/api/v1/analyses/x' OR 1=1").status_code == 404


def test_token_auth(token_client):
    assert token_client.get("/health").status_code == 200
    assert token_client.get("/api/v1/analyses").status_code == 401
    assert (
        token_client.get("/api/v1/analyses", headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    assert (
        token_client.get(
            "/api/v1/analyses", headers={"Authorization": "Bearer t0ken-for-tests"}
        ).status_code
        == 200
    )


def test_invalid_payloads(client):
    assert client.post("/api/v1/releases/gate", json={}).status_code == 422
    assert (
        client.post(
            "/api/v1/analyses/project", json={"project_path": "x", "scan_mode": "magic"}
        ).status_code
        == 422
    )
    assert client.get("/api/v1/analyses?kind=bogus").status_code == 422
