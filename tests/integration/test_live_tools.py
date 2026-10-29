"""Tests against the real Syft / OSV-Scanner / Cosign binaries.

Skipped automatically when a tool is not installed. OSV tests also need network
access to api.osv.dev and are marked ``live`` so CI can select or exclude them.
"""

import shutil
from dataclasses import replace

import pytest

from sentinel.core.models import ScanStatus, SignatureStatus
from sentinel.core.runner import run_tool
from sentinel.sbom.builder import build_sbom
from sentinel.scanners import osv
from sentinel.signing import keys
from sentinel.signing.verify import verify_artifact

from ..conftest import EXAMPLES

needs_syft = pytest.mark.skipif(shutil.which("syft") is None, reason="syft not installed")
needs_osv = pytest.mark.skipif(
    shutil.which("osv-scanner") is None, reason="osv-scanner not installed"
)
needs_cosign = pytest.mark.skipif(shutil.which("cosign") is None, reason="cosign not installed")


@needs_syft
def test_syft_sbom_is_valid_and_enriched(settings):
    live = replace(settings, use_syft="auto")
    build = build_sbom(EXAMPLES / "01-vulnerable-dependency" / "project", live)
    sbom = build.inventory.sbom
    assert sbom.generator == "syft" and sbom.mode.value == "live"
    assert sbom.validation.valid, sbom.validation.errors
    comps = {c.name: c for c in build.inventory.components}
    assert comps["pyyaml"].scope == "direct" and comps["urllib3"].scope == "transitive"
    assert str(EXAMPLES) not in build.raw.decode()  # no host paths in the SBOM


@needs_syft
def test_syft_npm_root_package_is_subject_not_dependency(settings):
    live = replace(settings, use_syft="auto")
    build = build_sbom(EXAMPLES / "03-dependency-drift" / "project", live)
    assert "notification-service" not in {c.name for c in build.inventory.components}
    assert build.document["metadata"]["component"]["name"] == "notification-service"


@pytest.mark.live
@needs_osv
def test_osv_live_scan_finds_known_vulnerability(settings):
    live = replace(settings, osv_bin="osv-scanner")
    project = EXAMPLES / "01-vulnerable-dependency" / "project"
    inv = build_sbom(project, settings).inventory
    scan = osv.scan_live(project, inv, live)
    if scan.status == ScanStatus.ERROR and scan.data_source_available is False:
        pytest.skip("OSV API unreachable from this environment")
    assert scan.status == ScanStatus.COMPLETED
    assert any("CVE-2020-14343" in v.aliases for v in scan.vulnerabilities)
    assert scan.packages_scanned == 8


@needs_cosign
def test_cosign_accepts_native_bundle_and_rejects_tampering(signed_artifact, keypair, settings):
    artifact, bundle = signed_artifact
    cmd = [
        "cosign",
        "verify-blob",
        "--key",
        str(keypair[1]),
        "--bundle",
        str(bundle),
        "--insecure-ignore-tlog=true",
        str(artifact),
    ]
    assert run_tool(cmd, timeout=60).returncode == 0
    artifact.write_bytes(b"tampered")
    assert run_tool(cmd, timeout=60).returncode != 0


@needs_cosign
def test_cross_check_with_cosign_cli(signed_artifact, keypair, settings):
    artifact, bundle = signed_artifact
    with_cosign = replace(settings, use_cosign="auto")
    result = verify_artifact(artifact, bundle, [keys.load_public_key(keypair[1])], with_cosign)
    assert result.verified and result.cosign_verified is True
    assert "cosign-verify-blob" in result.methods
    artifact.write_bytes(b"tampered")
    result = verify_artifact(artifact, bundle, [keys.load_public_key(keypair[1])], with_cosign)
    assert result.status == SignatureStatus.DIGEST_MISMATCH and result.cosign_verified is False
