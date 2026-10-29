import json
from dataclasses import replace
from pathlib import Path

from sentinel.core.models import Inventory, ScanStatus, Severity
from sentinel.sbom.builder import build_sbom
from sentinel.scanners import osv

from ..conftest import EXAMPLES, FIXTURES

VULN_DIR = EXAMPLES / "01-vulnerable-dependency"
RECORDED = VULN_DIR / "evidence" / "osv-scanner.recorded.json"
SYNTHETIC = FIXTURES / "osv" / "synthetic-severity-cases.json"


def _inventory(settings) -> Inventory:
    return build_sbom(VULN_DIR / "project", settings).inventory


def test_recorded_scan_normalises_real_advisories(settings):
    scan = osv.load_recorded(RECORDED, _inventory(settings))
    assert scan.status == ScanStatus.COMPLETED
    assert scan.mode.value == "recorded"
    assert scan.recorded_at and scan.scanner_version
    assert scan.packages_scanned == 8
    pyyaml = next(v for v in scan.vulnerabilities if "CVE-2020-14343" in v.aliases)
    assert pyyaml.package == "pyyaml"
    assert pyyaml.severity == Severity.CRITICAL
    assert pyyaml.cvss_score == 9.8
    assert pyyaml.severity_source.startswith("osv-scanner max_severity")
    assert "5.4" in pyyaml.fixed_versions
    assert pyyaml.dependency_scope == "direct"
    assert pyyaml.references == [f"https://osv.dev/vulnerability/{pyyaml.id}"]


def test_aliased_advisories_are_grouped_once(settings):
    scan = osv.load_recorded(RECORDED, _inventory(settings))
    identities = [v.identity for v in scan.vulnerabilities]
    for i, a in enumerate(identities):
        for b in identities[i + 1 :]:
            assert not (a & b), "the same vulnerability was reported twice"


def test_version_canonicalisation_links_scope(settings):
    """OSV reports idna 2.10.0 while the lockfile pins 2.10; scope must still resolve."""
    scan = osv.load_recorded(RECORDED, _inventory(settings))
    idna = [v for v in scan.vulnerabilities if v.package == "idna"]
    assert idna and all(v.dependency_scope == "transitive" for v in idna)
    assert all(v.introduced_via == ["requests"] for v in idna)


def test_results_sorted_by_severity(settings):
    scan = osv.load_recorded(RECORDED, _inventory(settings))
    ranks = [v.severity.rank for v in scan.vulnerabilities]
    assert ranks == sorted(ranks, reverse=True)


def test_severity_fallbacks_never_invent_scores():
    data = json.loads(SYNTHETIC.read_text())["output"]
    vulns, scanned, _ = osv.normalize_output(data)
    by_id = {v.id: v for v in vulns}
    assert scanned == 1
    assert by_id["GHSA-test-label-only"].severity == Severity.MEDIUM  # "MODERATE" label
    assert by_id["GHSA-test-label-only"].cvss_score is None
    assert by_id["GHSA-test-no-severity"].severity == Severity.UNKNOWN
    assert by_id["GHSA-test-no-severity"].severity_source is None
    assert by_id["GHSA-test-no-severity"].remediation == "The advisory data lists no fixed version."


def _scan():
    return osv.VulnerabilityScan(status=ScanStatus.ERROR)


def test_interpret_exit_codes():
    assert osv._interpret(_scan(), 128, b"", "", None, None).status == ScanStatus.NO_PACKAGES
    err = osv._interpret(
        _scan(), 127, b"", "dial tcp: lookup api.osv.dev: no such host", None, None
    )
    assert err.status == ScanStatus.ERROR
    assert err.data_source_available is False
    assert osv._interpret(_scan(), 0, b"not json", "", None, None).status == ScanStatus.ERROR
    assert osv._interpret(_scan(), 0, b'{"x": 1}', "", None, None).status == ScanStatus.ERROR
    # exit 1 means "vulnerabilities found"; an empty list is a contradiction, not "clean"
    empty = osv._interpret(_scan(), 1, b'{"results": []}', "", None, None)
    assert empty.status == ScanStatus.ERROR
    clean = osv._interpret(_scan(), 0, b'{"results": []}', "", None, None)
    assert clean.status == ScanStatus.COMPLETED and clean.data_source_available is True


def test_live_scan_with_missing_binary_is_unavailable(settings):
    inv = _inventory(settings)
    scan = osv.scan_live(VULN_DIR / "project", inv, settings)
    assert scan.status == ScanStatus.UNAVAILABLE
    assert scan.vulnerabilities == []
    assert "not found" in scan.errors[0]


def test_live_scan_timeout_is_reported(settings, tmp_path: Path):
    stub = tmp_path / "slow-osv"
    stub.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n")
    stub.chmod(0o755)
    slow = replace(settings, osv_bin=str(stub), osv_timeout=1)
    scan = osv.scan_live(VULN_DIR / "project", _inventory(settings), slow)
    assert scan.status == ScanStatus.TIMEOUT
    assert "timed out" in scan.errors[0]


def test_live_scan_without_lockfiles(settings, tmp_path: Path):
    (tmp_path / "go.mod").write_text("module x\n")
    stub = tmp_path / "osv"
    stub.write_text("#!/usr/bin/env python3\nprint('{}')\n")
    stub.chmod(0o755)
    inv = build_sbom(tmp_path, settings).inventory
    scan = osv.scan_live(tmp_path, inv, replace(settings, osv_bin=str(stub)))
    assert scan.status == ScanStatus.NO_PACKAGES


def test_recording_without_metadata_is_rejected(tmp_path: Path):
    bad = tmp_path / "rec.json"
    bad.write_text(json.dumps({"results": []}))
    scan = osv.load_recorded(bad)
    assert scan.status == ScanStatus.ERROR
    assert "metadata" in scan.errors[0]
