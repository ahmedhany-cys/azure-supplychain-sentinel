import json
from dataclasses import replace

import pytest

from sentinel import cli

from ..conftest import EXAMPLES, FIXTURES


@pytest.fixture(autouse=True)
def offline(settings, monkeypatch):
    monkeypatch.setattr(cli, "get_settings", lambda: settings)


@pytest.mark.parametrize(
    "scenario,code",
    [
        ("01-vulnerable-dependency", 1),
        ("02-clean-release", 0),
        ("03-dependency-drift", 2),
        ("04-tampered-artifact", 1),
        ("05-missing-provenance", 1),
    ],
)
def test_gate_exit_codes(scenario, code, capsys):
    assert cli.main(["gate", str(EXAMPLES / scenario / "release.yaml")]) == code
    assert "policy default-release-policy@1.0.0" in capsys.readouterr().out


def test_gate_writes_evidence_directory(tmp_path):
    out = tmp_path / "evidence"
    cli.main(
        ["gate", str(EXAMPLES / "02-clean-release" / "release.yaml"), "--out", str(out), "--store"]
    )
    names = {p.name for p in out.iterdir()}
    assert {
        "sbom.cdx.json",
        "vulnerabilities.json",
        "signature-verification.json",
        "provenance-verification.json",
        "decision.json",
        "report.md",
        "report.json",
    } <= names
    assert json.loads((out / "decision.json").read_text())["result"] == "PASS"


def test_gate_json_output(capsys):
    cli.main(["gate", str(EXAMPLES / "04-tampered-artifact" / "release.yaml"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["signature"]["status"] == "digest_mismatch"


def test_live_scan_override_without_scanner_is_indeterminate():
    code = cli.main(
        ["gate", str(EXAMPLES / "02-clean-release" / "release.yaml"), "--scan-mode", "live"]
    )
    assert code == 2


def test_sbom_and_validate(tmp_path):
    out = tmp_path / "sbom.json"
    assert (
        cli.main(["sbom", str(EXAMPLES / "01-vulnerable-dependency" / "project"), "-o", str(out)])
        == 0
    )
    assert cli.main(["validate-sbom", str(out)]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{}]}')
    assert cli.main(["validate-sbom", str(bad)]) == 1


def test_diff_command(capsys):
    base = EXAMPLES / "03-dependency-drift" / "baseline.cdx.json"
    assert cli.main(["diff", str(base), str(base)]) == 0


def test_verify_command():
    art = FIXTURES / "signing" / "release-signed-by-untrusted-key.tar.gz"
    assert cli.main(["verify", str(art), "--bundle", f"{art}.sigstore.json"]) == 1


def test_keygen_and_sign_round_trip(tmp_path, monkeypatch, settings):
    monkeypatch.setenv("SENTINEL_SIGNING_PASSWORD", "cli-test-password")
    assert cli.main(["keygen", "--out-dir", str(tmp_path / "k")]) == 0
    art = tmp_path / "a.bin"
    art.write_bytes(b"payload")
    assert cli.main(["sign", str(art), "--key", str(tmp_path / "k" / "sentinel-dev.key")]) == 0
    assert (tmp_path / "a.bin.sigstore.json").exists()


def test_input_errors_exit_3(tmp_path, capsys):
    assert cli.main(["gate", str(tmp_path / "missing.yaml")]) == 3
    assert "error:" in capsys.readouterr().err


def test_demo_check(settings, monkeypatch):
    fast = replace(settings)
    monkeypatch.setattr(cli, "get_settings", lambda: fast)
    assert cli.main(["demo", "--check"]) == 0
    assert cli.main(["demo", "--scenario", "nope"]) == 3


def test_policy_command(capsys):
    assert cli.main(["policy"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "default-release-policy"


def test_sbom_output_creates_parent_directories(tmp_path):
    out = tmp_path / "reports" / "nested" / "sbom.cdx.json"
    assert cli.main(["sbom", str(EXAMPLES / "02-clean-release" / "project"), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["bomFormat"] == "CycloneDX"
