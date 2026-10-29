"""Shared fixtures. Unit tests never need network access or external tools."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from sentinel.config import REPO_ROOT, Settings
from sentinel.policies.model import load_policy
from sentinel.provenance.dsse import sign_statement
from sentinel.provenance.slsa import build_statement
from sentinel.signing import keys
from sentinel.signing.bundle import sign_blob

EXAMPLES = REPO_ROOT / "examples"
FIXTURES = REPO_ROOT / "fixtures"
TEST_PASSWORD = "unit-test-password-not-a-secret"
DEMO_BUILDER = "https://sentinel.local/builders/demo-fixture-builder@v1"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Offline settings: external tools disabled unless a test opts in."""
    return replace(
        Settings(),
        data_dir=tmp_path / "data",
        allowed_roots=[EXAMPLES.resolve(), tmp_path.resolve()],
        use_syft="off",
        use_cosign="off",
        osv_bin=str(tmp_path / "no-such-osv-scanner"),
    )


@pytest.fixture
def policy():
    return load_policy(REPO_ROOT / "config" / "policy.default.yaml")


@pytest.fixture
def keypair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(keys.PASSWORD_ENV, TEST_PASSWORD)
    priv, pub = keys.generate_keypair(tmp_path / "keys", "test-signer")
    return priv, pub


@pytest.fixture
def other_keypair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(keys.PASSWORD_ENV, TEST_PASSWORD)
    return keys.generate_keypair(tmp_path / "other-keys", "other-signer")


@pytest.fixture
def signed_artifact(tmp_path: Path, keypair):
    priv, _ = keypair
    artifact = tmp_path / "app-1.0.0.tar.gz"
    artifact.write_bytes(b"release payload v1.0.0\n" * 100)
    bundle = sign_blob(artifact, priv, tmp_path / "app-1.0.0.tar.gz.sigstore.json")
    return artifact, bundle


@pytest.fixture
def make_policy(tmp_path: Path, keypair):
    """Write a copy of the default policy that trusts the per-test key, with overrides."""

    def _make(**overrides) -> Path:
        data = yaml.safe_load((REPO_ROOT / "config" / "policy.default.yaml").read_text())
        _, pub = keypair
        data["signing"]["trusted_keys"] = [{"name": "test-signer", "path": str(pub)}]
        for dotted, value in overrides.items():
            target = data
            parts = dotted.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = value
        path = tmp_path / f"policy-{len(list(tmp_path.glob('policy-*.yaml')))}.yaml"
        path.write_text(yaml.safe_dump(data))
        return path

    return _make


@pytest.fixture
def make_provenance(tmp_path: Path, keypair):
    def _make(
        artifact_sha: str,
        *,
        builder: str = DEMO_BUILDER,
        sign: bool = True,
        key_path: Path | None = None,
        revision: str = "a" * 40,
        repo: str = "https://example.com/demo/app.git",
        mutate=None,
    ) -> Path:
        statement = build_statement(
            artifact_name="app-1.0.0.tar.gz",
            artifact_sha256=artifact_sha,
            builder_id=builder,
            build_type="https://example.com/build/v1",
            source_uri=repo,
            source_revision=revision,
            invocation_id="test-run",
            started_on="2026-01-01T00:00:00Z",
            finished_on="2026-01-01T00:05:00Z",
        )
        if mutate:
            mutate(statement)
        out = tmp_path / f"prov-{len(list(tmp_path.glob('prov-*.json')))}.json"
        if sign:
            envelope = sign_statement(statement, keys.load_private_key(key_path or keypair[0]))
            out.write_text(json.dumps(envelope))
        else:
            out.write_text(json.dumps(statement))
        return out

    return _make


@pytest.fixture
def scenario_copy(tmp_path: Path):
    """Copy an example scenario so a test can modify it safely."""

    def _copy(name: str) -> Path:
        dest = tmp_path / "scenarios" / name
        shutil.copytree(EXAMPLES / name, dest)
        return dest

    return _copy
