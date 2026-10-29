#!/usr/bin/env python3
"""Build the signed demonstration fixtures under ``examples/``.

What it does, per scenario:

* packs the scenario's ``project/`` into a deterministic ``dist/<name>-<version>.tar.gz``;
* signs it with a freshly generated demo key (Cosign when installed, otherwise the
  built-in ECDSA P-256 implementation) and writes a Sigstore bundle;
* creates an in-toto/SLSA v1 provenance attestation signed by the same key;
* applies the scenario's deliberate defect (tampering, missing provenance, ...);
* optionally records live osv-scanner output for deterministic replay (``--record-osv``);
* writes ``release.yaml`` and ``examples/fixture-manifest.json``.

The demo private key lives only in a 0700 temporary directory and is destroyed when
the script exits. Only the public key is written to ``config/keys/``. Re-running the
script therefore rotates the demo key and invalidates the previous fixtures.

Usage:  python scripts/build_demo_fixtures.py [--record-osv] [--native]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import secrets
import shutil
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel.config import Settings  # noqa: E402
from sentinel.core.runner import run_tool, tool_version, which  # noqa: E402
from sentinel.core.security import private_tempdir, sha256_file  # noqa: E402
from sentinel.provenance.dsse import sign_statement  # noqa: E402
from sentinel.provenance.slsa import build_statement  # noqa: E402
from sentinel.sbom.builder import build_sbom  # noqa: E402
from sentinel.signing import keys as native_keys  # noqa: E402
from sentinel.signing.bundle import sign_blob  # noqa: E402

EXAMPLES = ROOT / "examples"
BUILDER_ID = "https://sentinel.local/builders/demo-fixture-builder@v1"
BUILD_TYPE = "https://sentinel.local/build-types/python-sdist-tarball@v1"
EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z, fixed mtime for reproducible tarballs
EMPTY_SIGNING_CONFIG = {
    "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
    "caUrls": [],
    "oidcUrls": [],
    "rekorTlogUrls": [],
    "tsaUrls": [],
    "rekorTlogConfig": {"selector": "ANY"},
    "tsaConfig": {"selector": "ANY"},
}

SCENARIOS = [
    {
        "dir": "01-vulnerable-dependency",
        "name": "payments-api",
        "version": "2.3.0",
        "description": "Release whose dependency set contains publicly disclosed vulnerabilities.",
    },
    {
        "dir": "02-clean-release",
        "name": "billing-api",
        "version": "1.8.0",
        "description": "Release with complete, valid evidence and no blocking findings.",
    },
    {
        "dir": "03-dependency-drift",
        "name": "notification-service",
        "version": "3.2.0",
        "description": "Release that adds an unapproved dependency and moves transitive versions.",
        "baseline": "baseline-project",
    },
    {
        "dir": "04-tampered-artifact",
        "name": "payments-api",
        "version": "2.3.1",
        "description": "Release artifact modified after it was signed.",
        "tamper": True,
    },
    {
        "dir": "05-missing-provenance",
        "name": "reporting-worker",
        "version": "0.9.0",
        "description": "Signed release without any build provenance.",
        "no_provenance": True,
    },
    {
        "dir": "06-scanner-unavailable",
        "name": "billing-api",
        "version": "1.8.1",
        "description": "Release evaluated while the vulnerability scanner times out.",
        "live_scan": True,
    },
]


def deterministic_tarball(src: Path, dest: Path, prefix: str) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(p for p in src.rglob("*") if p.is_file()):
            rel = path.relative_to(src)
            if "node_modules" in rel.parts:
                continue
            info = tarfile.TarInfo(f"{prefix}/{rel.as_posix()}")
            data = path.read_bytes()
            info.size, info.mtime, info.mode = len(data), EPOCH, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=EPOCH) as gz:
        gz.write(buf.getvalue())


def source_revision(project: Path) -> str:
    """Synthetic, deterministic 40-hex 'revision' for the fictional demo repository."""
    digest = hashlib.sha1(usedforsecurity=False)
    for path in sorted(p for p in project.rglob("*") if p.is_file()):
        digest.update(path.relative_to(project).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


class Signer:
    """Signs blobs and attestations with an ephemeral key; Cosign preferred."""

    def __init__(self, workdir: Path, settings: Settings, force_native: bool) -> None:
        self.workdir = workdir
        self.settings = settings
        self.use_cosign = not force_native and which(settings.cosign_bin) is not None
        self.password = secrets.token_urlsafe(24)
        self.signing_config = workdir / "signing-config.json"
        self.signing_config.write_text(json.dumps(EMPTY_SIGNING_CONFIG))
        self.tool = (
            f"cosign {tool_version(settings.cosign_bin, ['version'])}"
            if self.use_cosign
            else "sentinel native ECDSA P-256"
        )

    def generate(self, prefix: str) -> tuple[Path, Path]:
        if self.use_cosign:
            result = run_tool(
                [
                    self.settings.cosign_bin,
                    "generate-key-pair",
                    "--output-key-prefix",
                    str(self.workdir / prefix),
                ],
                timeout=60,
                cwd=self.workdir,
                env_extra={"COSIGN_PASSWORD": self.password},
            )
            if not result.ok:
                raise SystemExit(f"cosign generate-key-pair failed: {result.stderr}")
            return self.workdir / f"{prefix}.key", self.workdir / f"{prefix}.pub"
        os.environ[native_keys.PASSWORD_ENV] = self.password
        return native_keys.generate_keypair(self.workdir, prefix)

    def sign(self, key: Path, artifact: Path, bundle: Path) -> None:
        if self.use_cosign:
            self._cosign(
                [
                    "sign-blob",
                    "--yes",
                    "--key",
                    str(key),
                    "--signing-config",
                    str(self.signing_config),
                    "--bundle",
                    str(bundle),
                    str(artifact),
                ]
            )
        else:
            sign_blob(artifact, key, bundle)

    def attest(self, key: Path, artifact: Path, statement: dict, out: Path) -> None:
        if self.use_cosign:
            predicate = self.workdir / "predicate.json"
            predicate.write_text(json.dumps(statement["predicate"]))
            self._cosign(
                [
                    "attest-blob",
                    "--yes",
                    "--key",
                    str(key),
                    "--signing-config",
                    str(self.signing_config),
                    "--predicate",
                    str(predicate),
                    "--type",
                    "slsaprovenance1",
                    "--bundle",
                    str(out),
                    str(artifact),
                ]
            )
        else:
            envelope = sign_statement(statement, native_keys.load_private_key(key))
            out.write_text(json.dumps(envelope, indent=2))

    def _cosign(self, args: list[str]) -> None:
        result = run_tool(
            [self.settings.cosign_bin, *args],
            timeout=120,
            cwd=self.workdir,
            env_extra={"COSIGN_PASSWORD": self.password},
        )
        if not result.ok:
            raise SystemExit(f"cosign {args[0]} failed: {result.stderr}")


def record_osv(project: Path, out: Path, settings: Settings) -> dict:
    lockfiles = sorted(
        p
        for p in project.iterdir()
        if p.name in {"package-lock.json", "poetry.lock"}
        or (p.name.startswith("requirements") and p.suffix == ".txt")
    )
    argv = [settings.osv_bin, "scan", "source", "--format", "json", "--all-packages"]
    for lock in lockfiles:
        argv += ["--lockfile", str(lock)]
    result = run_tool(argv, timeout=settings.osv_timeout)
    if result.returncode not in (0, 1):
        raise SystemExit(f"osv-scanner failed ({result.returncode}): {result.stderr[:400]}")
    output = json.loads(result.stdout)
    for res in output.get("results", []):  # do not leak local absolute paths
        src = res.get("source", {})
        if src.get("path"):
            src["path"] = Path(src["path"]).name
    wrapper = {
        "recording": {
            "tool": "osv-scanner",
            "tool_version": tool_version(settings.osv_bin, ["--version"]),
            "captured_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "command": [
                "osv-scanner",
                "scan",
                "source",
                "--format",
                "json",
                "--all-packages",
                *[a for lock in lockfiles for a in ("--lockfile", lock.name)],
            ],
            "exit_code": result.returncode,
            "targets": [lock.name for lock in lockfiles],
            "note": "Recorded for deterministic, offline demonstrations. Re-record with "
            "scripts/build_demo_fixtures.py --record-osv.",
        },
        "output": output,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(wrapper, indent=2) + "\n")
    vulns = sum(
        len(p.get("vulnerabilities", []))
        for r in output.get("results", [])
        for p in r.get("packages", [])
    )
    return {"file": out.name, "exit_code": result.returncode, "vulnerability_records": vulns}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--record-osv",
        action="store_true",
        help="re-record osv-scanner output (requires network access)",
    )
    parser.add_argument("--native", action="store_true", help="do not use Cosign")
    args = parser.parse_args()
    settings = Settings()
    now = datetime.now(UTC).replace(microsecond=0)
    manifest: dict = {"generated_at": now.isoformat(), "scenarios": {}}

    with private_tempdir("sentinel-demo-keys-") as workdir:
        signer = Signer(workdir, settings, args.native)
        manifest["signing_tool"] = signer.tool
        demo_key, demo_pub = signer.generate("sentinel-demo-release")
        shutil.copyfile(demo_pub, ROOT / "config" / "keys" / "sentinel-demo-release.pub")

        # Untrusted-signer fixture used by tests and the Artifact Trust page.
        rogue_key, rogue_pub = signer.generate("untrusted-signer")
        fixtures = ROOT / "fixtures" / "signing"
        fixtures.mkdir(parents=True, exist_ok=True)
        rogue_artifact = fixtures / "release-signed-by-untrusted-key.tar.gz"
        deterministic_tarball(
            EXAMPLES / "02-clean-release" / "project", rogue_artifact, "billing-api-1.8.0"
        )
        signer.sign(rogue_key, rogue_artifact, fixtures / f"{rogue_artifact.name}.sigstore.json")
        shutil.copyfile(rogue_pub, fixtures / "untrusted-signer.pub")

        for spec in SCENARIOS:
            sdir = EXAMPLES / spec["dir"]
            dist = sdir / "dist"
            if dist.exists():
                shutil.rmtree(dist)
            label = f"{spec['name']}-{spec['version']}"
            artifact = dist / f"{label}.tar.gz"
            deterministic_tarball(sdir / "project", artifact, label)
            original_sha = sha256_file(artifact)
            bundle = dist / f"{label}.tar.gz.sigstore.json"
            signer.sign(demo_key, artifact, bundle)
            repo = f"https://example.com/demo/{spec['name']}.git"
            revision = source_revision(sdir / "project")
            prov_path = None
            if not spec.get("no_provenance"):
                prov_path = dist / f"{label}.provenance.sigstore.json"
                started = now - timedelta(minutes=4)
                statement = build_statement(
                    artifact_name=artifact.name,
                    artifact_sha256=original_sha,
                    builder_id=BUILDER_ID,
                    build_type=BUILD_TYPE,
                    source_uri=repo,
                    source_revision=revision,
                    invocation_id=f"demo-{spec['dir']}",
                    started_on=started.isoformat().replace("+00:00", "Z"),
                    finished_on=(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
                    external_parameters={
                        "source": repo,
                        "ref": "refs/heads/main",
                        "artifact": artifact.name,
                    },
                )
                signer.attest(demo_key, artifact, statement, prov_path)
            if spec.get("tamper"):
                # Simulate a post-signing modification: same file name, different content.
                tampered = sdir / "project-tampered"
                if tampered.exists():
                    shutil.rmtree(tampered)
                shutil.copytree(sdir / "project", tampered)
                with (tampered / "app.py").open("a") as handle:
                    handle.write("\n# Modified after signing (demonstration of tampering).\n")
                deterministic_tarball(tampered, artifact, label)
                shutil.rmtree(tampered)

            record: dict = {
                "apiVersion": "sentinel.dev/v1",
                "kind": "ReleaseCandidate",
                "metadata": {
                    "name": spec["name"],
                    "version": spec["version"],
                    "description": spec["description"],
                },
                "project": "project",
                "artifact": {
                    "path": f"dist/{artifact.name}",
                    "signature_bundle": f"dist/{bundle.name}",
                },
                "source": {"repository": repo, "revision": revision},
                "evidence": {
                    "vulnerability_scan": (
                        {"mode": "live"}
                        if spec.get("live_scan")
                        else {"mode": "recorded", "path": "evidence/osv-scanner.recorded.json"}
                    )
                },
            }
            if spec.get("tamper"):
                record["artifact"]["expected_sha256"] = original_sha
            if prov_path:
                record["provenance"] = f"dist/{prov_path.name}"
            entry: dict = {"artifact_sha256": sha256_file(artifact), "signed_sha256": original_sha}
            if spec.get("baseline"):
                base_project = sdir / spec["baseline"]
                build = build_sbom(base_project, settings, project_name=spec["name"])
                (sdir / "baseline.cdx.json").write_bytes(build.raw)
                record["baseline_sbom"] = "baseline.cdx.json"
                record["evidence"]["baseline_vulnerability_scan"] = {
                    "mode": "recorded",
                    "path": "evidence/baseline-osv-scanner.recorded.json",
                }
                entry["baseline_sbom_generator"] = build.inventory.sbom.generator
                if args.record_osv:
                    entry["baseline_osv"] = record_osv(
                        base_project,
                        sdir / "evidence" / "baseline-osv-scanner.recorded.json",
                        settings,
                    )
            if args.record_osv and not spec.get("live_scan"):
                entry["osv"] = record_osv(
                    sdir / "project", sdir / "evidence" / "osv-scanner.recorded.json", settings
                )
            header = (
                f"# Release record for demonstration scenario {spec['dir']}.\n"
                "# Generated by scripts/build_demo_fixtures.py; paths are relative to "
                "this file\n# and may not leave this directory.\n"
            )
            (sdir / "release.yaml").write_text(header + yaml.safe_dump(record, sort_keys=False))
            manifest["scenarios"][spec["dir"]] = entry
            print(f"built {spec['dir']}: {artifact.name}")
        # Private keys are deleted with the temporary directory here.

    manifest["demo_public_key_sha256"] = sha256_file(
        ROOT / "config" / "keys" / "sentinel-demo-release.pub"
    )
    (EXAMPLES / "fixture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"signing tool: {manifest['signing_tool']}; demo private key destroyed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
