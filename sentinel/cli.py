"""Command-line interface.

Exit codes for gate-style commands: 0 = PASS, 1 = FAIL, 2 = INDETERMINATE, 3 = usage/input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from sentinel import __version__
from sentinel.config import Settings, get_settings
from sentinel.core.models import DecisionResult
from sentinel.core.security import SecurityError, read_bounded
from sentinel.core.service import (
    Outcome,
    analyze_project,
    compare_sboms,
    gate_release,
    verify_upload,
)
from sentinel.policies.model import load_policy
from sentinel.reporting.reports import to_markdown
from sentinel.sbom import cyclonedx
from sentinel.sbom.builder import build_sbom
from sentinel.storage.db import Store

EXIT = {DecisionResult.PASS: 0, DecisionResult.FAIL: 1, DecisionResult.INDETERMINATE: 2}
COLOR = {"PASS": "\033[32m", "FAIL": "\033[31m", "INDETERMINATE": "\033[33m"}


def _settings(args: argparse.Namespace) -> Settings:
    settings = get_settings()
    if getattr(args, "policy", None):
        from dataclasses import replace

        settings = replace(settings, policy_path=Path(args.policy).resolve())
    return settings


def _emit(outcome: Outcome, args: argparse.Namespace) -> int:
    record = outcome.record
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for name, (content, _) in outcome.evidence.items():
            (out / name).write_bytes(content)
    if args.format == "json":
        print(record.model_dump_json(indent=2))
    elif args.format == "md":
        print(to_markdown(record))
    else:
        decision = record.decision
        if decision is None:
            print(f"{record.name}: no decision produced", file=sys.stderr)
            return 3
        tty = sys.stdout.isatty()
        color, reset = (COLOR[decision.result.value], "\033[0m") if tty else ("", "")
        print(
            f"{record.name}: {color}{decision.result.value}{reset}  "
            f"(policy {decision.policy_name}@{decision.policy_version}, id {record.id})"
        )
        for check in decision.checks:
            req = "required" if check.required else "optional"
            print(f"  {check.status.value:<14} {check.title} [{req}] - {check.summary}")
        print()
        for line in decision.reasons:
            print(f"  {line}")
        if args.out:
            print(f"\n  evidence written to {args.out}/")
    return EXIT[record.decision.result] if record.decision else 3


def cmd_gate(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = Store(settings.db_path) if args.store else None
    outcome = gate_release(Path(args.release), settings, store=store, scan_mode=args.scan_mode)
    return _emit(outcome, args)


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = Store(settings.db_path) if args.store else None
    recording = Path(args.recorded) if args.recorded else None
    outcome = analyze_project(
        Path(args.project).resolve(),
        settings,
        store=store,
        scan_mode="recorded" if recording else "live",
        recording=recording,
    )
    return _emit(outcome, args)


def cmd_sbom(args: argparse.Namespace) -> int:
    settings = _settings(args)
    build = build_sbom(Path(args.project).resolve(), settings)
    info = build.inventory.sbom
    if args.output:
        Path(args.output).write_bytes(build.raw or b"")
    print(
        f"generator: {info.generator} {info.generator_version or ''} ({info.mode.value})",
        file=sys.stderr,
    )
    print(
        f"components: {len(build.inventory.components)}; valid: {info.validation.valid}",
        file=sys.stderr,
    )
    for warning in build.inventory.discovery.warnings if build.inventory.discovery else []:
        print(f"warning: {warning}", file=sys.stderr)
    for err in info.validation.errors + info.errors:
        print(f"error: {err}", file=sys.stderr)
    if not args.output:
        sys.stdout.write((build.raw or b"").decode())
    return 0 if info.validation.valid else 1


def cmd_validate(args: argparse.Namespace) -> int:
    result = cyclonedx.validate(read_bounded(Path(args.sbom), 25 * 1024 * 1024))
    print(result.model_dump_json(indent=2))
    return 0 if result.valid else 1


def cmd_diff(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = Store(settings.db_path) if args.store else None
    baseline, candidate = Path(args.baseline), Path(args.candidate)
    outcome = compare_sboms(
        read_bounded(baseline, 25 * 1024 * 1024),
        read_bounded(candidate, 25 * 1024 * 1024),
        settings,
        store=store,
        baseline_label=baseline.name,
        candidate_label=candidate.name,
    )
    return _emit(outcome, args)


def cmd_verify(args: argparse.Namespace) -> int:
    settings = _settings(args)
    store = Store(settings.db_path) if args.store else None
    outcome = verify_upload(
        Path(args.artifact),
        Path(args.bundle) if args.bundle else None,
        settings,
        store=store,
        expected_sha256=args.expected_sha256,
        provenance=Path(args.provenance) if args.provenance else None,
    )
    return _emit(outcome, args)


def cmd_keygen(args: argparse.Namespace) -> int:
    from sentinel.signing.keys import generate_keypair

    priv, pub = generate_keypair(Path(args.out_dir), args.prefix)
    print(f"private key (encrypted, 0600): {priv}\npublic key: {pub}")
    print("Add the public key to signing.trusted_keys in your policy to trust this signer.")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    from sentinel.signing.bundle import sign_blob

    artifact = Path(args.artifact)
    bundle = Path(args.bundle or f"{artifact}.sigstore.json")
    sign_blob(artifact, Path(args.key), bundle)
    print(f"wrote {bundle}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from sentinel.demo import print_runs, run_scenarios

    settings = _settings(args)
    store = Store(settings.db_path) if args.store else None
    runs = run_scenarios(settings, only=args.scenario, store=store)
    if not runs:
        print(f"no scenario named {args.scenario!r}", file=sys.stderr)
        return 3
    print_runs(runs)
    if args.check and not all(r.matched for r in runs):
        return 1
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    loaded = load_policy(_settings(args).policy_path)
    summary = {
        "name": loaded.name,
        "version": loaded.version,
        "sha256": loaded.sha256,
        "required_checks": loaded.policy.required_checks,
        "trusted_keys": [k.info().model_dump() for k in loaded.trusted_keys],
    }
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel", description="Software supply-chain release gate"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def outputs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--policy", help="policy YAML (default: config/policy.default.yaml)")
        p.add_argument("--format", choices=["text", "json", "md"], default="text")
        p.add_argument("--out", help="directory to write evidence and reports to")
        p.add_argument(
            "--store", action="store_true", help="record the result in the local database"
        )

    p = sub.add_parser("gate", help="evaluate a release record against the policy")
    p.add_argument("release", help="path to release.yaml")
    p.add_argument(
        "--scan-mode",
        choices=["live", "recorded"],
        help="override the release record's vulnerability evidence mode",
    )
    outputs(p)
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("scan", help="source-only analysis: SBOM + vulnerability scan")
    p.add_argument("project")
    p.add_argument("--recorded", help="replay recorded osv-scanner output instead of scanning")
    outputs(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("sbom", help="generate a CycloneDX SBOM for a project directory")
    p.add_argument("project")
    p.add_argument("-o", "--output")
    p.add_argument("--policy")
    p.set_defaults(func=cmd_sbom)

    p = sub.add_parser("validate-sbom", help="validate a CycloneDX JSON SBOM")
    p.add_argument("sbom")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("diff", help="compare two CycloneDX SBOMs")
    p.add_argument("baseline")
    p.add_argument("candidate")
    outputs(p)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("verify", help="verify an artifact signature (and optional provenance)")
    p.add_argument("artifact")
    p.add_argument("--bundle", help="Sigstore bundle produced by cosign sign-blob --bundle")
    p.add_argument("--expected-sha256")
    p.add_argument("--provenance")
    outputs(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("keygen", help="generate an encrypted local development signing key")
    p.add_argument("--out-dir", default=".sentinel/keys")
    p.add_argument("--prefix", default="sentinel-dev")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="sign an artifact with a local development key")
    p.add_argument("artifact")
    p.add_argument("--key", required=True)
    p.add_argument("--bundle")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("demo", help="run the demonstration scenarios in examples/")
    p.add_argument("--scenario")
    p.add_argument("--check", action="store_true", help="exit 1 if any decision is unexpected")
    p.add_argument("--store", action="store_true")
    p.add_argument("--policy")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("policy", help="show the active policy and trust anchors")
    p.add_argument("--policy")
    p.set_defaults(func=cmd_policy)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (SecurityError, ValidationError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
