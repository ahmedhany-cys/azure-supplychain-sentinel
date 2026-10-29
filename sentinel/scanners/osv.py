"""OSV-Scanner integration and normalisation of its JSON output.

Severity is taken only from what the scanner/advisory data provides:

1. ``groups[].max_severity`` - the highest CVSS base score osv-scanner computed for
   the group of aliased advisories;
2. otherwise the advisory's ``database_specific.severity`` label (e.g. GHSA "HIGH");
3. otherwise ``UNKNOWN``. Unknown is never silently treated as low.

Exit codes of ``osv-scanner scan source`` (v2): 0 = no vulnerabilities, 1 = vulnerabilities
found, 128 = no packages found, anything else = error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.config import Settings
from sentinel.core.models import (
    EvidenceMode,
    Inventory,
    ScanStatus,
    Severity,
    Vulnerability,
    VulnerabilityScan,
    utcnow,
)
from sentinel.core.runner import run_tool, tool_version, which
from sentinel.core.security import (
    SecurityError,
    load_json_bounded,
    parse_json_bytes,
    sha256_bytes,
)
from sentinel.sbom.identity import component_key, normalize_name, version_key

OSV_SUPPORTED_LOCKFILES = ("requirements", "package-lock.json", "poetry.lock")
LIMITATIONS = [
    "Only publicly disclosed vulnerabilities present in OSV.dev at scan time are reported.",
    "Absence of findings does not prove the absence of vulnerabilities.",
    "Reachability of vulnerable code is not analysed.",
]


def _first_fixed(records: list[dict[str, Any]], ecosystem: str | None, name: str) -> list[str]:
    fixed: list[str] = []
    want = normalize_name(ecosystem, name)
    for record in records:
        for affected in record.get("affected") or []:
            pkg = affected.get("package") or {}
            if normalize_name(pkg.get("ecosystem"), str(pkg.get("name", ""))) != want:
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if "fixed" in event and event["fixed"] not in fixed:
                        fixed.append(str(event["fixed"]))
    return fixed


def _record_severity(records: list[dict[str, Any]]) -> tuple[Severity, str | None]:
    best = Severity.UNKNOWN
    for record in records:
        label = Severity.parse((record.get("database_specific") or {}).get("severity"))
        if label.rank > best.rank:
            best = label
    return (
        (best, "advisory database_specific.severity")
        if best != Severity.UNKNOWN
        else (Severity.UNKNOWN, None)
    )


def normalize_output(
    data: dict[str, Any], inventory: Inventory | None = None
) -> tuple[list[Vulnerability], int, list[str]]:
    """Return (vulnerabilities, packages_scanned, sources) from osv-scanner JSON output."""
    scope_index: dict[tuple[str, str | None], tuple[str, list[str]]] = {}
    if inventory is not None:
        for comp in inventory.components:
            scope_index[(comp.key, version_key(comp.ecosystem, comp.version))] = (
                comp.scope,
                comp.introduced_via,
            )

    findings: list[Vulnerability] = []
    packages_scanned = 0
    sources: list[str] = []
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path")
        if source:
            sources.append(str(source))
        for pkg_entry in result.get("packages") or []:
            packages_scanned += 1
            pkg = pkg_entry.get("package") or {}
            name, version, eco = str(pkg.get("name", "")), pkg.get("version"), pkg.get("ecosystem")
            records = {
                v.get("id"): v for v in pkg_entry.get("vulnerabilities") or [] if v.get("id")
            }
            groups = pkg_entry.get("groups") or [
                {"ids": [vid], "aliases": [vid]} for vid in records
            ]
            scope, via = scope_index.get(
                (component_key(eco, name), version_key(eco, version)), ("unknown", [])
            )
            for group in groups:
                ids = [i for i in group.get("ids") or [] if i]
                if not ids:
                    continue
                group_records = [records[i] for i in ids if i in records]
                primary = sorted(ids, key=_id_preference)[0]
                aliases = sorted((set(group.get("aliases") or []) | set(ids)) - {primary})
                for record in group_records:
                    aliases = sorted((set(aliases) | set(record.get("aliases") or [])) - {primary})
                summary = next((r.get("summary") for r in group_records if r.get("summary")), None)
                severity, source_label, score = Severity.UNKNOWN, None, None
                raw_score = str(group.get("max_severity") or "").strip()
                if raw_score:
                    try:
                        score = float(raw_score)
                        severity = Severity.from_cvss_score(score)
                        source_label = "osv-scanner max_severity (CVSS base score)"
                    except ValueError:
                        score = None
                if severity == Severity.UNKNOWN:
                    severity, source_label = _record_severity(group_records)
                fixed = _first_fixed(group_records, eco, name)
                remediation = (
                    f"Upgrade {name} to a fixed version: {', '.join(fixed)} "
                    "(as listed by the advisory)."
                    if fixed
                    else "The advisory data lists no fixed version."
                )
                findings.append(
                    Vulnerability(
                        id=primary,
                        aliases=aliases,
                        package=name,
                        version=version,
                        ecosystem=eco,
                        purl=pkg.get("purl"),
                        summary=summary,
                        severity=severity,
                        cvss_score=score,
                        severity_source=source_label,
                        fixed_versions=fixed,
                        remediation=remediation,
                        references=[f"https://osv.dev/vulnerability/{primary}"],
                        dependency_scope=scope,  # type: ignore[arg-type]
                        introduced_via=via,
                        source_file=Path(source).name if source else None,
                    )
                )
    findings.sort(key=lambda v: (-v.severity.rank, -(v.cvss_score or 0), v.package, v.id))
    return findings, packages_scanned, sources


def _id_preference(vuln_id: str) -> tuple[int, str]:
    order = ("GHSA-", "PYSEC-", "CVE-")
    for idx, prefix in enumerate(order):
        if vuln_id.startswith(prefix):
            return idx, vuln_id
    return len(order), vuln_id


def scan_targets(root: Path, inventory: Inventory) -> list[Path]:
    targets = []
    if inventory.discovery is None:
        return targets
    for manifest in inventory.discovery.supported:
        name = Path(manifest.path).name
        if name.startswith(OSV_SUPPORTED_LOCKFILES):
            targets.append(root / manifest.path)
    return targets


def scan_live(root: Path, inventory: Inventory, settings: Settings) -> VulnerabilityScan:
    started = utcnow()
    scan = VulnerabilityScan(
        status=ScanStatus.ERROR,
        mode=EvidenceMode.LIVE,
        started_at=started,
        limitations=list(LIMITATIONS),
    )
    if not which(settings.osv_bin):
        scan.status = ScanStatus.UNAVAILABLE
        scan.data_source_available = None
        scan.errors.append(f"osv-scanner executable not found ({settings.osv_bin})")
        scan.finished_at = utcnow()
        return scan
    targets = scan_targets(root, inventory)
    scan.targets = [str(t.relative_to(root)) for t in targets]
    if not targets:
        scan.status = ScanStatus.NO_PACKAGES
        scan.errors.append("no lockfiles supported by osv-scanner were found in the project")
        scan.finished_at = utcnow()
        return scan
    argv = [settings.osv_bin, "scan", "source", "--format", "json", "--all-packages"]
    for target in targets:
        argv += ["--lockfile", str(target)]
    result = run_tool(argv, timeout=settings.osv_timeout)
    scan.finished_at = utcnow()
    if result.timed_out:
        scan.status = ScanStatus.TIMEOUT
        scan.data_source_available = None
        scan.errors.append(f"osv-scanner {result.error}; results are incomplete")
        return scan
    if result.not_found or result.returncode is None:
        scan.status = ScanStatus.UNAVAILABLE
        scan.errors.append(result.error or "osv-scanner could not be started")
        return scan
    # Only ask for the version once the tool has proven responsive.
    scan.scanner_version = tool_version(settings.osv_bin, ["--version"], timeout=10)
    return _interpret(scan, result.returncode, result.stdout, result.stderr, inventory, root)


def _interpret(
    scan: VulnerabilityScan,
    returncode: int,
    stdout: bytes,
    stderr: str,
    inventory: Inventory | None,
    root: Path | None,
) -> VulnerabilityScan:
    scan.raw_output_sha256 = sha256_bytes(stdout) if stdout else None
    if returncode == 128:
        scan.status = ScanStatus.NO_PACKAGES
        scan.errors.append("osv-scanner found no packages to scan")
        return scan
    if returncode not in (0, 1):
        scan.status = ScanStatus.ERROR
        scan.data_source_available = False if _looks_like_network_error(stderr) else None
        scan.errors.append(f"osv-scanner exited with code {returncode}: {stderr[:500]}")
        return scan
    try:
        data = parse_json_bytes(stdout)
    except SecurityError as exc:
        scan.status = ScanStatus.ERROR
        scan.errors.append(f"osv-scanner output could not be parsed: {exc}")
        return scan
    if not isinstance(data, dict) or "results" not in data:
        scan.status = ScanStatus.ERROR
        scan.errors.append("osv-scanner output did not contain a 'results' list")
        return scan
    vulns, scanned, _ = normalize_output(data, inventory)
    if returncode == 1 and not vulns:
        scan.status = ScanStatus.ERROR
        scan.errors.append("osv-scanner reported vulnerabilities but none could be parsed")
        return scan
    scan.vulnerabilities = vulns
    scan.packages_scanned = scanned
    scan.status = ScanStatus.COMPLETED
    scan.data_source_available = True
    if inventory is not None:
        versioned = [c for c in inventory.components if c.version and c.ecosystem]
        if scanned < len(versioned):
            scan.limitations.append(
                f"osv-scanner checked {scanned} packages; the SBOM lists {len(versioned)} "
                "versioned packages, so coverage is partial"
            )
    return scan


def _looks_like_network_error(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(
        token in lowered
        for token in ("dial tcp", "no such host", "connection refused", "timeout", "tls", "network")
    )


def load_recorded(path: Path, inventory: Inventory | None = None) -> VulnerabilityScan:
    """Replay osv-scanner output captured earlier by ``scripts/record_osv.py``.

    Recorded evidence is labelled as such everywhere it is displayed; it exists so
    demonstrations and tests are deterministic and work offline.
    """
    scan = VulnerabilityScan(
        status=ScanStatus.ERROR,
        mode=EvidenceMode.RECORDED,
        started_at=utcnow(),
        limitations=list(LIMITATIONS),
    )
    try:
        wrapper = load_json_bounded(path)
    except SecurityError as exc:
        scan.errors.append(f"recorded scanner output unreadable: {exc}")
        return scan
    meta = wrapper.get("recording") if isinstance(wrapper, dict) else None
    if not isinstance(meta, dict) or "output" not in wrapper:
        scan.errors.append("recorded scanner output is missing its 'recording' metadata")
        return scan
    scan.scanner = str(meta.get("tool", "osv-scanner"))
    scan.scanner_version = meta.get("tool_version")
    scan.recorded_at = meta.get("captured_at")
    scan.targets = list(meta.get("targets") or [])
    scan.limitations.append(
        f"Recorded evidence captured at {scan.recorded_at}; advisories published since then "
        "are not reflected. Run with live scanning for current results."
    )
    stdout = json.dumps(wrapper["output"]).encode()
    result = _interpret(
        scan, int(meta.get("exit_code", 1)), stdout, str(meta.get("stderr", "")), inventory, None
    )
    result.finished_at = utcnow()
    return result


def skipped(reason: str) -> VulnerabilityScan:
    return VulnerabilityScan(status=ScanStatus.SKIPPED, errors=[reason], mode=EvidenceMode.LIVE)
