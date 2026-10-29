"""Pure data shaping for the dashboard (no Streamlit imports, unit-tested)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

from sentinel.core.models import AnalysisRecord, Severity
from sentinel.sbom.identity import version_key

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
RESULT_ORDER = ["PASS", "FAIL", "INDETERMINATE"]


def fmt_ts(value: datetime | str | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    return value.strftime("%Y-%m-%d %H:%M UTC")


def history_frame(rows: list[dict]) -> pd.DataFrame:
    columns = ["created", "name", "kind", "result", "components", "vulns", "policy", "source", "id"]
    if not rows:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame(rows)
    frame["created"] = frame["created_at"].map(fmt_ts)
    frame["kind"] = frame["kind"].str.replace("_", " ")
    frame["result"] = frame["result"].fillna("-")
    frame["source"] = frame.apply(
        lambda r: f"demo: {r['demo_scenario']}" if r["demo"] else "user", axis=1
    )
    return frame[columns]


def latest_per_release(records: list[AnalysisRecord]) -> list[AnalysisRecord]:
    """Most recent release-gate record per release name (records arrive newest first)."""
    seen: dict[str, AnalysisRecord] = {}
    for record in records:
        if record.kind == "release_gate" and record.name not in seen:
            seen[record.name] = record
    return list(seen.values())


def overview_metrics(records: list[AnalysisRecord]) -> dict:
    latest = latest_per_release(records)
    severities: Counter[str] = Counter()
    components = 0
    for record in latest:
        if record.inventory:
            components += len(record.inventory.components)
        if record.vulnerability_scan:
            severities.update(v.severity.value for v in record.vulnerability_scan.vulnerabilities)
    results = Counter(r.decision.result.value for r in latest if r.decision)
    return {
        "analyses": len(records),
        "releases": len(latest),
        "components": components,
        "severities": {s: severities.get(s, 0) for s in SEVERITY_ORDER},
        "results": {r: results.get(r, 0) for r in RESULT_ORDER},
        "demo_only": bool(records) and all(r.demo for r in records),
        "any_demo": any(r.demo for r in records),
    }


def risk_summary(metrics: dict) -> str:
    if not metrics["releases"]:
        return "No release decisions recorded yet."
    fail, ind = metrics["results"]["FAIL"], metrics["results"]["INDETERMINATE"]
    crit_high = metrics["severities"]["CRITICAL"] + metrics["severities"]["HIGH"]
    parts = [f"{fail} of {metrics['releases']} latest release decisions are blocked (FAIL)"]
    if ind:
        parts.append(f"{ind} cannot be decided automatically (INDETERMINATE)")
    if crit_high:
        parts.append(f"{crit_high} confirmed CRITICAL/HIGH vulnerabilities are open")
    return "; ".join(parts) + "."


def components_frame(record: AnalysisRecord) -> pd.DataFrame:
    columns = [
        "package",
        "version",
        "ecosystem",
        "scope",
        "introduced via",
        "vulns",
        "max severity",
        "change",
        "purl",
        "found by",
    ]
    if not record.inventory or not record.inventory.components:
        return pd.DataFrame(columns=columns)
    vulns: dict[tuple[str, str | None], list] = {}
    if record.vulnerability_scan:
        for v in record.vulnerability_scan.vulnerabilities:
            vulns.setdefault((v.package.lower(), version_key(v.ecosystem, v.version)), []).append(v)
    changes = {}
    if record.dependency_diff:
        for c in record.dependency_diff.changes:
            changes[(c.name.lower(), c.new_version)] = c.change.value
    rows = []
    for comp in record.inventory.components:
        found = vulns.get((comp.name.lower(), version_key(comp.ecosystem, comp.version)), [])
        worst = max(found, key=lambda v: v.severity.rank).severity.value if found else ""
        rows.append(
            {
                "package": comp.name,
                "version": comp.version or "unknown",
                "ecosystem": comp.ecosystem or "unknown",
                "scope": comp.scope,
                "introduced via": ", ".join(comp.introduced_via),
                "vulns": len(found),
                "max severity": worst,
                "change": changes.get((comp.name.lower(), comp.version), ""),
                "purl": comp.purl or "",
                "found by": comp.found_by or "",
            }
        )
    return pd.DataFrame(rows, columns=columns)


def filter_components(
    frame: pd.DataFrame,
    *,
    search: str = "",
    ecosystems=None,
    scopes=None,
    vulnerable_only: bool = False,
    changed_only: bool = False,
) -> pd.DataFrame:
    out = frame
    if search:
        needle = search.lower()
        out = out[
            out["package"].str.lower().str.contains(needle, regex=False)
            | out["purl"].str.lower().str.contains(needle, regex=False)
        ]
    if ecosystems:
        out = out[out["ecosystem"].isin(ecosystems)]
    if scopes:
        out = out[out["scope"].isin(scopes)]
    if vulnerable_only:
        out = out[out["vulns"] > 0]
    if changed_only:
        out = out[out["change"] != ""]
    return out


def vulnerabilities_frame(record: AnalysisRecord) -> pd.DataFrame:
    columns = [
        "id",
        "aliases",
        "package",
        "version",
        "scope",
        "severity",
        "cvss",
        "fixed in",
        "summary",
        "link",
    ]
    scan = record.vulnerability_scan
    if not scan or not scan.vulnerabilities:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(
        [
            {
                "id": v.id,
                "aliases": ", ".join(v.aliases),
                "package": v.package,
                "version": v.version,
                "scope": v.dependency_scope,
                "severity": v.severity.value,
                "cvss": v.cvss_score,
                "fixed in": ", ".join(v.fixed_versions) or "none listed",
                "summary": v.summary or "",
                "link": v.references[0] if v.references else "",
            }
            for v in scan.vulnerabilities
        ],
        columns=columns,
    )


def diff_frame(record: AnalysisRecord) -> pd.DataFrame:
    columns = ["change", "package", "ecosystem", "old", "new", "scope", "introduced via", "note"]
    if not record.dependency_diff:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(
        [
            {
                "change": c.change.value,
                "package": c.name,
                "ecosystem": c.ecosystem,
                "old": c.old_version or "",
                "new": c.new_version or "",
                "scope": c.scope,
                "introduced via": ", ".join(c.introduced_via),
                "note": c.note or "",
            }
            for c in record.dependency_diff.changes
        ],
        columns=columns,
    )


def severity_frame(counts: dict[str, int]) -> pd.DataFrame:
    return pd.DataFrame({"severity": list(counts), "count": list(counts.values())})


def scope_counts(record: AnalysisRecord) -> dict[str, int]:
    counts = Counter(c.scope for c in record.inventory.components) if record.inventory else {}
    return {k: counts.get(k, 0) for k in ("direct", "transitive", "unknown")}


def ecosystem_counts(record: AnalysisRecord) -> dict[str, int]:
    if not record.inventory:
        return {}
    return dict(Counter(c.ecosystem or "unknown" for c in record.inventory.components))


def display_path(path: Path) -> str:
    """Repository-relative (or ~-relative) path, so the UI does not expose host layouts."""
    from sentinel.config import REPO_ROOT

    resolved = path.resolve()
    for base, prefix in ((REPO_ROOT, ""), (Path.home(), "~/")):
        try:
            rel = resolved.relative_to(base)
        except ValueError:
            continue
        return f"{prefix}{rel}" if str(rel) != "." else (prefix.rstrip("/") or ".")
    return str(resolved)


def find_release_records(roots: list[Path], limit: int = 100) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("release.yaml")):
            if any(part in {"node_modules", ".git", ".venv"} for part in path.parts):
                continue
            found.append(path)
            if len(found) >= limit:
                return found
    return found


def find_projects(roots: list[Path], limit: int = 100) -> list[Path]:
    """Directories under the allowed roots that contain a recognised lockfile."""
    names = {"requirements.txt", "package-lock.json", "poetry.lock"}
    found: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for name in names:
            for path in root.rglob(name):
                if not any(p in {"node_modules", ".git", ".venv"} for p in path.parts):
                    found.add(path.parent)
    return sorted(found)[:limit]


def severity_rank(value: str) -> int:
    return Severity.parse(value).rank
