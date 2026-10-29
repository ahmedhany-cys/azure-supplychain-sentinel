"""JSON and Markdown report rendering. Both outputs pass through secret redaction."""

from __future__ import annotations

from sentinel.core.models import Action, AnalysisRecord, EvidenceMode
from sentinel.core.security import redact, redact_json

ICON = {"PASS": "PASS", "FAIL": "FAIL", "INDETERMINATE": "INDETERMINATE"}


def to_json(record: AnalysisRecord) -> str:
    return redact_json(record.model_dump_json(indent=2))


def _fmt_ts(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "-"


def _esc(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(record: AnalysisRecord) -> str:
    lines: list[str] = []
    add = lines.append
    add(f"# Supply-chain security report: {record.name}")
    add("")
    if record.demo:
        add(
            f"> **Demonstration data** - scenario `{record.demo_scenario}`. Generated from "
            "repository fixtures; not a production finding."
        )
        add("")
    add(f"- **Analysis ID:** `{record.id}`")
    add(f"- **Type:** {record.kind.replace('_', ' ')}")
    add(f"- **Generated:** {_fmt_ts(record.created_at)}")
    add(f"- **Sentinel version:** {record.sentinel_version}")
    tools = ", ".join(f"{k} {v or 'n/a'}" for k, v in record.tool_versions.items())
    if tools:
        add(f"- **Tools:** {tools}")
    add("")

    decision = record.decision
    if decision:
        add(f"## Decision: **{ICON[decision.result.value]}**")
        add("")
        add(
            f"- Policy: `{decision.policy_name}` version `{decision.policy_version}` "
            f"(sha256 `{decision.policy_sha256[:16]}...`)"
        )
        add(f"- Evaluated: {_fmt_ts(decision.evaluated_at)}")
        if decision.artifact_sha256:
            add(f"- Artifact sha256: `{decision.artifact_sha256}`")
        add("")
        add("### Reasons")
        add("")
        add("```text")
        lines.extend(decision.reasons or ["(none)"])
        add("```")
        add("")
        add("### Checks")
        add("")
        add("| Check | Required | Status | Evidence mode | Summary |")
        add("|---|---|---|---|---|")
        for check in decision.checks:
            add(
                f"| {check.title} | {'yes' if check.required else 'no'} | {check.status.value} | "
                f"{check.evidence_mode.value if check.evidence_mode else '-'} | "
                f"{_esc(check.summary)} |"
            )
        add("")
        blocking = [f for f in decision.findings if f.action != Action.INFO]
        if blocking:
            add("### Findings requiring attention")
            add("")
            add("| Action | Kind | Check | Finding | Detail |")
            add("|---|---|---|---|---|")
            for f in blocking:
                add(
                    f"| {f.action.value.upper()} | {f.kind.value} | {f.check} | {_esc(f.title)} | "
                    f"{_esc((f.detail or '')[:300])} |"
                )
            add("")

    inv = record.inventory
    if inv and inv.sbom:
        sbom = inv.sbom
        add("## Software Bill of Materials")
        add("")
        add(
            f"- Format: {sbom.format} {sbom.spec_version}; generator: {sbom.generator} "
            f"{sbom.generator_version or ''} ({sbom.mode.value})"
        )
        add(
            f"- Components: {len(inv.components)} (direct: "
            f"{sum(c.scope == 'direct' for c in inv.components)}, transitive: "
            f"{sum(c.scope == 'transitive' for c in inv.components)}, unknown: "
            f"{sum(c.scope == 'unknown' for c in inv.components)})"
        )
        add(
            f"- Validation: {'valid' if sbom.validation.valid else 'INVALID'}"
            + (f" - {'; '.join(sbom.validation.errors[:3])}" if sbom.validation.errors else "")
        )
        add(f"- SBOM sha256: `{sbom.sha256}`")
        if inv.discovery and inv.discovery.unsupported:
            add(
                "- Not inventoried natively: "
                + ", ".join(f"`{m.path}` ({m.kind})" for m in inv.discovery.unsupported)
            )
        add("")

    scan = record.vulnerability_scan
    if scan:
        add("## Vulnerability evidence")
        add("")
        mode = scan.mode.value + (
            f", captured {scan.recorded_at}" if scan.mode == EvidenceMode.RECORDED else ""
        )
        add(
            f"- Scanner: {scan.scanner} {scan.scanner_version or ''} ({mode}); status: "
            f"**{scan.status.value}**"
        )
        add(f"- Data source: {scan.data_source}")
        if scan.errors:
            add(f"- Errors: {_esc('; '.join(scan.errors))}")
        add("")
        if scan.vulnerabilities:
            add("| ID | Aliases | Package | Version | Scope | Severity | Fixed in |")
            add("|---|---|---|---|---|---|---|")
            for v in scan.vulnerabilities:
                sev = v.severity.value + (f" ({v.cvss_score})" if v.cvss_score is not None else "")
                add(
                    f"| [{v.id}]({v.references[0] if v.references else '#'}) | "
                    f"{_esc(', '.join(v.aliases[:4]))} | {v.package} | {v.version} | "
                    f"{v.dependency_scope} | {sev} | {_esc(', '.join(v.fixed_versions) or '-')} |"
                )
            add("")
        add("Limitations: " + " ".join(scan.limitations))
        add("")

    diff = record.dependency_diff
    if diff:
        add(f"## Dependency changes ({diff.baseline_label} -> {diff.candidate_label})")
        add("")
        if diff.changes:
            add("| Change | Package | Ecosystem | Old | New | Scope |")
            add("|---|---|---|---|---|---|")
            for c in diff.changes:
                add(
                    f"| {c.change.value} | {c.name} | {c.ecosystem} | {c.old_version or '-'} | "
                    f"{c.new_version or '-'} | {c.scope} |"
                )
        else:
            add("No dependency changes.")
        add("")

    sig = record.signature
    if sig:
        add("## Artifact signature")
        add("")
        add(f"- Status: **{sig.status.value}** (verified: {sig.verified})")
        add(f"- Artifact: `{sig.artifact}`")
        add(f"- Actual sha256: `{sig.actual_sha256}`")
        add(f"- Signed sha256: `{sig.signed_sha256}`")
        if sig.expected_sha256:
            add(f"- Expected sha256 (release record): `{sig.expected_sha256}`")
        add(
            f"- Trusted keys: {', '.join(f'{k.name} ({k.key_id[:12]}...)' for k in sig.trusted_keys)}"
        )
        add(f"- Methods: {', '.join(sig.methods)}")
        for d in sig.details:
            add(f"- {d}")
        add("")

    prov = record.provenance
    if prov:
        add("## Build provenance")
        add("")
        add(f"- Status: **{prov.status.value}**; trust level reached: `{prov.trust_level}`")
        if prov.builder_id:
            add(f"- Builder: `{prov.builder_id}`")
        if prov.source_uri:
            add(f"- Source: `{prov.source_uri}@{prov.source_revision}`")
        if prov.checks:
            add("")
            add("| Check | Result | Detail |")
            add("|---|---|---|")
            for c in prov.checks:
                res = {True: "pass", False: "FAIL", None: "n/a"}[c.passed]
                add(f"| {c.name} | {res} | {_esc(c.detail)} |")
        for d in prov.details:
            add(f"- {d}")
        add("")

    if decision and decision.evidence:
        add("## Evidence")
        add("")
        add("| Name | Kind | sha256 |")
        add("|---|---|---|")
        for e in decision.evidence:
            add(f"| {e.name} | {e.kind} | `{e.sha256}` |")
        add("")
    add("---")
    add(
        "Generated by Azure SupplyChain Sentinel. A PASS is a policy decision based on the "
        "evidence listed above; it is not proof that software is free of vulnerabilities."
    )
    return redact("\n".join(lines)) + "\n"
