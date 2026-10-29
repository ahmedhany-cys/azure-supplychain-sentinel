from __future__ import annotations

from html import escape

import streamlit as st

from sentinel.core.models import Action
from sentinel.dashboard import common
from sentinel.dashboard.ui import badge, checks_list, decision_banner, demo_notice, setup_page

PROCEDURE = """
1. Any finding whose action is **block** → **FAIL**
2. Otherwise, any **required** check that did not complete (error, timeout, unavailable,
   skipped, missing evidence when configured) → **INDETERMINATE**
3. Otherwise, any **review** finding (with `review_outcome: INDETERMINATE`) → **INDETERMINATE**
4. Otherwise → **PASS** - a policy decision, not proof that software is safe.
"""


def _rules_table(policy) -> list[dict]:
    p = policy.policy
    rows = [
        {
            "area": "required checks",
            "rule": "required_checks",
            "setting": ", ".join(p.required_checks),
            "effect": "incomplete → INDETERMINATE",
        },
        {
            "area": "sbom",
            "rule": "require_schema_valid",
            "setting": str(p.sbom.require_schema_valid),
            "effect": "block",
        },
        {
            "area": "sbom",
            "rule": "min_components",
            "setting": str(p.sbom.min_components),
            "effect": "block",
        },
        {
            "area": "vulnerabilities",
            "rule": "block_at_or_above",
            "setting": p.vulnerabilities.block_at_or_above.value,
            "effect": "block",
        },
        {
            "area": "vulnerabilities",
            "rule": "below_threshold",
            "setting": "MEDIUM / LOW",
            "effect": p.vulnerabilities.below_threshold.value,
        },
        {
            "area": "vulnerabilities",
            "rule": "unknown_severity",
            "setting": "no rating",
            "effect": p.vulnerabilities.unknown_severity.value,
        },
        {
            "area": "vulnerabilities",
            "rule": "exceptions",
            "setting": f"{len(p.vulnerabilities.exceptions)} active",
            "effect": "info (until expiry)",
        },
    ]
    dc = p.dependency_changes
    for name in (
        "added",
        "removed",
        "upgraded",
        "downgraded",
        "version_changed",
        "identifier_changed",
        "scope_changed",
    ):
        rows.append(
            {
                "area": "dependency changes",
                "rule": name,
                "setting": "-",
                "effect": getattr(dc, name).value,
            }
        )
    rows.append(
        {
            "area": "dependency changes",
            "rule": "denied_packages",
            "setting": ", ".join(f"{d.ecosystem}:{d.name}" for d in dc.denied_packages) or "none",
            "effect": "block",
        }
    )
    rows.append(
        {
            "area": "dependency changes",
            "rule": "allowed_new_packages",
            "setting": ", ".join(dc.allowed_new_packages) or "none",
            "effect": "info",
        }
    )
    rows.append(
        {
            "area": "provenance",
            "rule": "require_signature",
            "setting": str(p.provenance.require_signature),
            "effect": "block",
        }
    )
    rows.append(
        {
            "area": "decision",
            "rule": "missing_required_evidence",
            "setting": "-",
            "effect": p.decision.missing_required_evidence.value,
        }
    )
    rows.append(
        {
            "area": "decision",
            "rule": "review_outcome",
            "setting": "-",
            "effect": p.decision.review_outcome.value,
        }
    )
    return rows


def render() -> None:
    setup_page(
        "Release Policy Center",
        "The active policy, its trust anchors, and why each "
        "release passed, failed or is indeterminate.",
    )
    policy = common.policy()
    c1, c2 = st.columns([3, 2])
    with c1:
        st.markdown(f"##### {escape(policy.name)} · version {escape(policy.version)}")
        st.caption(
            f"{policy.policy.metadata.description or ''} · sha256 {policy.sha256[:16]}… · "
            f"{policy.path.name}"
        )
        st.dataframe(_rules_table(policy), hide_index=True, use_container_width=True, height=520)
    with c2:
        st.markdown("##### Decision procedure")
        st.markdown(PROCEDURE)
        st.markdown("##### Trust anchors")
        for key in policy.trusted_keys:
            st.markdown(f"- Signing key `{key.name}` · id `{key.key_id[:24]}…`")
        for builder in policy.policy.provenance.trusted_builders:
            st.markdown(f"- Builder `{builder}`")
        st.caption(
            "Trust anchors come only from this operator-controlled policy file. Release "
            "records and uploads can never add keys or builders."
        )

    st.divider()
    st.markdown("### Decision explorer")
    record = common.pick_analysis("Decision", key="pol_pick", require="decision")
    if record is None:
        common.empty_state("No decisions recorded yet.", "Run a release gate first.")
        return
    demo_notice(record)
    decision_banner(record)
    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Checks")
        checks_list(record.decision.checks)
    with right:
        st.markdown("##### Why")
        st.code("\n".join(record.decision.reasons), language="text", wrap_lines=True)

    findings = [f for f in record.decision.findings if f.action != Action.INFO]
    info = [f for f in record.decision.findings if f.action == Action.INFO]
    st.markdown(f"##### Findings ({len(findings)} actionable, {len(info)} informational)")
    for action in (Action.BLOCK, Action.REVIEW, Action.WARN):
        group = [f for f in findings if f.action == action]
        if not group:
            continue
        with st.expander(f"{action.value.upper()} · {len(group)}", expanded=action != Action.WARN):
            for f in group:
                st.markdown(
                    f"{badge(action.value.upper(), action.value)} {badge(f.kind.value, 'info')} "
                    f"<b>{escape(f.title)}</b><br><span style='color:#AEB7C7'>"
                    f"{escape(f.detail or '')}</span><br><span style='color:#7B8597;"
                    f"font-size:0.8rem'>rule: {escape(f.rule or '-')} · check: {escape(f.check)}"
                    f"</span>",
                    unsafe_allow_html=True,
                )
                st.markdown("")
    if info:
        with st.expander(f"INFO · {len(info)}"):
            for f in info:
                st.markdown(f"- {f.title}")

    st.markdown("##### Evidence referenced by this decision")
    st.dataframe(
        [
            {"evidence": e.name, "sha256": e.sha256, "media type": e.media_type}
            for e in record.decision.evidence
        ],
        hide_index=True,
        use_container_width=True,
    )
    decision_json = common.store().evidence(record.id, "decision.json")
    if decision_json:
        st.download_button(
            "Download decision.json",
            decision_json[0],
            file_name=f"{record.id}-decision.json",
            mime="application/json",
            icon=":material/download:",
        )
