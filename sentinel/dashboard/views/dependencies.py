from __future__ import annotations

import streamlit as st

from sentinel.dashboard import common
from sentinel.dashboard.data import (
    components_frame,
    diff_frame,
    filter_components,
    vulnerabilities_frame,
)
from sentinel.dashboard.ui import COLORS, demo_notice, setup_page

CHANGE_COLORS = {
    "added": COLORS["review"],
    "removed": "#7B8597",
    "upgraded": COLORS["info"],
    "downgraded": COLORS["FAIL"],
    "version_changed": COLORS["review"],
    "identifier_changed": COLORS["FAIL"],
    "scope_changed": "#7B8597",
}


def _color_change(value: str) -> str:
    return f"color: {CHANGE_COLORS[value]}; font-weight: 600" if value in CHANGE_COLORS else ""


def _color_severity(value: str) -> str:
    return f"color: {COLORS[value]}; font-weight: 600" if value in COLORS and value else ""


def render() -> None:
    setup_page(
        "Dependency Explorer",
        "Search the inventory, see dependency changes and the vulnerability evidence "
        "linked to each package.",
    )
    record = common.pick_analysis(
        "Analysis",
        kinds=("release_gate", "project_analysis", "dependency_diff"),
        key="dep_pick",
        require="inventory",
    )
    if record is None:
        common.empty_state(
            "No analyses with a dependency inventory yet.",
            "Run a release gate or source analysis first.",
        )
        return
    demo_notice(record)
    frame = components_frame(record)

    f1, f2, f3, f4 = st.columns([3, 2, 2, 2])
    search = f1.text_input("Search package or purl", key="dep_search", placeholder="e.g. urllib3")
    ecosystems = f2.multiselect("Ecosystem", sorted(frame["ecosystem"].unique()), key="dep_eco")
    scopes = f3.multiselect("Scope", ["direct", "transitive", "unknown"], key="dep_scope")
    with f4:
        vulnerable = st.toggle("Vulnerable only", key="dep_vuln")
        changed = st.toggle(
            "Changed only", key="dep_changed", disabled=record.dependency_diff is None
        )
    shown = filter_components(
        frame,
        search=search,
        ecosystems=ecosystems,
        scopes=scopes,
        vulnerable_only=vulnerable,
        changed_only=changed,
    )
    shown = shown.sort_values(["vulns", "package"], ascending=[False, True])
    st.caption(
        f"{len(shown)} of {len(frame)} components · scope comes from lockfile metadata "
        "(pip-compile annotations, package-lock.json); 'unknown' means it could not be "
        "determined reliably."
    )
    st.dataframe(
        shown.style.map(_color_severity, subset=["max severity"]).map(
            _color_change, subset=["change"]
        ),
        hide_index=True,
        use_container_width=True,
        height=min(38 * (len(shown) + 1) + 4, 460),
        column_config={"vulns": st.column_config.NumberColumn("vulns", format="%d")},
    )

    if record.dependency_diff is not None:
        diff = record.dependency_diff
        st.markdown(f"##### Changes: {diff.baseline_label} → {diff.candidate_label}")
        dframe = diff_frame(record)
        if dframe.empty:
            st.success("No dependency changes against the baseline.")
        else:
            st.dataframe(
                dframe.style.map(_color_change, subset=["change"]),
                hide_index=True,
                use_container_width=True,
            )
            st.caption(
                "A new or changed package is a fact to review, not evidence of "
                "compromise. The policy decides whether it needs review or blocks."
            )
        if diff.vulnerability_comparison_available:
            new = ", ".join(v.id for v in diff.new_vulnerabilities) or "none"
            st.markdown(
                f"Newly introduced vulnerabilities: **{new}** · resolved since "
                f"baseline: **{', '.join(diff.resolved_vulnerabilities) or 'none'}**"
            )

    vframe = vulnerabilities_frame(record)
    st.markdown("##### Linked vulnerability evidence")
    scan = record.vulnerability_scan
    if scan is None:
        st.info("This analysis did not include a vulnerability scan.")
        return
    if vframe.empty:
        if scan.status.value == "completed":
            st.success(
                f"{scan.scanner} reported no known vulnerabilities for "
                f"{scan.packages_scanned} packages ({scan.mode.value} evidence). This "
                "does not prove the absence of vulnerabilities."
            )
        else:
            st.warning(
                f"Scan status: {scan.status.value}. Vulnerability status is unknown: "
                + "; ".join(scan.errors)
            )
        return
    packages = ["All packages", *sorted(vframe["package"].unique())]
    selected = st.selectbox("Package", packages, key="dep_vpkg")
    if selected != "All packages":
        vframe = vframe[vframe["package"] == selected]
    st.dataframe(
        vframe.style.map(_color_severity, subset=["severity"]),
        hide_index=True,
        use_container_width=True,
        column_config={
            "link": st.column_config.LinkColumn("advisory", display_text="osv.dev"),
            "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
        },
    )
    source = scan.mode.value + (f", captured {scan.recorded_at}" if scan.recorded_at else "")
    st.caption(
        f"Source: {scan.scanner} {scan.scanner_version or ''} ({source}) · "
        f"{scan.data_source}. Severity is the CVSS base score computed by osv-scanner "
        "when available, otherwise the advisory's own label; never estimated."
    )
