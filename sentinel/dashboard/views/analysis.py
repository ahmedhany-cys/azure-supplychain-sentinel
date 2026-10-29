from __future__ import annotations

from pathlib import Path

import streamlit as st

from sentinel.core.security import SecurityError, ensure_allowed_root
from sentinel.core.service import analyze_project, gate_release
from sentinel.dashboard import common
from sentinel.dashboard.data import display_path, find_projects, find_release_records
from sentinel.dashboard.ui import checks_list, decision_banner, setup_page


def _rel(path: Path) -> str:
    for root in common.settings().allowed_roots:
        try:
            return str(path.relative_to(root))
        except ValueError:
            continue
    return path.name


def _show(outcome) -> None:
    record = outcome.record
    st.session_state["selected_analysis"] = record.id
    decision_banner(record)
    checks_list(record.decision.checks)
    with st.expander("Decision reasons", expanded=True):
        st.code("\n".join(record.decision.reasons), language="text")
    st.caption(
        f"Stored as analysis `{record.id}`. Open Dependency Explorer, SBOM Viewer, "
        "Artifact Trust or Release Policy Center to inspect the evidence."
    )


def render() -> None:
    setup_page(
        "Project Analysis",
        "Run a full release gate or a source-only SBOM and vulnerability analysis.",
    )
    settings = common.settings()
    roots = ", ".join(f"`{display_path(r)}`" for r in settings.allowed_roots)
    st.caption(
        f"Analysis is limited to allowed roots: {roots} (SENTINEL_ALLOWED_ROOTS). "
        "Projects are read, never built or executed."
    )

    gate_tab, source_tab = st.tabs(
        [":material/gavel: Release gate", ":material/folder_open: Source analysis"]
    )
    with gate_tab:
        releases = find_release_records(settings.allowed_roots)
        if not releases:
            common.empty_state(
                "No release records (release.yaml) found under the allowed roots.",
                "Add one next to your project; see examples/ for the format.",
            )
        else:
            chosen = st.selectbox("Release record", releases, format_func=_rel, key="gate_rel")
            mode = st.radio(
                "Vulnerability evidence",
                ["as declared in release record", "force live scan"],
                horizontal=True,
                help="Live scans call osv-scanner and need network access to "
                "OSV.dev. Recorded evidence is replayed and labelled.",
            )
            if st.button("Run release gate", type="primary", icon=":material/play_arrow:"):
                with st.status("Evaluating release...", expanded=True) as status:
                    st.write(
                        "Generating SBOM, scanning dependencies, verifying signature and "
                        "provenance, evaluating policy..."
                    )
                    try:
                        outcome = gate_release(
                            chosen,
                            settings,
                            common.policy(),
                            store=common.store(),
                            scan_mode="live" if mode == "force live scan" else None,
                        )
                    except (SecurityError, ValueError) as exc:
                        status.update(label="Release record rejected", state="error")
                        st.error(str(exc))
                        return
                    for check in outcome.record.decision.checks:
                        st.write(f"{check.title}: **{check.status.value}**")
                    status.update(
                        label=f"Decision: {outcome.record.decision.result.value}",
                        state="complete",
                        expanded=False,
                    )
                _show(outcome)

    with source_tab:
        projects = find_projects(settings.allowed_roots)
        options = [str(p) for p in projects]
        chosen = st.selectbox(
            "Project directory",
            options,
            format_func=lambda p: _rel(Path(p)),
            key="src_proj",
            index=0 if options else None,
            placeholder="No projects with supported lockfiles found",
        )
        custom = st.text_input("...or enter a path inside an allowed root", key="src_custom")
        st.caption(
            "Source analysis runs a live osv-scanner query. If the scanner or OSV.dev is "
            "unavailable the result is INDETERMINATE, never clean."
        )
        if st.button(
            "Analyse project",
            type="primary",
            icon=":material/search:",
            disabled=not (chosen or custom),
        ):
            try:
                project = ensure_allowed_root(custom or chosen, settings.allowed_roots)
                if not project.is_dir():
                    raise SecurityError("path must be a directory")
            except SecurityError as exc:
                st.error(str(exc))
                return
            with st.status("Analysing project...", expanded=True) as status:
                outcome = analyze_project(project, settings, common.policy(), store=common.store())
                scan = outcome.record.vulnerability_scan
                st.write(f"SBOM: {len(outcome.record.inventory.components)} components")
                st.write(
                    f"Vulnerability scan: {scan.status.value}"
                    + (f" - {'; '.join(scan.errors)}" if scan.errors else "")
                )
                status.update(
                    label=f"Decision: {outcome.record.decision.result.value}",
                    state="complete",
                    expanded=False,
                )
            _show(outcome)
