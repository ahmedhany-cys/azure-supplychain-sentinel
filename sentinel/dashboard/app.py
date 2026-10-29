"""Streamlit entry point: ``streamlit run sentinel/dashboard/app.py``."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Allow `streamlit run sentinel/dashboard/app.py` from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel import __version__
from sentinel.core.service import tool_versions
from sentinel.dashboard import common
from sentinel.dashboard.views import (
    analysis,
    audit,
    dependencies,
    overview,
    policy_center,
    sbom_viewer,
    trust,
)
from sentinel.demo import run_scenarios

st.set_page_config(
    page_title="SupplyChain Sentinel",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data(ttl=300, show_spinner=False)
def _tools() -> dict[str, str | None]:
    return tool_versions(common.settings())


ASSETS = Path(__file__).resolve().parent / "assets"


def sidebar() -> None:
    st.logo(str(ASSETS / "logo.svg"), size="large", icon_image=str(ASSETS / "icon.svg"))
    with st.sidebar:
        st.caption(f"v{__version__} · local mode · no cloud resources")
        tools = _tools()
        with st.expander("Toolchain", expanded=False):
            for name in ("syft", "osv-scanner", "cosign"):
                version = tools.get(name)
                icon = ":material/check_circle:" if version else ":material/cancel:"
                st.markdown(f"{icon} **{name}** {version or 'not installed - native fallback'}")
        with st.expander("Demonstration data", expanded=False):
            st.caption(
                "Runs the six scenarios in examples/ through the real pipeline and "
                "stores the results, labelled as demonstration data."
            )
            if st.button(
                "Run demo scenarios", icon=":material/play_arrow:", use_container_width=True
            ):
                with st.spinner(
                    "Running scenarios (scenario 06 waits for a 3 s scanner timeout)..."
                ):
                    runs = run_scenarios(
                        common.settings(), store=common.store(), policy=common.policy()
                    )
                ok = sum(r.matched for r in runs)
                st.success(f"{len(runs)} scenarios stored; {ok} matched their expected decision")
            confirm = st.checkbox("Confirm removal of demo data", key="confirm_clear")
            if st.button(
                "Clear demo data",
                icon=":material/delete:",
                disabled=not confirm,
                use_container_width=True,
            ):
                st.success(f"Removed {common.store().delete_demo_data()} demo analyses")


pages = [
    st.Page(
        overview.render,
        title="Security Overview",
        icon=":material/dashboard:",
        url_path="overview",
        default=True,
    ),
    st.Page(
        analysis.render,
        title="Project Analysis",
        icon=":material/play_circle:",
        url_path="analysis",
    ),
    st.Page(
        dependencies.render,
        title="Dependency Explorer",
        icon=":material/account_tree:",
        url_path="dependencies",
    ),
    st.Page(
        sbom_viewer.render, title="SBOM Viewer", icon=":material/inventory_2:", url_path="sbom"
    ),
    st.Page(
        trust.render, title="Artifact Trust", icon=":material/verified_user:", url_path="trust"
    ),
    st.Page(
        policy_center.render,
        title="Release Policy Center",
        icon=":material/policy:",
        url_path="policy",
    ),
    st.Page(audit.render, title="Audit & Reports", icon=":material/history:", url_path="audit"),
]

sidebar()
st.navigation(pages).run()
