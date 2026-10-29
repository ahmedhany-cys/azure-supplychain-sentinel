from __future__ import annotations

import streamlit as st

from sentinel.dashboard import common
from sentinel.dashboard.data import (
    history_frame,
    latest_per_release,
    overview_metrics,
    risk_summary,
    severity_frame,
)
from sentinel.dashboard.ui import (
    COLORS,
    card,
    demo_notice,
    results_chart,
    setup_page,
    severity_chart,
)


def render() -> None:
    setup_page(
        "Security Overview",
        "Release-gate posture across all analysed releases (latest decision per release).",
    )
    records = common.all_records()
    if not records:
        common.empty_state(
            "No analyses have been recorded yet.",
            "Run a release gate from **Project Analysis**, or use **Run demo scenarios** in the "
            "sidebar to evaluate the six bundled demonstration releases.",
        )
        return
    metrics = overview_metrics(records)
    if metrics["any_demo"]:
        demo_notice(
            text="Figures include demonstration data produced by running the real "
            "pipeline on the fixtures in examples/. They are not production findings."
        )

    cols = st.columns(5)
    with cols[0]:
        card("Releases analysed", metrics["releases"], f"{metrics['analyses']} analyses in total")
    with cols[1]:
        card("Dependencies discovered", metrics["components"], "across latest release SBOMs")
    with cols[2]:
        crit_high = metrics["severities"]["CRITICAL"] + metrics["severities"]["HIGH"]
        card(
            "Critical / high vulns",
            crit_high,
            "confirmed by scanner evidence",
            COLORS["FAIL"] if crit_high else None,
        )
    with cols[3]:
        card(
            "Failed releases",
            metrics["results"]["FAIL"],
            "blocking policy findings",
            COLORS["FAIL"] if metrics["results"]["FAIL"] else None,
        )
    with cols[4]:
        card(
            "Indeterminate",
            metrics["results"]["INDETERMINATE"],
            "incomplete checks or manual review",
            COLORS["INDETERMINATE"] if metrics["results"]["INDETERMINATE"] else None,
        )

    st.markdown(" ")
    st.markdown(f"**Risk summary:** {risk_summary(metrics)}")

    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Confirmed vulnerabilities by severity")
        st.altair_chart(
            severity_chart(severity_frame(metrics["severities"])), use_container_width=True
        )
    with right:
        st.markdown("##### Latest release decisions")
        st.altair_chart(results_chart(metrics["results"]), use_container_width=True)

    st.markdown("##### Latest decision per release")
    latest = latest_per_release(records)
    table = [
        {
            "release": r.name,
            "result": r.decision.result.value if r.decision else "-",
            "blocking": sum(f.action.value == "block" for f in r.decision.findings)
            if r.decision
            else 0,
            "review": sum(f.action.value == "review" for f in r.decision.findings)
            if r.decision
            else 0,
            "incomplete checks": ", ".join(r.decision.checks_not_completed) if r.decision else "",
            "evaluated": r.decision.evaluated_at.strftime("%Y-%m-%d %H:%M UTC")
            if r.decision
            else "",
            "source": f"demo: {r.demo_scenario}" if r.demo else "user",
        }
        for r in latest
    ]
    st.dataframe(table, hide_index=True, use_container_width=True)

    st.markdown("##### Recent activity")
    st.dataframe(
        history_frame(common.store().list(limit=15)),
        hide_index=True,
        use_container_width=True,
        column_config={"id": st.column_config.TextColumn("analysis id")},
    )
