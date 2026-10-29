from __future__ import annotations

import streamlit as st

from sentinel.dashboard import common
from sentinel.dashboard.data import fmt_ts, history_frame
from sentinel.dashboard.ui import setup_page
from sentinel.reporting.reports import to_json, to_markdown


def render() -> None:
    setup_page(
        "Audit & Reports",
        "Analysis history, exportable reports, evidence downloads and the audit log.",
    )
    store = common.store()
    rows = store.list(limit=500)
    if not rows:
        common.empty_state("No analyses recorded yet.", "Nothing to audit.")
        return
    frame = history_frame(rows)
    f1, f2, f3 = st.columns([2, 2, 1])
    kinds = f1.multiselect("Type", sorted(frame["kind"].unique()), key="aud_kind")
    results = f2.multiselect("Result", sorted(frame["result"].unique()), key="aud_result")
    hide_demo = f3.toggle("Hide demo data", key="aud_demo")
    shown = frame
    if kinds:
        shown = shown[shown["kind"].isin(kinds)]
    if results:
        shown = shown[shown["result"].isin(results)]
    if hide_demo:
        shown = shown[shown["source"] == "user"]
    st.dataframe(shown, hide_index=True, use_container_width=True, height=300)

    st.markdown("##### Export")
    ids = list(shown["id"])
    if not ids:
        st.caption("No analyses match the filters.")
    else:
        labels = {
            r["id"]: f"{fmt_ts(r['created_at'])} · {r['name']} · {r['result'] or '-'}" for r in rows
        }
        preferred = st.session_state.get("selected_analysis")
        chosen = st.selectbox(
            "Analysis",
            ids,
            format_func=labels.get,
            key="aud_pick",
            index=ids.index(preferred) if preferred in ids else 0,
        )
        record = store.get(chosen)
        c1, c2 = st.columns(2)
        c1.download_button(
            "Report (Markdown)",
            to_markdown(record),
            icon=":material/description:",
            file_name=f"{record.id}-report.md",
            mime="text/markdown",
            use_container_width=True,
        )
        c2.download_button(
            "Report (JSON)",
            to_json(record),
            icon=":material/data_object:",
            file_name=f"{record.id}-report.json",
            mime="application/json",
            use_container_width=True,
        )
        evidence = store.evidence_list(record.id)
        st.markdown("**Evidence files**")
        for item in evidence:
            if item["name"].startswith("report."):
                continue
            content, media = store.evidence(record.id, item["name"])
            col_a, col_b = st.columns([4, 1])
            col_a.markdown(
                f"`{item['name']}` · {item['size']:,} bytes · sha256 `{item['sha256'][:16]}…`"
            )
            col_b.download_button(
                "Download",
                content,
                file_name=f"{record.id}-{item['name']}",
                mime=media,
                key=f"dl-{record.id}-{item['name']}",
                use_container_width=True,
            )
        with st.expander("Preview Markdown report"):
            st.markdown(to_markdown(record))

    st.markdown("##### Audit log")
    st.dataframe(
        [
            {
                "time": fmt_ts(e["ts"]),
                "event": e["event"],
                "actor": e["actor"],
                "analysis": e["analysis_id"] or "",
                "details": e["details"],
            }
            for e in store.audit_entries(limit=200)
        ],
        hide_index=True,
        use_container_width=True,
        height=260,
    )
