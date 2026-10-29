"""Streamlit-side helpers shared by the dashboard pages."""

from __future__ import annotations

import streamlit as st

from sentinel.config import Settings, get_settings
from sentinel.core.models import AnalysisRecord
from sentinel.dashboard.ui import record_label
from sentinel.policies.model import LoadedPolicy, load_policy
from sentinel.storage.db import Store


@st.cache_resource
def settings() -> Settings:
    return get_settings()


def store() -> Store:
    return Store(settings().db_path)


def policy() -> LoadedPolicy:
    return load_policy(settings().policy_path)


def all_records(limit: int = 200) -> list[AnalysisRecord]:
    s = store()
    return [r for r in (s.get(row["id"]) for row in s.list(limit=limit)) if r is not None]


def pick_analysis(
    label: str, *, kinds: tuple[str, ...] | None = None, key: str, require: str | None = None
) -> AnalysisRecord | None:
    """Select box over stored analyses; remembers the last analysis opened anywhere."""
    s = store()
    rows = [r for r in s.list(limit=300) if kinds is None or r["kind"] in kinds]
    if require:
        rows = [r for r in rows if _has(s.get(r["id"]), require)]
    if not rows:
        return None
    ids = [r["id"] for r in rows]
    labels = {r["id"]: record_label(r) for r in rows}
    preferred = st.session_state.get("selected_analysis")
    index = ids.index(preferred) if preferred in ids else 0
    chosen = st.selectbox(label, ids, index=index, format_func=labels.get, key=key)
    st.session_state["selected_analysis"] = chosen
    return s.get(chosen)


def _has(record: AnalysisRecord | None, attribute: str) -> bool:
    return record is not None and getattr(record, attribute, None) is not None


def empty_state(message: str, hint: str) -> None:
    st.info(f"{message}\n\n{hint}")
