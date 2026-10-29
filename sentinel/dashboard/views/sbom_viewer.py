from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from sentinel.dashboard import common
from sentinel.dashboard.data import ecosystem_counts, fmt_ts, scope_counts
from sentinel.dashboard.ui import badge, card, demo_notice, setup_page
from sentinel.sbom import cyclonedx

MAX_VALIDATE_BYTES = 25 * 1024 * 1024


def _validator() -> None:
    st.markdown("##### Validate a CycloneDX SBOM")
    upload = st.file_uploader("CycloneDX JSON (1.4 - 1.7)", type=["json"], key="sbom_upload")
    if upload is None:
        return
    raw = upload.getvalue()
    if len(raw) > MAX_VALIDATE_BYTES:
        st.error("File exceeds 25 MB.")
        return
    result = cyclonedx.validate(raw)
    st.markdown(
        badge("VALID" if result.valid else "INVALID", "PASSED" if result.valid else "FAILED"),
        unsafe_allow_html=True,
    )
    if result.errors:
        st.error("\n".join(f"- {e}" for e in result.errors))
    if result.warnings:
        with st.expander(f"{len(result.warnings)} warnings"):
            st.write("\n".join(f"- {w}" for w in result.warnings))


def render() -> None:
    setup_page(
        "SBOM Viewer", "CycloneDX metadata, validation results, discovery coverage and downloads."
    )
    record = common.pick_analysis(
        "Analysis", kinds=("release_gate", "project_analysis"), key="sbom_pick", require="inventory"
    )
    if record is None:
        common.empty_state("No SBOMs generated yet.", "Run a release gate or source analysis.")
        _validator()
        return
    demo_notice(record)
    inv = record.inventory
    sbom = inv.sbom
    c = st.columns(4)
    with c[0]:
        card("Format", f"{sbom.format} {sbom.spec_version or ''}", "standard SBOM format")
    with c[1]:
        card(
            "Components",
            len(inv.components),
            f"generator: {sbom.generator or 'unknown'} {sbom.generator_version or ''}",
        )
    with c[2]:
        card(
            "Validation",
            "VALID" if sbom.validation.valid else "INVALID",
            "JSON schema + semantic checks",
            "#2EB67D" if sbom.validation.valid else "#E5484D",
        )
    with c[3]:
        card("Evidence mode", sbom.mode.value, "live = Syft ran; native = built-in parser")

    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Metadata")
        st.markdown(
            f"- **Serial number:** `{sbom.serial_number or '-'}`\n"
            f"- **Generated:** {fmt_ts(sbom.generated_at)}\n"
            f"- **SHA-256:** `{sbom.sha256}`\n"
            f"- **Schema valid:** {sbom.validation.schema_valid}"
        )
        if sbom.validation.errors:
            st.error("Validation errors:\n" + "\n".join(f"- {e}" for e in sbom.validation.errors))
        if sbom.errors:
            st.warning("Generation problems:\n" + "\n".join(f"- {e}" for e in sbom.errors))
        if sbom.validation.warnings:
            with st.expander(f"{len(sbom.validation.warnings)} validation warnings"):
                st.write("\n".join(f"- {w}" for w in sbom.validation.warnings))
    with right:
        st.markdown("##### Composition")
        scopes = scope_counts(record)
        ecos = ecosystem_counts(record)
        st.dataframe(
            pd.DataFrame(
                [{"dimension": "scope", "value": k, "components": v} for k, v in scopes.items()]
                + [{"dimension": "ecosystem", "value": k, "components": v} for k, v in ecos.items()]
            ),
            hide_index=True,
            use_container_width=True,
        )

    if inv.discovery:
        st.markdown("##### Discovery coverage")
        rows = [
            {
                "manifest": m.path,
                "ecosystem": m.ecosystem,
                "kind": m.kind,
                "status": "parsed"
                if m.supported
                else (f"covered by {m.covered_by}" if m.covered_by else "not parsed natively"),
                "note": m.note or "",
            }
            for m in inv.discovery.manifests
        ]
        st.dataframe(rows, hide_index=True, use_container_width=True)
        for warning in inv.discovery.warnings:
            st.caption(f":material/info: {warning}")

    sbom_bytes = common.store().evidence(record.id, "sbom.cdx.json")
    if sbom_bytes:
        content, media = sbom_bytes
        st.download_button(
            "Download CycloneDX SBOM",
            content,
            file_name=f"{record.name.replace(' ', '-')}.cdx.json",
            mime=media,
            icon=":material/download:",
        )
        with st.expander("Raw SBOM JSON"):
            st.json(json.loads(content), expanded=1)
    st.divider()
    _validator()
