from __future__ import annotations

import re
from html import escape

import streamlit as st

from sentinel.core.models import AnalysisRecord, ProvenanceVerification, SignatureVerification
from sentinel.core.security import private_tempdir, safe_filename
from sentinel.core.service import verify_upload
from sentinel.dashboard import common
from sentinel.dashboard.ui import COLORS, badge, decision_banner, demo_notice, setup_page

LADDER = ["present", "well-formed", "subject-bound", "authenticated", "trusted"]
SIG_EXPLAIN = {
    "verified": "The artifact bytes match the signed digest and the signature verifies under a "
    "key in the policy trust store.",
    "digest_mismatch": "The artifact's SHA-256 differs from the digest that was signed (or "
    "pinned in the release record). The file was modified after signing, "
    "or the wrong signature was supplied.",
    "untrusted_signer": "The signature does not verify under any trusted key. It may be valid "
    "for some other key, but that key is not trusted by this policy.",
    "invalid_signature": "The signature bytes do not verify for this artifact under any "
    "trusted key.",
    "missing_signature": "No signature bundle was supplied.",
    "malformed_bundle": "The signature bundle could not be parsed as a Sigstore bundle.",
    "unsupported": "This bundle type requires identity-based (keyless) verification, which "
    "this gate is not configured for.",
    "no_trusted_keys": "The policy trust store is empty, so nothing can be trusted.",
}


def _digest_row(label: str, value: str | None, reference: str | None) -> str:
    if value is None:
        mark = '<span style="color:#7B8597">not provided</span>'
        return f"<div>{escape(label)}</div><div>{mark}</div>"
    ok = reference is None or value == reference
    icon = "✓" if ok else "✗"
    color = COLORS["PASS"] if ok else COLORS["FAIL"]
    return (
        f'<div>{escape(label)}</div><div class="ss-mono"><span style="color:{color};'
        f'font-weight:700">{icon}</span> {escape(value)}</div>'
    )


def show_signature(sig: SignatureVerification) -> None:
    st.markdown("##### Signature verification")
    st.markdown(
        badge(sig.status.value.upper().replace("_", " "), "PASS" if sig.verified else "FAIL"),
        unsafe_allow_html=True,
    )
    st.markdown(SIG_EXPLAIN.get(sig.status.value, ""))
    st.markdown(
        '<div class="ss-digest">'
        + _digest_row("Actual SHA-256", sig.actual_sha256, None)
        + _digest_row("Signed SHA-256", sig.signed_sha256, sig.actual_sha256)
        + _digest_row("Expected (record)", sig.expected_sha256, sig.actual_sha256)
        + "</div>",
        unsafe_allow_html=True,
    )
    st.markdown(" ")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Trusted signers (policy)**")
        for key in sig.trusted_keys:
            used = " ← verified" if key.key_id == sig.signer_key_id else ""
            st.markdown(f"- `{key.name}` · key id `{key.key_id[:20]}…`{used}")
        trusted_ids = {k.key_id for k in sig.trusted_keys}
        if sig.claimed_key_hint and not sig.verified:
            where = (
                "matches a trusted key, but the signature does not cover these bytes"
                if sig.claimed_key_hint in trusted_ids
                else "not in the trust store"
            )
            st.markdown(
                f"- Bundle names key hint `{sig.claimed_key_hint[:20]}…` (unauthenticated; {where})"
            )
    with c2:
        st.markdown("**Verification methods**")
        st.markdown(f"- {', '.join(sig.methods)}")
        if sig.cosign_verified is not None:
            st.markdown(
                f"- cosign {sig.cosign_version or ''}: "
                f"{'accepted' if sig.cosign_verified else 'rejected'}"
            )
        st.markdown(f"- transparency log checked: {sig.transparency_log_verified}")
    with st.expander("Verification details"):
        for detail in sig.details:
            st.markdown(f"- {detail}")


def show_provenance(prov: ProvenanceVerification) -> None:
    st.markdown("##### Build provenance")
    st.markdown(
        badge(prov.status.value.upper(), "PASS" if prov.verified else "FAIL"),
        unsafe_allow_html=True,
    )
    reached = LADDER.index(prov.trust_level) if prov.trust_level in LADDER else -1
    steps = "".join(
        f'<span class="ss-step{" on" if i <= reached else ""}">{escape(s)}</span>'
        for i, s in enumerate(LADDER)
    )
    st.markdown(f'<div class="ss-ladder">{steps}</div>', unsafe_allow_html=True)
    st.caption(
        "A provenance document that merely exists proves nothing. Each step must hold: "
        "parseable SLSA v1 statement → subject digest equals the artifact → DSSE "
        "signature by a trusted key → builder and source accepted by policy. Sentinel "
        "does not claim a SLSA Build Level."
    )
    if prov.checks:
        st.dataframe(
            [
                {
                    "check": c.name,
                    "result": {True: "pass", False: "FAIL", None: "n/a"}[c.passed],
                    "detail": c.detail,
                }
                for c in prov.checks
            ],
            hide_index=True,
            use_container_width=True,
        )
    for detail in prov.details:
        st.markdown(f"- {detail}")


def show_record(record: AnalysisRecord) -> None:
    demo_notice(record)
    decision_banner(record)
    if record.signature:
        show_signature(record.signature)
    if record.provenance:
        show_provenance(record.provenance)


def render() -> None:
    setup_page(
        "Artifact Trust",
        "Verify artifact signatures against the policy trust store and validate build provenance.",
    )
    verify_tab, history_tab = st.tabs(
        [":material/upload_file: Verify an artifact", ":material/history: Recorded verifications"]
    )
    with verify_tab:
        st.caption(
            "Files are hashed and verified in a private temporary directory, never "
            "unpacked or executed. Trusted keys come only from the active policy."
        )
        c1, c2 = st.columns(2)
        artifact = c1.file_uploader("Artifact", key="tr_art")
        bundle = c2.file_uploader(
            "Signature bundle (cosign sign-blob --bundle)", type=["json"], key="tr_bundle"
        )
        c3, c4 = st.columns(2)
        provenance = c3.file_uploader(
            "Provenance attestation (optional)", type=["json"], key="tr_prov"
        )
        expected = c4.text_input("Expected SHA-256 (optional)", key="tr_expected").strip()
        if st.button(
            "Verify", type="primary", icon=":material/verified_user:", disabled=artifact is None
        ):
            if expected and not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
                st.error("Expected SHA-256 must be 64 hexadecimal characters.")
                return
            limit = common.settings().max_upload_bytes
            if artifact.size > limit:
                st.error(f"Artifact exceeds {limit // (1024 * 1024)} MB.")
                return
            with private_tempdir() as tmp:
                art_path = tmp / safe_filename(artifact.name, "artifact")
                art_path.write_bytes(artifact.getvalue())
                bun_path = prov_path = None
                if bundle is not None:
                    bun_path = tmp / ("bundle-" + safe_filename(bundle.name, "bundle.json"))
                    bun_path.write_bytes(bundle.getvalue())
                if provenance is not None:
                    prov_path = tmp / ("prov-" + safe_filename(provenance.name, "prov.json"))
                    prov_path.write_bytes(provenance.getvalue())
                outcome = verify_upload(
                    art_path,
                    bun_path,
                    common.settings(),
                    common.policy(),
                    store=common.store(),
                    expected_sha256=expected or None,
                    provenance=prov_path,
                    display_name=art_path.name,
                )
            st.session_state["selected_analysis"] = outcome.record.id
            show_record(outcome.record)
    with history_tab:
        record = common.pick_analysis(
            "Analysis with signature evidence",
            kinds=("release_gate", "artifact_verification"),
            key="trust_pick",
            require="signature",
        )
        if record is None:
            common.empty_state(
                "No artifact verifications recorded yet.",
                "Verify an artifact or run a release gate.",
            )
            return
        show_record(record)
